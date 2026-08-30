"""Advanced secrets scanner for the Vinci ADR Tier 1 fast layer.

Provides regex-based secret detection, Shannon entropy calculations,
false-positive filtering, and redaction capabilities.
"""

import math
import re
import time
from collections import Counter
from dataclasses import dataclass

import structlog

from vinci_adr.core.schema import (
    ActionDecision,
    ThreatMatch,
    ThreatSeverity,
    TierSource,
    Verdict,
)

logger = structlog.get_logger()


@dataclass
class SecretFinding:
    """A detected secret with metadata.

    Attributes:
        secret_type: Type of secret (e.g., "aws_access_key_id", "github_pat").
        value: The actual secret value.
        full_match: The full matched string including context.
        entropy: Shannon entropy of the secret value.
        confidence: Confidence score (0.0-1.0) that this is a real secret.
        line_number: Optional line number where found.
    """

    secret_type: str
    value: str
    full_match: str
    entropy: float
    confidence: float
    line_number: int | None = None

    @property
    def redacted_value(self) -> str:
        """Returns the secret with middle characters redacted."""
        if len(self.value) <= 8:
            return self.value[:2] + "***" + self.value[-2:]
        return self.value[:4] + "***" + self.value[-4:]


# Secret patterns with metadata: (name, pattern, min_entropy, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float, ThreatSeverity]] = [
    # AWS
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), 3.0, ThreatSeverity.CRITICAL),
    (
        "aws_secret_key",
        re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        4.0,
        ThreatSeverity.CRITICAL,
    ),
    # GitHub
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}"), 4.0, ThreatSeverity.CRITICAL),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}"), 4.0, ThreatSeverity.CRITICAL),
    ("github_app", re.compile(r"ghu_[A-Za-z0-9]{36}"), 4.0, ThreatSeverity.HIGH),
    ("github_refresh", re.compile(r"ghr_[A-Za-z0-9]{36}"), 4.0, ThreatSeverity.HIGH),
    # OpenAI / Anthropic
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{48}"), 3.5, ThreatSeverity.CRITICAL),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}"), 3.5, ThreatSeverity.CRITICAL),
    # Google
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 3.5, ThreatSeverity.HIGH),
    # Slack
    (
        "slack_token",
        re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        3.5,
        ThreatSeverity.HIGH,
    ),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    # Generic patterns
    (
        "bearer_token",
        re.compile(r"Bearer\s+([A-Za-z0-9\-_.~+/]+=*)", re.IGNORECASE),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "basic_auth",
        re.compile(r"Basic\s+([A-Za-z0-9+/]+=*)", re.IGNORECASE),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----"),
        0.0,
        ThreatSeverity.CRITICAL,
    ),
    # Database connection strings
    (
        "postgres_uri",
        re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+"),
        2.5,
        ThreatSeverity.CRITICAL,
    ),
    ("mysql_uri", re.compile(r"mysql://[^:]+:[^@]+@[^/]+/\w+"), 2.5, ThreatSeverity.CRITICAL),
    (
        "mongodb_uri",
        re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+"),
        2.5,
        ThreatSeverity.CRITICAL,
    ),
    # Generic high-entropy secrets (last resort)
    (
        "generic_api_key",
        re.compile(r'(?i)api[_-]?key["\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?'),
        3.5,
        ThreatSeverity.MEDIUM,
    ),
    (
        "generic_secret",
        re.compile(r'(?i)secret["\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?'),
        3.5,
        ThreatSeverity.MEDIUM,
    ),
    (
        "generic_password",
        re.compile(r'(?i)password["\s:=]+["\']?([^\s"\']{8,})["\']?'),
        2.5,
        ThreatSeverity.MEDIUM,
    ),
]

# Import Gitleaks patterns if available
try:
    from vinci_adr.tier1_fast.gitleaks_patterns import GITLEAKS_PATTERNS

    _existing_names = {p[0] for p in SECRET_PATTERNS}
    for _pattern in GITLEAKS_PATTERNS:
        if _pattern[0] not in _existing_names:
            SECRET_PATTERNS.append(_pattern)
            _existing_names.add(_pattern[0])
except ImportError:
    pass  # Gitleaks patterns not generated yet

# Known false positive patterns to exclude
FALSE_POSITIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^[A-Za-z]+$"),  # All letters (likely a normal word)
    re.compile(r"^[0-9]+$"),  # All numbers
    re.compile(r"example|test|dummy|fake|placeholder|your[_-]?(?:api[_-]?)?key", re.IGNORECASE),
    re.compile(r"^x{8,}$", re.IGNORECASE),  # Repeated x's
    re.compile(r"^0{8,}$"),  # Repeated zeros
]


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string.

    Formula: H = -sum(p(x) * log2(p(x))) for each distinct character.

    Args:
        text: Input string.

    Returns:
        Float value representing entropy in bits. Returns 0.0 for empty strings.

    Example:
        >>> calculate_entropy("aaaa")
        0.0
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_false_positive(value: str) -> bool:
    """Determines whether a secret candidate is a known false positive or placeholder.

    Args:
        value: Candidate secret string.

    Returns:
        True if the candidate matches a false positive heuristic, False otherwise.

    Example:
        >>> is_false_positive("your_api_key_here")
        True
        >>> is_false_positive("AKIAIOSFODNN7EXAMPLE")
        False
    """
    if not value:
        return True

    # Known high-confidence token prefixes
    if value.startswith(("AKIA", "ghp_", "gho_", "ghu_", "ghr_", "sk-", "sk_", "rk_", "AIza")):
        # Only false positive if it's completely repetitive
        return len(set(value[4:])) <= 2

    # Check for false positive patterns
    for fp_pattern in FALSE_POSITIVE_PATTERNS:
        if fp_pattern.search(value):
            return True

    # Check for repeated single characters
    return len(set(value)) <= 2 and len(value) > 4


def extract_secret_value(match: re.Match[str], pattern_name: str) -> str:
    """Extracts the secret token value from a regular expression match.

    Args:
        match: Regex match object.
        pattern_name: Name of the matched pattern.

    Returns:
        The extracted secret substring.
    """
    if match.groups() and match.group(1):
        return match.group(1).strip()
    return match.group(0).strip()


class SecretsScanner:
    """Advanced secrets detection with entropy analysis and validation.

    Attributes:
        min_entropy_override: Optional override for minimum entropy threshold.
        findings: List of detected secrets from last scan.
    """

    def __init__(self, min_entropy_override: float | None = None) -> None:
        """Initialize the secrets scanner.

        Args:
            min_entropy_override: If set, overrides per-pattern entropy thresholds.
        """
        self.min_entropy_override = min_entropy_override
        self.findings: list[SecretFinding] = []

    def scan(self, text: str) -> list[SecretFinding]:
        """Scan text for secrets.

        Args:
            text: Input text to scan.

        Returns:
            List of SecretFinding objects for detected secrets.
        """
        if not isinstance(text, str) or not text:
            self.findings = []
            return []

        findings: list[SecretFinding] = []
        seen_values: set[str] = set()

        for pattern_name, pattern, min_entropy, _severity in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                full_match = match.group(0)
                secret_val = extract_secret_value(match, pattern_name)

                # Skip if already detected
                if secret_val in seen_values:
                    continue

                # Skip false positives
                if is_false_positive(secret_val):
                    continue

                # Entropy check
                entropy = calculate_entropy(secret_val)
                effective_min_entropy = (
                    self.min_entropy_override
                    if self.min_entropy_override is not None
                    else min_entropy
                )

                # Skip if below entropy threshold (except private keys which have 0.0 threshold)
                if min_entropy > 0.0 and entropy < effective_min_entropy:
                    continue

                # Confidence calculation
                confidence = 0.5
                entropy_diff = max(0.0, entropy - min_entropy)
                confidence += min(0.3, entropy_diff * 0.1)

                if not pattern_name.startswith("generic_"):
                    confidence += 0.1

                if (
                    pattern_name == "aws_access_key_id"
                    and len(secret_val) == 20
                    or (
                        pattern_name
                        in ("github_pat", "github_oauth", "github_app", "github_refresh")
                        and len(secret_val) == 40
                    )
                    or pattern_name == "openai_api_key"
                    and len(secret_val) == 51
                ):
                    confidence += 0.05

                confidence = min(1.0, confidence)

                finding = SecretFinding(
                    secret_type=pattern_name,
                    value=secret_val,
                    full_match=full_match,
                    entropy=entropy,
                    confidence=confidence,
                )
                findings.append(finding)
                seen_values.add(secret_val)

        self.findings = findings
        return findings

    def evaluate(self, text: str) -> Verdict:
        """Evaluate text for secrets and return a verdict.

        Args:
            text: Input text to evaluate.

        Returns:
            Verdict with decision based on detected secrets.
        """
        start_time = time.perf_counter()
        findings = self.scan(text)

        # Map pattern names to severity
        pattern_severities = {name: sev for name, _, _, sev in SECRET_PATTERNS}
        severities = [
            pattern_severities.get(f.secret_type, ThreatSeverity.MEDIUM) for f in findings
        ]

        threat_matches: list[ThreatMatch] = []
        for f in findings:
            sev = pattern_severities.get(f.secret_type, ThreatSeverity.MEDIUM)
            threat_matches.append(
                ThreatMatch(
                    rule_id=f"ADR-SEC-{f.secret_type[:3].upper()}",
                    rule_name=f"Secret Detected: {f.secret_type}",
                    category="secret_leak",
                    severity=sev,
                    matched_pattern=f.secret_type,
                    matched_content=f.redacted_value,
                )
            )

        if ThreatSeverity.CRITICAL in severities:
            crit_finding = next(
                f
                for f in findings
                if pattern_severities.get(f.secret_type) == ThreatSeverity.CRITICAL
            )
            decision = ActionDecision.BLOCK
            confidence = 0.95
            reason = f"Critical secret detected: {crit_finding.secret_type}"
        elif ThreatSeverity.HIGH in severities:
            high_finding = next(
                f for f in findings if pattern_severities.get(f.secret_type) == ThreatSeverity.HIGH
            )
            decision = ActionDecision.BLOCK
            confidence = 0.85
            reason = f"High severity secret detected: {high_finding.secret_type}"
        elif ThreatSeverity.MEDIUM in severities:
            med_finding = next(
                f
                for f in findings
                if pattern_severities.get(f.secret_type) == ThreatSeverity.MEDIUM
            )
            decision = ActionDecision.ASK
            confidence = 0.70
            reason = f"Secret detected: {med_finding.secret_type}"
        else:
            decision = ActionDecision.ALLOW
            confidence = 0.10
            reason = "No secrets detected"

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return Verdict(
            decision=decision,
            confidence=confidence,
            tier_source=TierSource.TIER1_HEURISTICS,
            threats=threat_matches,
            reason=reason,
            latency_ms=latency_ms,
        )

    def get_redacted_text(self, text: str) -> str:
        """Returns the text with all detected secrets redacted.

        Args:
            text: Original text.

        Returns:
            Text with secrets replaced by [REDACTED:type].
        """
        if not text:
            return text

        findings = self.scan(text)
        redacted = text

        for f in sorted(findings, key=lambda item: len(item.full_match), reverse=True):
            redacted = redacted.replace(f.full_match, f"[REDACTED:{f.secret_type}]")

        return redacted
