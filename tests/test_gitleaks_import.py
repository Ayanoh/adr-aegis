"""Unit tests for imported Gitleaks secret detection patterns."""

import re

from aegis.tier1_fast.gitleaks_patterns import GITLEAKS_PATTERNS
from aegis.tier1_fast.secrets_scanner import SECRET_PATTERNS, SecretsScanner


def test_pattern_count() -> None:
    """Verify that at least 100 Gitleaks patterns were successfully imported."""
    assert len(GITLEAKS_PATTERNS) >= 100, f"Expected >= 100 patterns, got {len(GITLEAKS_PATTERNS)}"


def test_patterns_compile() -> None:
    """Verify that all imported Gitleaks patterns compile without errors."""
    for pattern_name, compiled_regex, min_entropy, severity in GITLEAKS_PATTERNS:
        assert isinstance(pattern_name, str) and len(pattern_name) > 0
        assert isinstance(compiled_regex, re.Pattern)
        assert isinstance(min_entropy, (int, float)) and min_entropy >= 0.0
        assert severity is not None


def test_known_secrets_detected() -> None:
    """Verify that Gitleaks patterns detect JWT tokens (new capability from Gitleaks)."""
    scanner = SecretsScanner()

    # JWT token - this pattern comes from Gitleaks (not in our original 21 patterns)
    jwt_text = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    findings_jwt = scanner.scan(jwt_text)
    assert len(findings_jwt) >= 1, f"JWT not detected, got: {findings_jwt}"
    assert any(f.secret_type == "jwt" for f in findings_jwt), (
        f"Expected jwt pattern type, got: {[f.secret_type for f in findings_jwt]}"
    )

    # Verify JWT wasn't in our original patterns (it's from Gitleaks)
    from aegis.tier1_fast.gitleaks_patterns import GITLEAKS_PATTERNS

    gitleaks_names = {p[0] for p in GITLEAKS_PATTERNS}
    assert "jwt" in gitleaks_names, "JWT pattern should come from Gitleaks"


def test_no_duplicates() -> None:
    """Verify that no duplicate pattern names exist in SECRET_PATTERNS."""
    pattern_names = [name for name, _, _, _ in SECRET_PATTERNS]
    unique_names = set(pattern_names)
    assert len(pattern_names) == len(unique_names), (
        f"Found duplicate pattern names: {[name for name in pattern_names if pattern_names.count(name) > 1]}"
    )
