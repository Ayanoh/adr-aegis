"""Fast rule-based threat detection engine.

Loads YAML rule files and performs high-speed pattern matching against input text.
Designed for sub-15ms response latencies on typical payloads.
"""

import time
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import ValidationError

from aegis.core.rules import RuleSet, ThreatRule
from aegis.core.schema import (
    ActionDecision,
    ThreatMatch,
    ThreatSeverity,
    TierSource,
    Verdict,
)

logger = structlog.get_logger()


class HeuristicsEngine:
    """Fast rule-based threat detection engine.

    Loads YAML rule files and performs pattern matching against input text.
    Designed for < 15ms latency on typical inputs.

    Attributes:
        rule_set: The loaded rule set.
        rules_dir: Directory containing YAML rule files.
    """

    def __init__(self, rules_dir: Path | None = None) -> None:
        """Initialize the heuristics engine.

        Args:
            rules_dir: Path to directory containing YAML rule files.
                      If None, uses default rules directory.
        """
        if rules_dir is None:
            self.rules_dir = Path(__file__).resolve().parent.parent.parent / "rules"
        else:
            self.rules_dir = Path(rules_dir)

        self.rule_set = RuleSet()
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all YAML rule files from the rules directory."""
        if not self.rules_dir.exists() or not self.rules_dir.is_dir():
            logger.warning("Rules directory not found", rules_dir=str(self.rules_dir))
            return

        yaml_files = sorted(
            list(self.rules_dir.rglob("*.yaml")) + list(self.rules_dir.rglob("*.yml"))
        )

        loaded_rules: list[ThreatRule] = []
        for file_path in yaml_files:
            file_rules = self._load_yaml_file(file_path)
            loaded_rules.extend(file_rules)

        self.rule_set.rules = loaded_rules
        logger.info(
            "Loaded threat rules",
            count=len(self.rule_set.rules),
            rules_dir=str(self.rules_dir),
        )

    def _load_yaml_file(self, file_path: Path) -> list[ThreatRule]:
        """Load rules from a single YAML file.

        Args:
            file_path: Path to the YAML file.

        Returns:
            List of ThreatRule objects parsed from the file.
        """
        rules: list[ThreatRule] = []
        try:
            with open(file_path, encoding="utf-8") as f:
                content: Any = yaml.safe_load(f)

            if not content:
                return []

            raw_list: list[dict[str, Any]] = []
            if isinstance(content, list):
                raw_list = content
            elif isinstance(content, dict) and "rules" in content:
                raw_list = content["rules"]

            for item in raw_list:
                if not isinstance(item, dict):
                    continue
                try:
                    rule = ThreatRule(**item)
                    rules.append(rule)
                except ValidationError as e:
                    logger.warning(
                        "Invalid rule in YAML file",
                        file=str(file_path),
                        rule_id=item.get("id"),
                        error=str(e),
                    )
        except (yaml.YAMLError, OSError) as e:
            logger.warning("Failed to parse YAML file", file=str(file_path), error=str(e))

        return rules

    def scan(self, text: str) -> list[ThreatMatch]:
        """Scan text against all enabled rules.

        Args:
            text: Input text to scan.

        Returns:
            List of ThreatMatch objects for all matching rules.
        """
        if not isinstance(text, str) or not text:
            return []

        matches: list[ThreatMatch] = []

        for rule in self.rule_set.get_enabled_rules():
            for compiled in rule._compiled_patterns:
                match = compiled.search(text)
                if match:
                    matched_str = match.group(0)
                    matches.append(
                        ThreatMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            matched_pattern=compiled.pattern,
                            matched_content=matched_str,
                            mitre_atlas_id=rule.mitre_atlas_id,
                        )
                    )
                    # Once a rule matches, move to next rule
                    break

        return matches

    def evaluate(self, text: str) -> Verdict:
        """Evaluate text and return a verdict.

        Args:
            text: Input text to evaluate.

        Returns:
            Verdict with decision, confidence, and threat matches.
        """
        start_time = time.perf_counter()
        matches = self.scan(text)

        # Determine decision and confidence based on highest severity match
        severities = [m.severity for m in matches]

        if ThreatSeverity.CRITICAL in severities:
            crit_match = next(m for m in matches if m.severity == ThreatSeverity.CRITICAL)
            decision = ActionDecision.BLOCK
            confidence = 0.95
            reason = (
                f"Critical threat detected: {crit_match.rule_name} (Rule ID: {crit_match.rule_id})"
            )
        elif ThreatSeverity.HIGH in severities:
            high_match = next(m for m in matches if m.severity == ThreatSeverity.HIGH)
            decision = ActionDecision.BLOCK
            confidence = 0.85
            reason = f"High threat detected: {high_match.rule_name} (Rule ID: {high_match.rule_id})"
        elif ThreatSeverity.MEDIUM in severities:
            med_match = next(m for m in matches if m.severity == ThreatSeverity.MEDIUM)
            decision = ActionDecision.ASK
            confidence = 0.70
            reason = f"Medium threat detected: {med_match.rule_name} (Rule ID: {med_match.rule_id})"
        elif ThreatSeverity.LOW in severities:
            low_match = next(m for m in matches if m.severity == ThreatSeverity.LOW)
            decision = ActionDecision.ALLOW
            confidence = 0.50
            reason = f"Low threat detected: {low_match.rule_name} (Rule ID: {low_match.rule_id})"
        else:
            decision = ActionDecision.ALLOW
            confidence = 0.10
            reason = "No threats detected by heuristics engine"

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return Verdict(
            decision=decision,
            confidence=confidence,
            tier_source=TierSource.TIER1_HEURISTICS,
            threats=matches,
            reason=reason,
            latency_ms=latency_ms,
        )

    def reload_rules(self) -> int:
        """Reload rules from disk.

        Returns:
            Number of rules loaded.
        """
        self.rule_set = RuleSet()
        self._load_rules()
        return len(self.rule_set.rules)

    @property
    def rule_count(self) -> int:
        """Returns the total number of loaded rules."""
        return len(self.rule_set.rules)
