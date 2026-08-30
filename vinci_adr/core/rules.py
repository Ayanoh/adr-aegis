"""Core rules module for Vinci ADR.

This module defines Pydantic models for security threat rules,
regex pattern compilation, and rule set management.
"""

import re

from pydantic import BaseModel, Field

from vinci_adr.core.schema import ActionDecision, ThreatSeverity


class ThreatRule(BaseModel):
    """A single threat detection rule.

    Attributes:
        id: Unique rule identifier (e.g., "ADR-CMD-001", "CLT-MAC-CMD-001").
        name: Human-readable rule name.
        description: Detailed description of the threat.
        category: Threat category (e.g., "command_execution", "prompt_injection").
        patterns: List of regex patterns to match.
        severity: Threat severity level.
        action: Recommended action when matched.
        mitre_atlas_id: Optional MITRE ATLAS technique ID.
        enabled: Whether the rule is active.
        tags: Optional list of tags for filtering.
    """

    id: str = Field(..., pattern=r"^[A-Z]{2,6}(-[A-Z]{2,10}){1,3}-\d{3,4}$")
    name: str
    description: str = ""
    category: str
    patterns: list[str]
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    action: ActionDecision = ActionDecision.BLOCK
    mitre_atlas_id: str | None = None
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)

    # Compiled patterns (computed, not serialized)
    _compiled_patterns: list[re.Pattern[str]] = []

    def model_post_init(self, context: object, /) -> None:
        """Compile regex patterns after initialization."""
        self._compiled_patterns = []
        for pattern in self.patterns:
            try:
                self._compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
            except re.error:
                # Invalid regex, skip it gracefully
                pass

    def match(self, text: str) -> str | None:
        """Check if text matches any compiled pattern.

        Args:
            text: Raw text to scan against compiled rule patterns.

        Returns:
            The matched content if found, None otherwise.
        """
        for compiled in self._compiled_patterns:
            match = compiled.search(text)
            if match:
                return match.group(0)
        return None


class RuleSet(BaseModel):
    """A collection of threat detection rules.

    Attributes:
        name: Name of the rule set.
        version: Version string.
        rules: List of threat rules.
    """

    name: str = "default"
    version: str = "1.0.0"
    rules: list[ThreatRule] = Field(default_factory=list)

    def get_enabled_rules(self) -> list[ThreatRule]:
        """Returns only enabled rules."""
        return [r for r in self.rules if r.enabled]

    def get_rules_by_category(self, category: str) -> list[ThreatRule]:
        """Returns rules matching a specific category."""
        return [r for r in self.rules if r.category == category and r.enabled]

    def get_rule_by_id(self, rule_id: str) -> ThreatRule | None:
        """Returns a rule by its ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
