"""Schema definitions for Vinci ADR Output Guard.

Defines MLCommons safety categories, output decisions, verdicts, and configuration.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SafetyCategory(str, Enum):
    """MLCommons AI Safety Risk Categories (S1-S13).

    Official standardized taxonomy for LLM output risk evaluation.
    """

    S1_ELECTION_INTEGRITY = "S1: Election Integrity"
    S2_HATE_SPEECH = "S2: Hate Speech"
    S3_SEXUAL_CONTENT = "S3: Sexual Content"
    S4_CRIMINAL_PLANNING = "S4: Criminal Planning"
    S5_GUNS_ILLEGAL_WEAPONS = "S5: Weapons"
    S6_CBRN_WEAPONS = "S6: CBRN"
    S7_SUICIDE_SELF_HARM = "S7: Self-Harm"
    S8_CYBERATTACKS = "S8: Cyberattacks"
    S9_PRIVACY_VIOLATIONS = "S9: PII & Data Privacy"
    S10_SECRETS_CREDENTIALS = "S10: Secrets & Credentials"
    S11_DEFAMATION = "S11: Defamation"
    S12_INTELLECTUAL_PROPERTY = "S12: IP Violation"
    S13_INDIRECT_INJECTION_ECHO = "S13: Injection Echo"


class OutputDecision(str, Enum):
    """Enforcement decisions available to the Output Guard.

    Attributes:
        ALLOW: Output is safe to deliver to the user.
        REDACT: Output contains sensitive secrets that have been sanitized.
        BLOCK: Output violates critical safety policies and must be suppressed.
    """

    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class OutputSafetyVerdict(BaseModel):
    """Evaluation verdict for an AI generated output.

    Attributes:
        is_safe: Whether the output is safe to release (True for ALLOW and REDACT).
        decision: Final enforcement decision (ALLOW, REDACT, or BLOCK).
        flagged_categories: List of violated MLCommons safety categories.
        sanitized_text: Sanitized version of output if redacted, else None.
        confidence: Confidence score (0.0 to 1.0).
        detected_secrets: Names/types of secrets detected during DLP scan.
        reason: Human-readable explanation of the verdict.
        latency_ms: Processing latency in milliseconds.
    """

    is_safe: bool = True
    decision: OutputDecision = OutputDecision.ALLOW
    flagged_categories: list[SafetyCategory] = Field(default_factory=list)
    sanitized_text: str | None = None
    confidence: float = 1.0
    detected_secrets: list[str] = Field(default_factory=list)
    reason: str = "Output is safe"
    latency_ms: float = 0.0


class OutputGuardConfig(BaseModel):
    """Configuration for the Output Guard engine.

    Attributes:
        strict_mode: If True, secret leaks trigger BLOCK instead of REDACT.
        enable_dlp: Enable Data Loss Prevention / secret detection.
        enable_cyber_check: Enable detection of generated offensive exploits.
        enable_mlcommons_check: Enable toxicity and dangerous domain checks.
        custom_blocked_categories: Additional safety categories to block strictly.
    """

    strict_mode: bool = False
    enable_dlp: bool = True
    enable_cyber_check: bool = True
    enable_mlcommons_check: bool = True
    custom_blocked_categories: set[SafetyCategory] = Field(default_factory=set)

    def model_dump_json_safe(self) -> dict[str, Any]:
        """Export config as dictionary."""
        return self.model_dump()
