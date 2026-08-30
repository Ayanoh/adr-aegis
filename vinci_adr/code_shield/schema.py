"""Schema definitions for Meta PurpleLlama Code Shield.

Defines CWE vulnerability types, detected findings, verdicts, and configuration.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CWEType(str, Enum):
    """Common Weakness Enumeration (CWE) categories covered by Code Shield."""

    CWE_89_SQL_INJECTION = "CWE-89: SQL Injection"
    CWE_78_COMMAND_INJECTION = "CWE-78: OS Command Injection"
    CWE_79_XSS = "CWE-79: Cross-Site Scripting"
    CWE_502_INSECURE_DESERIALIZATION = "CWE-502: Insecure Deserialization"
    CWE_22_PATH_TRAVERSAL = "CWE-22: Path Traversal"
    CWE_94_CODE_INJECTION = "CWE-94: Code Injection"
    CWE_327_BROKEN_CRYPTO = "CWE-327: Broken/Risky Cryptography"


class CodeVulnerability(BaseModel):
    """A detected security vulnerability in generated source code.

    Attributes:
        cwe_type: The CWE category of the vulnerability.
        severity: Severity level (critical, high, medium, low).
        matched_pattern: Name of the detection rule or pattern.
        line_number: Line number where the vulnerability was found.
        snippet: Code snippet illustrating the vulnerable statement.
        remediation_suggestion: Recommended secure code alternative.
    """

    cwe_type: CWEType
    severity: str
    matched_pattern: str
    line_number: int | None = None
    snippet: str
    remediation_suggestion: str


class CodeShieldVerdict(BaseModel):
    """Evaluation verdict for source code security.

    Attributes:
        is_secure: True if code contains no unacceptable security flaws.
        vulnerabilities: List of detected code vulnerabilities.
        risk_score: Aggregated risk score from 0.0 (clean) to 1.0 (critical).
        language_detected: Programming language identifier if determined.
        scanned_lines_count: Total lines of code evaluated.
        latency_ms: Scan duration in milliseconds.
    """

    is_secure: bool = True
    vulnerabilities: list[CodeVulnerability] = Field(default_factory=list)
    risk_score: float = 0.0
    language_detected: str | None = None
    scanned_lines_count: int = 0
    latency_ms: float = 0.0


class CodeShieldConfig(BaseModel):
    """Configuration settings for the Code Shield scanner.

    Attributes:
        strict_mode: If True, any detected flaw marks code as insecure.
        enabled_cwes: Set of active CWE categories to check.
        max_acceptable_risk: Maximum risk threshold before marking is_secure=False.
    """

    strict_mode: bool = False
    enabled_cwes: set[CWEType] = Field(default_factory=lambda: set(CWEType))
    max_acceptable_risk: float = 0.50

    def model_dump_json_safe(self) -> dict[str, Any]:
        """Export config as dictionary."""
        return self.model_dump()
