"""Core schema models for ADR-AEGIS.

This module defines all Pydantic data models and enumerations
used throughout the ADR-AEGIS detection and response pipeline.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    """Returns current datetime in UTC timezone."""
    return datetime.now(UTC)


class ThreatSeverity(str, Enum):
    """Severity levels for detected threats.

    Attributes:
        CRITICAL: Severe risk requiring immediate termination (e.g., reverse shell).
        HIGH: Serious risk such as credential theft or sensitive data access.
        MEDIUM: Moderate risk such as suspicious command patterns or prompt injection.
        LOW: Minor anomaly or policy deviation.
        INFO: Informational observation with no immediate threat.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ActionDecision(str, Enum):
    """Enforcement decisions available to the ADR engine.

    Attributes:
        ALLOW: Permit the action to proceed without modification.
        BLOCK: Prevent the action from executing.
        ASK: Require human confirmation before proceeding.
        SANITIZE: Modify or redact malicious elements before execution.
    """

    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"
    SANITIZE = "sanitize"


class TierSource(str, Enum):
    """Origin tier that produced a given verdict.

    Attributes:
        TIER1_HEURISTICS: Fast regex and rule-based heuristic engine.
        TIER1_ML: Machine learning classifier (e.g., DeBERTa-v3).
        TIER1_VECTOR: Vector similarity matching against threat database.
        TIER2_COGNITIVE: Deep dual-agent cognitive forensic reasoning.
        CACHE_HIT: Verdict retrieved from fast in-memory cache.
    """

    TIER1_HEURISTICS = "tier1_heuristics"
    TIER1_ML = "tier1_ml"
    TIER1_VECTOR = "tier1_vector"
    TIER2_COGNITIVE = "tier2_cognitive"
    CACHE_HIT = "cache_hit"


class ExtractedArtifacts(BaseModel):
    """Artifacts extracted from tool inputs and agent trajectory.

    Attributes:
        commands: Shell commands identified in input payloads.
        file_paths: System and local file paths detected.
        urls: Network endpoints and web URLs extracted.
        secrets: API keys, tokens, or credentials identified.
        untrusted_data_markers: Indicators of external/untrusted data ingestion.
    """

    commands: list[str] = Field(
        default_factory=list,
        description="Shell commands detected in the input payload.",
    )
    file_paths: list[str] = Field(
        default_factory=list,
        description="File paths detected in the input payload.",
    )
    urls: list[str] = Field(
        default_factory=list,
        description="URLs extracted from the input payload.",
    )
    secrets: list[str] = Field(
        default_factory=list,
        description="API keys, tokens, or passwords identified.",
    )
    untrusted_data_markers: list[str] = Field(
        default_factory=list,
        description="Markers representing untrusted external data sources.",
    )


class AgentEvent(BaseModel):
    """Represents a single captured event in the AI agent lifecycle.

    Attributes:
        session_id: Unique identifier for the agent session.
        timestamp: UTC timestamp when the event was recorded.
        step_number: Sequential step number in the agent's ReAct trajectory.
        user_intent: Original instruction or query provided by the user.
        tool_name: Name of the tool invoked by the agent.
        tool_input: Raw input arguments supplied to the tool.
        llm_reasoning: Optional chain-of-thought or reasoning text from the LLM.
        artifacts: Structured artifacts extracted from tool inputs.
    """

    session_id: str = Field(
        ...,
        description="Unique identifier for the agent session.",
    )
    timestamp: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the event occurred.",
    )
    step_number: int = Field(
        default=0,
        description="Sequential step index in the agent execution chain.",
    )
    user_intent: str = Field(
        ...,
        description="The original user goal or instruction.",
    )
    tool_name: str = Field(
        ...,
        description="Name of the tool being called.",
    )
    tool_input: Any = Field(
        ...,
        description="Raw input arguments provided to the tool.",
    )
    llm_reasoning: str | None = Field(
        default=None,
        description="Internal reasoning or thoughts emitted by the LLM.",
    )
    artifacts: ExtractedArtifacts = Field(
        default_factory=ExtractedArtifacts,
        description="Structured artifacts extracted from the input.",
    )


class ThreatMatch(BaseModel):
    """Detailed record of a single threat detected by the engine.

    Attributes:
        rule_id: Unique identifier of the triggered security rule.
        rule_name: Human-readable name of the security rule.
        category: Broad category of the detected threat.
        severity: Severity level of the threat.
        matched_pattern: The pattern or signature that triggered the detection.
        matched_content: The specific substring or content that caused the match.
        mitre_atlas_id: Optional reference identifier in the MITRE ATLAS matrix.
    """

    rule_id: str = Field(
        ...,
        description="Unique identifier of the matching rule.",
    )
    rule_name: str = Field(
        ...,
        description="Human-readable title of the rule.",
    )
    category: str = Field(
        ...,
        description="Security category of the threat.",
    )
    severity: ThreatSeverity = Field(
        ...,
        description="Severity classification of the threat.",
    )
    matched_pattern: str = Field(
        ...,
        description="The regex pattern or signature that matched.",
    )
    matched_content: str = Field(
        ...,
        description="The actual string content that triggered the match.",
    )
    mitre_atlas_id: str | None = Field(
        default=None,
        description="MITRE ATLAS technique identifier mapping.",
    )


class Verdict(BaseModel):
    """Final security verdict produced by the ADR-AEGIS engine.

    Attributes:
        decision: Enforcement action to be taken.
        confidence: Confidence score of the assessment, bounded between 0.0 and 1.0.
        tier_source: The engine tier that produced this verdict.
        threats: List of individual threat matches identified.
        reason: Plain-text justification for the decision.
        remediation: Optional actionable guidance to fix or bypass securely.
        latency_ms: Processing latency in milliseconds.
        timestamp: UTC timestamp when the verdict was generated.
    """

    decision: ActionDecision = Field(
        ...,
        description="Enforcement decision (ALLOW, BLOCK, ASK, SANITIZE).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0.",
    )
    tier_source: TierSource = Field(
        ...,
        description="Pipeline tier that evaluated and generated the verdict.",
    )
    threats: list[ThreatMatch] = Field(
        default_factory=list,
        description="List of detected threat matches.",
    )
    reason: str = Field(
        ...,
        description="Human-readable explanation of the verdict.",
    )
    remediation: str | None = Field(
        default=None,
        description="Recommended remediation steps if a threat was found.",
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Evaluation latency in milliseconds.",
    )
    timestamp: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the verdict was issued.",
    )


class Tier2Assessment(BaseModel):
    """Structured judgment produced by a Tier 2 cognitive agent (Forensic or Critic).

    Attributes:
        source_agent: Identifier of the agent that produced this assessment
            (e.g. "forensic", "critic").
        is_malicious: Whether the agent concludes the action is malicious.
        severity: Assessed severity level of the threat.
        recommended_decision: Enforcement action the agent recommends.
        confidence: Confidence of the assessment, bounded 0.0-1.0.
        rationale: Human-readable justification (the "why").
        indicators: Concrete signals/evidence the agent relied on.
    """

    source_agent: str = Field(..., description="Agent that produced the assessment.")
    is_malicious: bool = Field(..., description="Whether the action is judged malicious.")
    severity: ThreatSeverity = Field(..., description="Assessed severity level.")
    recommended_decision: ActionDecision = Field(..., description="Recommended enforcement action.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0.")
    rationale: str = Field(..., description="Human-readable justification.")
    indicators: list[str] = Field(default_factory=list, description="Evidence signals relied upon.")


class Tier2Input(BaseModel):
    """Context passed to the Tier 2 dual-agent reasoner for an ambiguous case.

    Attributes:
        content: The text/action under scrutiny (e.g. combined agent event text).
        tier1_decision: Decision produced by the Tier 1 fast filter.
        tier1_reason: Human-readable summary of the Tier 1 outcome.
        threats: Threat matches surfaced by Tier 1 (may be empty).
        artifacts: Structured artifacts extracted from the input (optional).
        obfuscation: Obfuscation/deobfuscation signals detected (may be empty).
    """

    content: str = Field(..., description="Action/text under scrutiny.")
    tier1_decision: ActionDecision = Field(..., description="Decision from Tier 1.")
    tier1_reason: str = Field(default="", description="Summary of the Tier 1 outcome.")
    threats: list[ThreatMatch] = Field(default_factory=list, description="Tier 1 threat matches.")
    artifacts: ExtractedArtifacts | None = Field(default=None, description="Extracted artifacts.")
    obfuscation: list[str] = Field(
        default_factory=list, description="Obfuscation signals detected."
    )
