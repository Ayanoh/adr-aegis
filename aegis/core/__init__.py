"""Core module: engine, schemas, and caching."""

from .engine import (
    ADRAegisEngine,
    EngineConfig,
    EvaluationResult,
    SensitivityPreset,
)
from .rules import RuleSet, ThreatRule
from .schema import (
    ActionDecision,
    AgentEvent,
    ExtractedArtifacts,
    ThreatMatch,
    ThreatSeverity,
    Tier2Assessment,
    Tier2Input,
    TierSource,
    Verdict,
)

__all__ = [
    "ADRAegisEngine",
    "ActionDecision",
    "AgentEvent",
    "EngineConfig",
    "EvaluationResult",
    "ExtractedArtifacts",
    "RuleSet",
    "SensitivityPreset",
    "ThreatMatch",
    "ThreatRule",
    "ThreatSeverity",
    "Tier2Assessment",
    "Tier2Input",
    "TierSource",
    "Verdict",
]
