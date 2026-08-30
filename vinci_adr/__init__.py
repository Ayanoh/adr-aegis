"""Vinci ADR: Agent Detection & Response security framework for AI Agents and LLMs."""

__version__ = "0.1.0"

from vinci_adr.core.engine import (
    ADRAegisEngine,
    EngineConfig,
    EvaluationResult,
    SensitivityPreset,
    VinciADREngine,
    VinciEngine,
)
from vinci_adr.core.schema import (
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
from vinci_adr.daemon.interceptor import (
    AegisDaemon,
    DaemonConfig,
    InterceptionDecision,
    InterceptionResult,
    VinciDaemon,
)
from vinci_adr.daemon.langchain_hook import (
    AegisToolkit,
    AegisToolWrapper,
    VinciToolkit,
    VinciToolWrapper,
    aegis_tool,
    protect_agent_tools,
    vinci_tool,
)
from vinci_adr.daemon.mcp_interceptor import AegisMCPMiddleware, VinciMCPMiddleware
from vinci_adr.output_guard.scanner import OutputGuardEngine
from vinci_adr.code_shield.scanner import CodeShieldScanner

__all__ = [
    "__version__",
    "VinciADREngine",
    "VinciEngine",
    "ADRAegisEngine",
    "EngineConfig",
    "EvaluationResult",
    "SensitivityPreset",
    "Verdict",
    "ActionDecision",
    "ThreatSeverity",
    "ThreatMatch",
    "AgentEvent",
    "ExtractedArtifacts",
    "TierSource",
    "Tier2Assessment",
    "Tier2Input",
    "VinciDaemon",
    "AegisDaemon",
    "DaemonConfig",
    "InterceptionDecision",
    "InterceptionResult",
    "VinciMCPMiddleware",
    "AegisMCPMiddleware",
    "VinciToolWrapper",
    "AegisToolWrapper",
    "VinciToolkit",
    "AegisToolkit",
    "vinci_tool",
    "aegis_tool",
    "protect_agent_tools",
    "OutputGuardEngine",
    "CodeShieldScanner",
]
