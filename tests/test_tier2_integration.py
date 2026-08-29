"""Integration tests for Tier 2 escalation and cognitive reasoning within ADRAegisEngine."""

import json

from aegis.core.engine import ADRAegisEngine, EngineConfig
from aegis.core.schema import ActionDecision, TierSource
from aegis.tier2_deep.llm_provider import MockLLMProvider
from aegis.tier2_deep.orchestrator import Tier2Engine

# Reliable ASK case: clean base64 payload that triggers decode_all deobfuscation
# (is_suspicious=True), boosting an initial ALLOW verdict to Tier 1 ASK.
ASK_TEST_INPUT = "echo aGVsbG8= | base64 -d"


def _make_assessment_json(
    *,
    is_malicious: bool,
    severity: str,
    decision: str,
    confidence: float,
    rationale: str,
    indicators: list[str] | None = None,
) -> str:
    """Helper to generate valid Tier2Assessment JSON strings."""
    return json.dumps(
        {
            "is_malicious": is_malicious,
            "severity": severity,
            "recommended_decision": decision,
            "confidence": confidence,
            "rationale": rationale,
            "indicators": indicators or [],
        }
    )


def test_ask_escalates_to_block() -> None:
    """Verify that an ambiguous Tier 1 ASK decision escalates to Tier 2 and is confirmed as BLOCK."""
    forensic_json = _make_assessment_json(
        is_malicious=True,
        severity="critical",
        decision="block",
        confidence=0.88,
        rationale="Forensic detected hidden malicious intent in obfuscated script",
        indicators=["base64", "script"],
    )
    critic_json = _make_assessment_json(
        is_malicious=True,
        severity="critical",
        decision="block",
        confidence=0.92,
        rationale="Critic confirmed Forensic findings: dangerous payload execution",
        indicators=["confirmed execution"],
    )

    mock_provider = MockLLMProvider(responses=[forensic_json, critic_json])
    tier2 = Tier2Engine(mock_provider)
    config = EngineConfig(enable_ml=False, enable_vector=False, enable_tier2=True)
    engine = ADRAegisEngine(config, tier2_engine=tier2)

    result = engine.evaluate(ASK_TEST_INPUT)
    assert result.verdict.decision == ActionDecision.BLOCK
    assert result.verdict.tier_source == TierSource.TIER2_COGNITIVE
    assert result.verdict.confidence == 0.92
    assert "Forensic" in result.verdict.reason
    assert "Critic" in result.verdict.reason


def test_ask_deescalates_to_allow() -> None:
    """Verify that an ambiguous Tier 1 ASK decision is safely cleared to ALLOW by Tier 2."""
    forensic_json = _make_assessment_json(
        is_malicious=False,
        severity="info",
        decision="allow",
        confidence=0.85,
        rationale="Decoded payload is standard benign greeting text",
        indicators=["benign echo"],
    )
    critic_json = _make_assessment_json(
        is_malicious=False,
        severity="info",
        decision="allow",
        confidence=0.90,
        rationale="Critic verified: no threat present in decoded payload",
        indicators=[],
    )

    mock_provider = MockLLMProvider(responses=[forensic_json, critic_json])
    tier2 = Tier2Engine(mock_provider)
    config = EngineConfig(enable_ml=False, enable_vector=False, enable_tier2=True)
    engine = ADRAegisEngine(config, tier2_engine=tier2)

    result = engine.evaluate(ASK_TEST_INPUT)
    assert result.verdict.decision == ActionDecision.ALLOW
    assert result.verdict.tier_source == TierSource.TIER2_COGNITIVE
    assert result.verdict.confidence == 0.90


def test_tier2_populates_result_trace() -> None:
    """Verify that EvaluationResult.tier2 exposes full Forensic and Critic trace."""
    forensic_json = _make_assessment_json(
        is_malicious=True,
        severity="medium",
        decision="ask",
        confidence=0.75,
        rationale="Suspicious structure",
    )
    critic_json = _make_assessment_json(
        is_malicious=True,
        severity="medium",
        decision="ask",
        confidence=0.80,
        rationale="Maintain human review",
    )

    mock_provider = MockLLMProvider(responses=[forensic_json, critic_json])
    tier2 = Tier2Engine(mock_provider)
    config = EngineConfig(enable_ml=False, enable_vector=False, enable_tier2=True)
    engine = ADRAegisEngine(config, tier2_engine=tier2)

    result = engine.evaluate(ASK_TEST_INPUT)
    assert result.tier2 is not None
    assert result.tier2.forensic is not None
    assert result.tier2.critic is not None
    assert result.tier2.forensic.source_agent == "forensic"
    assert result.tier2.critic.source_agent == "critic"


def test_block_case_not_escalated() -> None:
    """Verify that Tier 1 BLOCK cases are never escalated to Tier 2 (saving LLM inference)."""
    # Even if Tier 2 would return ALLOW, Tier 1 BLOCK must short-circuit without calling Tier 2
    mock_provider = MockLLMProvider(
        default_response=_make_assessment_json(
            is_malicious=False,
            severity="info",
            decision="allow",
            confidence=0.99,
            rationale="Would allow if called",
        )
    )
    tier2 = Tier2Engine(mock_provider)
    config = EngineConfig(enable_ml=False, enable_vector=False, enable_tier2=True)
    engine = ADRAegisEngine(config, tier2_engine=tier2)

    # Definite Tier 1 BLOCK (Mimikatz credential dump)
    result = engine.evaluate("sekurlsa::logonPasswords")
    assert result.verdict.decision == ActionDecision.BLOCK
    assert result.verdict.tier_source != TierSource.TIER2_COGNITIVE
    assert len(mock_provider.calls) == 0
    assert result.tier2 is None


def test_allow_case_not_escalated() -> None:
    """Verify that clear Tier 1 ALLOW cases are never escalated to Tier 2."""
    mock_provider = MockLLMProvider()
    tier2 = Tier2Engine(mock_provider)
    config = EngineConfig(enable_ml=False, enable_vector=False, enable_tier2=True)
    engine = ADRAegisEngine(config, tier2_engine=tier2)

    result = engine.evaluate("Hello, how are you?")
    assert result.verdict.decision == ActionDecision.ALLOW
    assert result.verdict.tier_source != TierSource.TIER2_COGNITIVE
    assert len(mock_provider.calls) == 0
    assert result.tier2 is None


def test_tier2_disabled_by_default() -> None:
    """Verify non-regression: Tier 2 is disabled by default, keeping Tier 1 ASK intact."""
    config = EngineConfig(enable_ml=False, enable_vector=False)
    assert config.enable_tier2 is False
    engine = ADRAegisEngine(config)

    result = engine.evaluate(ASK_TEST_INPUT)
    assert result.verdict.decision == ActionDecision.ASK
    assert result.tier2 is None
    assert result.verdict.tier_source != TierSource.TIER2_COGNITIVE


def test_tier2_degrades_safely() -> None:
    """Verify that if Tier 2 encounters a parsing or provider error, it falls back to ASK."""
    mock_provider = MockLLMProvider(default_response="ceci n'est pas du JSON")
    tier2 = Tier2Engine(mock_provider)
    config = EngineConfig(enable_ml=False, enable_vector=False, enable_tier2=True)
    engine = ADRAegisEngine(config, tier2_engine=tier2)

    result = engine.evaluate(ASK_TEST_INPUT)
    assert result.verdict.decision == ActionDecision.ASK
    assert "Tier 2 degraded" in result.verdict.reason
    assert result.tier2 is not None
    assert result.tier2.forensic is None
