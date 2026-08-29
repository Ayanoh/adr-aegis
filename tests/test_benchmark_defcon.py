"""Unit tests for DEF CON 31 benchmark and Full Arsenal live demonstration."""

from pathlib import Path
from unittest.mock import MagicMock

from aegis.core.engine import ADRAegisEngine
from aegis.core.schema import ActionDecision, TierSource, Verdict
from scripts.benchmark_defcon import (
    calculate_metrics,
    load_benchmark_dataset,
    run_defcon_benchmark,
)
from scripts.demo_full_arsenal import (
    generate_executive_report,
    run_scenario_1_input_encoding,
    run_scenario_2_secrets_dlp,
    run_scenario_5_daemon_mcp_interception,
    run_scenario_6_output_guard_and_code_shield,
)


def test_benchmark_dataset_loading() -> None:
    """Benchmark dataset loads cleanly and respects the limit argument."""
    full_dataset = load_benchmark_dataset()
    assert len(full_dataset) > 5
    assert all("text" in item and "is_malicious" in item for item in full_dataset)

    limited_dataset = load_benchmark_dataset(limit=3)
    assert len(limited_dataset) == 3


def test_benchmark_metrics_calculation() -> None:
    """Metrics calculation computes accurate Precision, Recall, F1, and FPR."""
    mock_results = [
        {"is_malicious": True, "was_blocked": True, "latency_ms": 10.0},
        {"is_malicious": True, "was_blocked": True, "latency_ms": 12.0},
        {"is_malicious": True, "was_blocked": False, "latency_ms": 8.0},  # 1 FN
        {"is_malicious": False, "was_blocked": False, "latency_ms": 5.0},
        {"is_malicious": False, "was_blocked": False, "latency_ms": 6.0},
    ]

    metrics = calculate_metrics(mock_results)

    assert metrics["total_samples"] == 5
    assert metrics["true_positives"] == 2
    assert metrics["false_negatives"] == 1
    assert metrics["true_negatives"] == 2
    assert metrics["false_positives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall_block_rate"] == round(2 / 3, 4)
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["latency_p50_ms"] > 0


def test_benchmark_engine_evaluation_flow() -> None:
    """run_defcon_benchmark executes successfully on a mock engine."""
    mock_engine = MagicMock(spec=ADRAegisEngine)
    mock_eval_res = MagicMock()
    mock_eval_res.verdict = Verdict(
        decision=ActionDecision.BLOCK,
        confidence=1.0,
        reason="Malicious prompt detected",
        threats=[],
        tier_source=TierSource.TIER1_HEURISTICS,
        latency_ms=5.0,
    )
    mock_engine.evaluate.return_value = mock_eval_res

    sample_data = [
        {"text": "malicious input", "is_malicious": True, "category": "test"},
        {"text": "benign input", "is_malicious": False, "category": "test"},
    ]

    output = run_defcon_benchmark(engine=mock_engine, dataset=sample_data)

    assert "metrics" in output
    assert "results" in output
    assert len(output["results"]) == 2
    assert mock_engine.evaluate.call_count == 2


def test_benchmark_zero_division_guard() -> None:
    """calculate_metrics handles empty lists without ZeroDivisionError."""
    empty_metrics = calculate_metrics([])
    assert empty_metrics["total_samples"] == 0
    assert empty_metrics["precision"] == 1.0
    assert empty_metrics["recall_block_rate"] == 1.0
    assert empty_metrics["f1_score"] == 0.0


def test_benchmark_latency_tracking() -> None:
    """Latency mean, P50 and P95 percentiles are computed accurately."""
    mock_results = [
        {"is_malicious": True, "was_blocked": True, "latency_ms": float(i)} for i in range(1, 25)
    ]
    metrics = calculate_metrics(mock_results)
    assert metrics["latency_mean_ms"] == 12.5
    assert metrics["latency_p50_ms"] == 12.5
    assert metrics["latency_p95_ms"] > 20.0


def test_demo_scenario_execution_input_guards() -> None:
    """Demo scenarios 1 and 2 execute cleanly without error."""
    mock_engine = MagicMock(spec=ADRAegisEngine)
    mock_eval_res = MagicMock()
    mock_eval_res.verdict = Verdict(
        decision=ActionDecision.BLOCK,
        confidence=1.0,
        reason="Threat detected",
        threats=[],
        tier_source=TierSource.TIER1_HEURISTICS,
        latency_ms=8.0,
    )
    mock_engine.evaluate.return_value = mock_eval_res

    res1 = run_scenario_1_input_encoding(mock_engine)
    assert res1["verdict"].decision == ActionDecision.BLOCK

    res2 = run_scenario_2_secrets_dlp(mock_engine)
    assert res2["verdict"].decision == ActionDecision.BLOCK


def test_demo_scenario_execution_daemon_mcp() -> None:
    """Demo scenario 5 executes Daemon MCP interception properly."""
    res5 = run_scenario_5_daemon_mcp_interception()
    assert res5["is_allowed"] is False
    assert res5["response"]["error"]["code"] == -32000


def test_demo_scenario_execution_output_and_code() -> None:
    """Demo scenario 6 executes Output Guard and Code Shield properly."""
    res6 = run_scenario_6_output_guard_and_code_shield()
    assert res6["output_verdict"].decision.value == "redact"
    assert not res6["code_verdict"].is_secure

    # Test report generation
    report_path = generate_executive_report()
    assert report_path.exists()
    assert Path(report_path).stat().st_size > 500
