"""Evaluation harness for measuring ML prompt injection classifier performance.

Loads evaluation datasets (from HuggingFace), computes model predictions,
sweeps classification confidence thresholds, and recommends optimal calibration
thresholds for Paranoid, Balanced, and Relaxed security presets.

HuggingFace Datasets & Models Used:
- Model: ProtectAI/deberta-v3-base-prompt-injection-v2
- Dataset 1: deepset/prompt-injections (split: test)
- Dataset 2: fka/awesome-chatgpt-prompts (benign negative samples)
"""

import sys
import time

import structlog

from aegis.tier1_fast.ml_classifier import MLClassifier

logger = structlog.get_logger()


def load_evaluation_dataset(include_extra_benign: bool = True) -> list[tuple[str, int]]:
    """Loads labeled evaluation data for prompt injection benchmarking.

    Primary Source: deepset/prompt-injections (HuggingFace)
      - Columns: 'text' (str), 'label' (int: 1=injection, 0=benign)
      - Uses the 'test' split for unbiased evaluation.

    Secondary Source (if include_extra_benign):
      - fka/awesome-chatgpt-prompts (HuggingFace)
      - Column 'prompt' mapped to label 0 (benign prompt samples)

    Args:
        include_extra_benign: Whether to append additional benign prompt samples.

    Returns:
        List of tuples (text, label) where label is in {0, 1}.

    Raises:
        ImportError: If the datasets library is not installed.
        RuntimeError: If dataset loading fails due to network or format errors.
    """
    try:
        from datasets import load_dataset
    except ImportError as e:
        raise ImportError(
            "The 'datasets' package is required for evaluation. Install it with: pip install datasets"
        ) from e

    samples: list[tuple[str, int]] = []

    # 1. Load deepset/prompt-injections test split
    try:
        logger.info("Loading primary evaluation dataset: deepset/prompt-injections")
        ds = load_dataset("deepset/prompt-injections", split="test")
        for item in ds:
            text = str(item.get("text", "")).strip()
            label = int(item.get("label", 0))
            if text:
                samples.append((text, label))
        logger.info("Loaded primary samples", count=len(samples))
    except Exception as e:
        raise RuntimeError(f"Failed to load dataset 'deepset/prompt-injections': {e}") from e

    # 2. Optionally load additional benign prompts
    if include_extra_benign:
        try:
            logger.info("Loading supplementary benign dataset: fka/awesome-chatgpt-prompts")
            extra_ds = load_dataset("fka/awesome-chatgpt-prompts", split="train")
            extra_count = 0
            for item in extra_ds:
                text = str(item.get("prompt", "")).strip()
                if text:
                    samples.append((text, 0))
                    extra_count += 1
            logger.info("Loaded supplementary benign samples", count=extra_count)
        except (RuntimeError, ValueError, OSError, TypeError, AttributeError, KeyError) as e:
            logger.warning(
                "Could not load supplementary benign dataset (continuing with primary dataset)",
                error=str(e),
            )

    return samples


def compute_predictions(
    classifier: MLClassifier, samples: list[tuple[str, int]]
) -> list[tuple[float, int]]:
    """Computes raw injection probabilities for all samples using the ML classifier.

    Extracts result.raw_scores[1] (raw injection probability) for every sample
    to allow multi-threshold sweeping without re-running model inference.

    Args:
        classifier: MLClassifier instance.
        samples: List of (text, true_label) evaluation samples.

    Returns:
        List of tuples (injection_probability, true_label).
    """
    predictions: list[tuple[float, int]] = []
    total = len(samples)

    logger.info("Computing model predictions", total_samples=total)
    start_time = time.perf_counter()

    for idx, (text, true_label) in enumerate(samples, 1):
        result = classifier.classify(text)
        # raw_scores format: [benign_prob, injection_prob]
        if len(result.raw_scores) >= 2:
            injection_prob = float(result.raw_scores[1])
        else:
            injection_prob = float(result.confidence) if result.is_injection else 0.0

        predictions.append((injection_prob, true_label))

        if idx % 100 == 0 or idx == total:
            logger.debug(f"Progress: {idx}/{total} predictions computed")

    elapsed = time.perf_counter() - start_time
    avg_latency = (elapsed / total * 1000.0) if total > 0 else 0.0
    logger.info(
        "Predictions computation complete",
        elapsed_sec=round(elapsed, 2),
        avg_latency_ms=round(avg_latency, 2),
    )

    return predictions


def evaluate_at_threshold(
    predictions: list[tuple[float, int]], threshold: float
) -> dict[str, float]:
    """Calculates classification metrics at a given injection confidence threshold.

    Prediction rule: sample is classified as INJECTION if injection_probability >= threshold.

    Calculates:
      - TP (True Positive): predicted injection AND actual injection
      - FP (False Positive): predicted injection AND actual benign (False alarm)
      - TN (True Negative): predicted benign AND actual benign
      - FN (False Negative): predicted benign AND actual injection (Missed threat)
      - Precision: TP / (TP + FP)
      - Recall: TP / (TP + FN)
      - F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
      - Accuracy: (TP + TN) / Total

    Args:
        predictions: List of (injection_probability, true_label) tuples.
        threshold: Confidence threshold value (0.0 - 1.0).

    Returns:
        Dictionary containing threshold, counts (tp, fp, tn, fn), and calculated metrics.
    """
    tp = sum(1 for prob, label in predictions if prob >= threshold and label == 1)
    fp = sum(1 for prob, label in predictions if prob >= threshold and label == 0)
    tn = sum(1 for prob, label in predictions if prob < threshold and label == 0)
    fn = sum(1 for prob, label in predictions if prob < threshold and label == 1)

    total = len(predictions)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total) if total > 0 else 0.0

    return {
        "threshold": threshold,
        "tp": float(tp),
        "fp": float(fp),
        "tn": float(tn),
        "fn": float(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def threshold_sweep(
    predictions: list[tuple[float, int]],
    thresholds: list[float] | None = None,
) -> list[dict[str, float]]:
    """Evaluates classifier performance across a range of confidence thresholds.

    Args:
        predictions: List of (injection_probability, true_label) tuples.
        thresholds: Optional list of thresholds to evaluate. Defaults to [0.50..0.95, 0.99].

    Returns:
        List of evaluation metric dictionaries, one per threshold.
    """
    if thresholds is None:
        thresholds = [
            0.50,
            0.55,
            0.60,
            0.65,
            0.70,
            0.75,
            0.80,
            0.85,
            0.90,
            0.95,
            0.99,
        ]

    return [evaluate_at_threshold(predictions, t) for t in thresholds]


def recommend_thresholds(sweep_results: list[dict[str, float]]) -> dict[str, float]:
    """Recommends calibrated thresholds for each security sensitivity preset.

    Presets:
      - PARANOID: Maximizes RECALL (catches maximum threats, allows more false positives).
                  Selects highest recall with precision >= 0.70.
      - BALANCED: Maximizes F1 score (best balance between precision and recall).
      - RELAXED:  Maximizes PRECISION (minimizes false alarms, tolerates occasional misses).
                  Selects highest precision with recall >= 0.60.

    Args:
        sweep_results: List of threshold metric dictionaries from threshold_sweep.

    Returns:
        Dictionary mapping preset names ("paranoid", "balanced", "relaxed") to recommended thresholds.
    """
    if not sweep_results:
        return {"paranoid": 0.70, "balanced": 0.85, "relaxed": 0.95}

    # 1. PARANOID: Maximize recall subject to precision >= 0.70
    paranoid_candidates = [r for r in sweep_results if r["precision"] >= 0.70]
    if paranoid_candidates:
        paranoid_best = max(paranoid_candidates, key=lambda r: (r["recall"], r["f1"]))
    else:
        paranoid_best = max(sweep_results, key=lambda r: r["recall"])

    # 2. BALANCED: Maximize F1 score
    balanced_best = max(sweep_results, key=lambda r: (r["f1"], r["accuracy"]))

    # 3. RELAXED: Maximize precision subject to recall >= 0.60
    relaxed_candidates = [r for r in sweep_results if r["recall"] >= 0.60]
    if relaxed_candidates:
        relaxed_best = max(relaxed_candidates, key=lambda r: (r["precision"], r["f1"]))
    else:
        relaxed_best = max(sweep_results, key=lambda r: r["precision"])

    return {
        "paranoid": paranoid_best["threshold"],
        "balanced": balanced_best["threshold"],
        "relaxed": relaxed_best["threshold"],
    }


def format_table(results: list[dict[str, float]]) -> str:
    """Formats sweep results into an aligned, terminal-friendly ASCII table."""
    headers = ["Threshold", "Precision", "Recall", "F1 Score", "Accuracy", "TP", "FP", "FN", "TN"]
    rows = []

    for r in results:
        rows.append(
            [
                f"{r['threshold']:.2f}",
                f"{r['precision']:.4f}",
                f"{r['recall']:.4f}",
                f"{r['f1']:.4f}",
                f"{r['accuracy']:.4f}",
                f"{int(r['tp']):d}",
                f"{int(r['fp']):d}",
                f"{int(r['fn']):d}",
                f"{int(r['tn']):d}",
            ]
        )

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def make_line(chars: list[str], sep: str = "|") -> str:
        padded = [f" {c.ljust(col_widths[i])} " for i, c in enumerate(chars)]
        return f"{sep}{sep.join(padded)}{sep}"

    divider = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    header_line = make_line(headers)

    table_lines = [divider, header_line, divider]
    for row in rows:
        table_lines.append(make_line(row))
    table_lines.append(divider)

    return "\n".join(table_lines)


def main() -> None:
    """Runs the complete evaluation and threshold calibration workflow."""
    print("=" * 80)
    print(" ADR-AEGIS: ML Prompt Injection Classifier Calibration & Benchmark ")
    print("=" * 80)
    print("Model: ProtectAI/deberta-v3-base-prompt-injection-v2\n")

    # 1. Load dataset
    try:
        samples = load_evaluation_dataset(include_extra_benign=True)
    except (RuntimeError, ImportError, ValueError, OSError) as e:
        print(f"\n[ERROR] Failed to load evaluation dataset: {e}", file=sys.stderr)
        print(
            "Ensure internet connectivity or install datasets: pip install datasets\n",
            file=sys.stderr,
        )
        sys.exit(1)

    total_samples = len(samples)
    injections = sum(1 for _, label in samples if label == 1)
    benign = sum(1 for _, label in samples if label == 0)

    print("Dataset Summary:")
    print(f"  • Total samples: {total_samples}")
    print(f"  • Injections   : {injections} ({injections / total_samples:.1%})")
    print(f"  • Benign       : {benign} ({benign / total_samples:.1%})\n")

    # 2. Initialize classifier
    print("Initializing ML Classifier...")
    classifier = MLClassifier()
    if not classifier.is_available:
        print(
            "\n[WARNING] Real ML model not loaded (transformers/onnx missing). Using fallback/mock.\n"
        )

    # 3. Compute predictions
    print("Running inferences across dataset...")
    predictions = compute_predictions(classifier, samples)

    # 4. Sweep thresholds
    print("\nExecuting threshold sweep...")
    sweep_results = threshold_sweep(predictions)

    # 5. Display table
    print("\n" + format_table(sweep_results))

    # 6. Display recommendations
    recommendations = recommend_thresholds(sweep_results)
    print("\n" + "=" * 80)
    print(" RECOMMENDED THRESHOLDS BY PRESET")
    print("=" * 80)
    print(
        f"  🛡️  PARANOID : threshold = {recommendations['paranoid']:.2f}  (High Recall, catches subtle attacks)"
    )
    print(
        f"  ⚖️  BALANCED : threshold = {recommendations['balanced']:.2f}  (Optimal F1 score, balanced tradeoff)"
    )
    print(
        f"  🚀 RELAXED  : threshold = {recommendations['relaxed']:.2f}  (High Precision, minimal false alarms)"
    )
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
