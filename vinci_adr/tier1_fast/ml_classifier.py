"""Machine learning classifier for prompt injection detection.

Uses DeBERTa-v3 model optimized with ONNX Runtime for fast inference.
Falls back gracefully if ML dependencies or models are not installed.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import numpy as np
except ImportError:
    np = None
import structlog

from vinci_adr.core.schema import (
    ActionDecision,
    ThreatMatch,
    ThreatSeverity,
    TierSource,
    Verdict,
)

logger = structlog.get_logger()

# Model configuration
MODEL_NAME = "ProtectAI/deberta-v3-base-prompt-injection-v2"
MAX_LENGTH = 512  # Maximum token length for the model
DEFAULT_THRESHOLD = 0.85  # Confidence threshold for injection classification

# Label mapping (model outputs)
LABEL_BENIGN = 0
LABEL_INJECTION = 1


@dataclass
class ClassificationResult:
    """Result of ML classification.

    Attributes:
        is_injection: Whether the text is classified as prompt injection.
        confidence: Model confidence score (0.0-1.0).
        raw_scores: Raw logits/probabilities from the model.
        truncated: Whether the input was truncated to fit max length.
        latency_ms: Inference latency in milliseconds.
    """

    is_injection: bool
    confidence: float
    raw_scores: list[float]
    truncated: bool
    latency_ms: float


class MLClassifier:
    """Machine learning classifier for prompt injection detection.

    Uses DeBERTa-v3 model optimized with ONNX Runtime for fast inference.
    Falls back gracefully if ML dependencies are not installed.

    Attributes:
        threshold: Confidence threshold for classifying as injection.
        model_loaded: Whether the model was successfully loaded.
    """

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        model_path: Path | None = None,
        use_gpu: bool = False,
        auto_load: bool = True,
    ) -> None:
        """Initialize the ML classifier.

        Args:
            threshold: Confidence threshold for injection classification.
            model_path: Optional path to ONNX model file. If None, downloads from HuggingFace.
            use_gpu: Whether to use GPU acceleration (requires onnxruntime-gpu).
            auto_load: Whether to automatically load model weights on init.
        """
        self.threshold = threshold
        self.model_path = model_path
        self.use_gpu = use_gpu
        self.model_loaded = False

        self._tokenizer: Any = None
        self._session: Any = None
        self._pipeline: Any = None

        if auto_load:
            self._initialize()

    def _initialize(self) -> None:
        """Lazy initialization of model and tokenizer.

        Only ``transformers`` (with a torch backend) is strictly required. ONNX
        Runtime is an optional inference accelerator: if it is absent, we fall
        back to the standard transformers pipeline instead of disabling the
        classifier entirely.
        """
        try:
            from transformers import AutoTokenizer
        except ImportError as e:
            logger.warning(
                "ML dependencies not available, classifier disabled",
                error=str(e),
            )
            return

        try:
            # Load tokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

            # Determine model path (ONNX is an optional optimization)
            onnx_path = None
            if self.model_path and self.model_path.exists():
                onnx_path = str(self.model_path)
            else:
                onnx_path = self._get_or_create_onnx_model()

            # Use ONNX Runtime only if we actually have an ONNX model AND the lib
            if onnx_path:
                try:
                    import onnxruntime as ort

                    # Configure ONNX Runtime session
                    providers = (
                        ["CUDAExecutionProvider", "CPUExecutionProvider"]
                        if self.use_gpu
                        else ["CPUExecutionProvider"]
                    )
                    self._session = ort.InferenceSession(onnx_path, providers=providers)
                    self.model_loaded = True
                    logger.info("ML classifier initialized", model=MODEL_NAME, onnx=True)
                except ImportError:
                    # onnxruntime not installed -> use transformers pipeline instead
                    self._setup_transformers_fallback()
            else:
                # Fallback to transformers pipeline
                self._setup_transformers_fallback()

        except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
            logger.warning("Failed to initialize ML classifier", error=str(e))

    def _get_or_create_onnx_model(self) -> str | None:
        """Get or create ONNX model from HuggingFace model.

        Returns:
            Path to ONNX model file, or None if not available.
        """
        # In development/test mode, fall back to transformers pipeline
        return None

    def _setup_transformers_fallback(self) -> None:
        """Setup transformers pipeline as fallback when ONNX is not available."""
        try:
            from transformers import pipeline

            self._pipeline = pipeline(
                "text-classification",
                model=MODEL_NAME,
                device=-1,  # CPU
                truncation=True,
                max_length=MAX_LENGTH,
            )
            self.model_loaded = True
            logger.info("ML classifier initialized (transformers fallback)", model=MODEL_NAME)
        except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
            logger.warning("Transformers fallback failed", error=str(e))

    def classify(self, text: str) -> ClassificationResult:
        """Classify text as benign or prompt injection.

        Args:
            text: Input text to classify.

        Returns:
            ClassificationResult with classification details.
        """
        if not self.model_loaded:
            # Return safe default if model not available
            return ClassificationResult(
                is_injection=False,
                confidence=0.0,
                raw_scores=[1.0, 0.0],
                truncated=False,
                latency_ms=0.0,
            )

        start_time = time.perf_counter()
        truncated = len(text) > MAX_LENGTH * 4

        if self._session is not None:
            result = self._classify_onnx(text)
        elif self._pipeline is not None:
            result = self._classify_transformers(text)
        else:
            return ClassificationResult(
                is_injection=False,
                confidence=0.0,
                raw_scores=[1.0, 0.0],
                truncated=truncated,
                latency_ms=0.0,
            )

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        result.truncated = truncated
        result.latency_ms = latency_ms

        return result

    def _classify_onnx(self, text: str) -> ClassificationResult:
        """Classify using ONNX Runtime."""
        inputs = self._tokenizer(
            text,
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
            return_tensors="np",
        )

        ort_inputs = {
            self._session.get_inputs()[0].name: inputs["input_ids"],
            self._session.get_inputs()[1].name: inputs["attention_mask"],
        }

        outputs = self._session.run(None, ort_inputs)
        logits = outputs[0][0]

        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)

        injection_prob = float(probs[LABEL_INJECTION])

        return ClassificationResult(
            is_injection=injection_prob >= self.threshold,
            confidence=injection_prob if injection_prob >= 0.5 else 1.0 - injection_prob,
            raw_scores=probs.tolist(),
            truncated=False,
            latency_ms=0.0,
        )

    def _classify_transformers(self, text: str) -> ClassificationResult:
        """Classify using transformers pipeline."""
        result = self._pipeline(text[: MAX_LENGTH * 4])[0]

        label = str(result["label"])
        score = float(result["score"])

        is_injection = label.upper() in ("INJECTION", "1", "LABEL_1")

        if is_injection:
            probs = [1.0 - score, score]
        else:
            probs = [score, 1.0 - score]

        return ClassificationResult(
            is_injection=is_injection and score >= self.threshold,
            confidence=score,
            raw_scores=probs,
            truncated=False,
            latency_ms=0.0,
        )

    def evaluate(self, text: str) -> Verdict:
        """Evaluate text and return a verdict.

        Args:
            text: Input text to evaluate.

        Returns:
            Verdict with decision based on ML classification.
        """
        result = self.classify(text)

        threats: list[ThreatMatch] = []
        if result.is_injection:
            severity = ThreatSeverity.HIGH if result.confidence >= 0.90 else ThreatSeverity.MEDIUM
            decision = ActionDecision.BLOCK if result.confidence >= 0.90 else ActionDecision.ASK
            threats.append(
                ThreatMatch(
                    rule_id="ADR-ML-001",
                    rule_name="ML Prompt Injection Detection",
                    category="prompt_injection",
                    severity=severity,
                    matched_pattern="deberta-v3-prompt-injection",
                    matched_content=text[:100] + "..." if len(text) > 100 else text,
                )
            )
            confidence = result.confidence
            reason = (
                f"ML classifier detected prompt injection (confidence: {result.confidence:.2%})"
            )
        else:
            decision = ActionDecision.ALLOW
            confidence = 1.0 - result.confidence if result.confidence < 0.5 else result.confidence
            reason = "ML classifier: no injection detected"

        return Verdict(
            decision=decision,
            confidence=confidence,
            tier_source=TierSource.TIER1_ML,
            threats=threats,
            reason=reason,
            latency_ms=result.latency_ms,
        )

    @property
    def is_available(self) -> bool:
        """Returns True if the classifier is ready to use."""
        return self.model_loaded
