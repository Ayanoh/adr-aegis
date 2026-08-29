"""Wolf Defender v2 classifier for prompt injection detection using ModernBERT."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import structlog

from aegis.core.schema import (
    ActionDecision,
    ThreatMatch,
    ThreatSeverity,
    TierSource,
    Verdict,
)

logger = structlog.get_logger()

DEFAULT_THRESHOLD = 0.50
MODEL_NAME = "patronus-studio/wolf-defender-prompt-injection-small"


@dataclass
class WolfDefenderResult:
    """Result of a Wolf Defender classification.

    Attributes:
        is_injection: Whether the input was classified as a prompt injection.
        injection_score: Confidence score for prompt injection (0.0 to 1.0).
        benign_score: Confidence score for benign input (0.0 to 1.0).
        confidence: Maximum confidence score between injection and benign.
        model_variant: Variant of the model used (e.g. 'small').
        latency_ms: Inference time in milliseconds.
    """

    is_injection: bool
    injection_score: float
    benign_score: float
    confidence: float
    model_variant: str = "small"
    latency_ms: float = 0.0


class WolfDefenderClassifier:
    """Classifies prompt injections using Patronus AI Wolf Defender (ModernBERT)."""

    def __init__(
        self,
        model_variant: str = "small",
        threshold: float = DEFAULT_THRESHOLD,
        auto_load: bool = True,
        use_onnx: bool = False,
    ) -> None:
        """Initialize the Wolf Defender classifier.

        Args:
            model_variant: Model variant to load ('small').
            threshold: Confidence threshold for prompt injection detection.
            auto_load: If True, load the model on initialization.
            use_onnx: If True, attempt to use ONNX runtime.
        """
        self.model_variant = model_variant
        self.threshold = threshold
        self.use_onnx = use_onnx
        self.model_loaded = False
        self._tokenizer: Any = None
        self._model: Any = None

        if auto_load:
            self.load_model()

    @property
    def is_available(self) -> bool:
        """Return True if the classifier model is loaded and ready."""
        return self.model_loaded and self._model is not None and self._tokenizer is not None

    def load_model(self) -> bool:
        """Load the tokenizer and model from Hugging Face or local cache."""
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            logger.info("Loading Wolf Defender model", model=MODEL_NAME)
            self._tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            self._model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
            self._model.eval()
            self.model_loaded = True
            logger.info("Wolf Defender model loaded successfully")
            return True
        except Exception as e:
            logger.warning("Failed to load Wolf Defender model", error=str(e))
            self.model_loaded = False
            return False

    def classify(self, text: str) -> WolfDefenderResult:
        """Classify input text as prompt injection or benign.

        Args:
            text: Input string to evaluate.

        Returns:
            WolfDefenderResult with scores and latency.
        """
        if not text or not text.strip():
            return WolfDefenderResult(
                is_injection=False,
                injection_score=0.0,
                benign_score=1.0,
                confidence=1.0,
                model_variant=self.model_variant,
                latency_ms=0.0,
            )

        if not self.is_available:
            if not self.load_model():
                return WolfDefenderResult(
                    is_injection=False,
                    injection_score=0.0,
                    benign_score=1.0,
                    confidence=0.0,
                    model_variant=self.model_variant,
                    latency_ms=0.0,
                )

        t0 = time.perf_counter()
        try:
            import torch

            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)[0].tolist()

            # Patronus Wolf Defender output mapping: [BENIGN, INJECTION] or model config
            # Let's inspect id2label if present
            if hasattr(self._model.config, "id2label") and self._model.config.id2label:
                id2label = self._model.config.id2label
                labels = {v.lower(): k for k, v in id2label.items()}
                inj_idx = labels.get("injection", labels.get("prompt_injection", 1))
                benign_idx = labels.get("benign", labels.get("safe", 0))
            else:
                benign_idx, inj_idx = 0, 1

            benign_score = float(probs[benign_idx])
            injection_score = float(probs[inj_idx])
            is_injection = injection_score >= self.threshold
            confidence = max(benign_score, injection_score)
            latency_ms = (time.perf_counter() - t0) * 1000.0

            return WolfDefenderResult(
                is_injection=is_injection,
                injection_score=injection_score,
                benign_score=benign_score,
                confidence=confidence,
                model_variant=self.model_variant,
                latency_ms=latency_ms,
            )
        except Exception as e:
            logger.error("Wolf Defender inference failed", error=str(e))
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return WolfDefenderResult(
                is_injection=False,
                injection_score=0.0,
                benign_score=1.0,
                confidence=0.0,
                model_variant=self.model_variant,
                latency_ms=latency_ms,
            )

    def evaluate(self, text: str) -> Verdict:
        """Evaluate input text and return a standard ADR-AEGIS Verdict.

        Args:
            text: Input text.

        Returns:
            Verdict object.
        """
        if not self.is_available and not self.model_loaded:
            return Verdict(
                decision=ActionDecision.ALLOW,
                confidence=0.0,
                tier_source=TierSource.TIER1_ML,
                threats=[],
                reason="Wolf Defender not available",
                latency_ms=0.0,
            )

        res = self.classify(text)

        if res.is_injection:
            if res.injection_score >= 0.85:
                sev = ThreatSeverity.CRITICAL
            elif res.injection_score >= 0.65:
                sev = ThreatSeverity.HIGH
            else:
                sev = ThreatSeverity.MEDIUM

            threat = ThreatMatch(
                rule_id="WOLF-001",
                rule_name="WolfDefenderPromptInjection",
                category="prompt_injection",
                severity=sev,
                matched_pattern="patronus-studio/wolf-defender-prompt-injection-small",
                matched_content=text[:100],
            )
            return Verdict(
                decision=ActionDecision.BLOCK,
                confidence=res.confidence,
                tier_source=TierSource.TIER1_ML,
                threats=[threat],
                reason=f"Prompt injection detected by Wolf Defender ({res.injection_score:.0%})",
                latency_ms=res.latency_ms,
            )

        return Verdict(
            decision=ActionDecision.ALLOW,
            confidence=res.confidence,
            tier_source=TierSource.TIER1_ML,
            threats=[],
            reason="No prompt injection detected (Wolf Defender)",
            latency_ms=res.latency_ms,
        )
