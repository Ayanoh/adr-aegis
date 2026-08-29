"""Tier 1 Fast Detection: heuristics, secrets scanning, ML classifier, and vector matching."""

from .heuristics import HeuristicsEngine
from .ml_classifier import (
    DEFAULT_THRESHOLD,
    ClassificationResult,
    MLClassifier,
)
from .secrets_scanner import (
    SecretFinding,
    SecretsScanner,
    calculate_entropy,
    is_false_positive,
)
from .vector_matcher import (
    DEFAULT_CRITICAL_THRESHOLD,
    DEFAULT_HIGH_THRESHOLD,
    DEFAULT_MEDIUM_THRESHOLD,
    VectorMatch,
    VectorMatcher,
)
from .wolf_defender import (
    WolfDefenderClassifier,
    WolfDefenderResult,
)

__all__ = [
    "DEFAULT_CRITICAL_THRESHOLD",
    "DEFAULT_HIGH_THRESHOLD",
    "DEFAULT_MEDIUM_THRESHOLD",
    "DEFAULT_THRESHOLD",
    "ClassificationResult",
    "HeuristicsEngine",
    "MLClassifier",
    "SecretFinding",
    "SecretsScanner",
    "VectorMatch",
    "VectorMatcher",
    "WolfDefenderClassifier",
    "WolfDefenderResult",
    "calculate_entropy",
    "is_false_positive",
]
