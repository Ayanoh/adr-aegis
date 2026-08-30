"""Decision Engine and orchestrator for Tier 1 Fast detection and Tier 2 Deep reasoning.

Coordinates heuristics, secrets scanner, ML classifier, vector matcher, and cognitive
dual-agent LLM reasoning to deliver fast, unified, and explainable security verdicts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from vinci_adr.core.schema import (
    ActionDecision,
    AgentEvent,
    ExtractedArtifacts,
    ThreatMatch,
    TierSource,
    Verdict,
)
from vinci_adr.sensor.decoders import DecodedResult

if TYPE_CHECKING:
    from vinci_adr.tier2_deep.orchestrator import Tier2Engine, Tier2Result

logger = structlog.get_logger()


class SensitivityPreset(str, Enum):
    """Sensitivity presets for detection thresholds.

    Attributes:
        PARANOID: Maximum security, may have more false positives.
        BALANCED: Default balance between security and usability.
        RELAXED: Minimum friction, only high-confidence threats blocked.
    """

    PARANOID = "paranoid"
    BALANCED = "balanced"
    RELAXED = "relaxed"


@dataclass
class EngineConfig:
    """Configuration for the Vinci ADR engine.

    Attributes:
        sensitivity: Detection sensitivity preset.
        enable_heuristics: Enable rule-based heuristics.
        enable_secrets: Enable secrets scanning.
        enable_ml: Enable ML classifier (requires dependencies).
        enable_vector: Enable vector similarity matching (requires dependencies).
        enable_tier2: Enable Tier 2 deep cognitive reasoning on ambiguous (ASK) cases.
        rules_dir: Path to YAML rules directory.
        vector_db_path: Path to vector database persistence directory.
        ml_threshold: ML classifier confidence threshold (compatibility alias).
        ml_threshold_paranoid: ML classifier threshold for paranoid preset.
        ml_threshold_balanced: ML classifier threshold for balanced preset.
        ml_threshold_relaxed: ML classifier threshold for relaxed preset.
        paranoid_threshold: Confidence threshold for paranoid mode.
        balanced_threshold: Confidence threshold for balanced mode.
        relaxed_threshold: Confidence threshold for relaxed mode.
    """

    sensitivity: SensitivityPreset = SensitivityPreset.BALANCED
    enable_heuristics: bool = True
    enable_secrets: bool = True
    enable_ml: bool = True
    enable_vector: bool = True
    enable_tier2: bool = False
    enable_jailbreak_classifier: bool = False
    enable_wolf_defender: bool = False
    rules_dir: Path | None = None
    vector_db_path: Path | None = None

    # Low thresholds justified by Order #10 benchmark: 100% precision across
    # all thresholds, so lowering threshold increases recall without false positives.
    ml_threshold: float = 0.50  # alias de compat (garder)
    ml_threshold_paranoid: float = 0.05  # rappel max, précision reste 100 %
    ml_threshold_balanced: float = 0.50
    ml_threshold_relaxed: float = 0.50

    paranoid_threshold: float = 0.70
    balanced_threshold: float = 0.85
    relaxed_threshold: float = 0.95


@dataclass
class EvaluationResult:
    """Complete evaluation result from the engine.

    Attributes:
        verdict: Final unified verdict.
        decoded: Result of decoding/deobfuscation.
        artifacts: Extracted artifacts from the input.
        tier1_verdicts: Individual verdicts from each Tier 1 component.
        total_latency_ms: Total evaluation time in milliseconds.
        tier2: Outcome of Tier 2 cognitive evaluation if escalated.
    """

    verdict: Verdict
    decoded: DecodedResult
    artifacts: ExtractedArtifacts
    tier1_verdicts: dict[str, Verdict] = field(default_factory=dict)
    total_latency_ms: float = 0.0
    tier2: Tier2Result | None = None


class VinciADREngine:
    """Main orchestration engine for Vinci ADR threat detection.

    Coordinates all Tier 1 components (heuristics, secrets, ML, vector)
    and produces unified security verdicts, escalating ambiguous (ASK) cases
    to Tier 2 deep cognitive reasoning.

    Attributes:
        config: Engine configuration.
    """

    def __init__(
        self,
        config: EngineConfig | None = None,
        *,
        tier2_engine: Tier2Engine | None = None,
    ) -> None:
        """Initialize the Vinci ADR engine.

        Args:
            config: Engine configuration. Uses defaults if None.
            tier2_engine: Optional injected Tier 2 reasoning engine.
        """
        self.config = config or EngineConfig()
        self._tier2: Any = tier2_engine

        self._heuristics: Any = None
        self._secrets: Any = None
        self._ml: Any = None
        self._wolf: Any = None
        self._vector: Any = None
        self._jailbreak: Any = None

        self._initialize_components()

    @property
    def _jailbreak_classifier(self) -> Any:
        """Alias property for _jailbreak."""
        return self._jailbreak

    def _initialize_components(self) -> None:
        """Initialize enabled detection components."""
        if self.config.enable_heuristics:
            try:
                from vinci_adr.tier1_fast.heuristics import HeuristicsEngine

                self._heuristics = HeuristicsEngine(rules_dir=self.config.rules_dir)
                logger.info(
                    "Heuristics engine initialized",
                    rule_count=self._heuristics.rule_count,
                )
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize heuristics", error=str(e))

        if self.config.enable_secrets:
            try:
                from vinci_adr.tier1_fast.secrets_scanner import SecretsScanner

                self._secrets = SecretsScanner()
                logger.info("Secrets scanner initialized")
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize secrets scanner", error=str(e))

        if self.config.enable_ml:
            try:
                from vinci_adr.tier1_fast.ml_classifier import MLClassifier

                self._ml = MLClassifier(threshold=self._get_ml_threshold())
                if self._ml.is_available:
                    logger.info("ML classifier initialized")
                else:
                    logger.info("ML classifier not available (optional dependencies missing)")
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize ML classifier", error=str(e))

        if self.config.enable_jailbreak_classifier:
            try:
                from vinci_adr.tier1_fast.jailbreak_classifier import JailbreakClassifier

                # Use lazy loading (auto_load=False) to defer heavy model loading
                # The model will be loaded on first classify() call
                self._jailbreak = JailbreakClassifier(
                    threshold=self._get_ml_threshold(),
                    auto_load=False,  # Lazy loading for faster startup
                )
                logger.info("Jailbreak classifier registered (lazy loading enabled)")
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize jailbreak classifier", error=str(e))

        if self.config.enable_wolf_defender:
            try:
                from vinci_adr.tier1_fast.wolf_defender import WolfDefenderClassifier

                self._wolf = WolfDefenderClassifier(
                    threshold=self._get_ml_threshold(),
                    auto_load=True,
                )
                logger.info("Wolf Defender classifier initialized")
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize Wolf Defender", error=str(e))

        if self.config.enable_vector:
            try:
                from vinci_adr.tier1_fast.vector_matcher import VectorMatcher

                self._vector = VectorMatcher(db_path=self.config.vector_db_path)
                if self._vector.is_available:
                    # Load known attack patterns into the vector database
                    loaded = self._vector.load_known_attacks()
                    logger.info(
                        "Vector matcher initialized",
                        doc_count=self._vector.document_count,
                        attack_patterns_loaded=loaded,
                    )
                else:
                    logger.info("Vector matcher not available (optional dependencies missing)")
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize vector matcher", error=str(e))

        # Tier 2 deep reasoning (opt-in). If an engine was injected in __init__,
        # keep it. Otherwise, build a real one backed by Gemini when enabled.
        if self.config.enable_tier2 and self._tier2 is None:
            try:
                from vinci_adr.tier2_deep.llm_provider import GeminiProvider
                from vinci_adr.tier2_deep.orchestrator import Tier2Engine

                provider = GeminiProvider()
                if provider.is_available:
                    self._tier2 = Tier2Engine(provider)
                    logger.info("Tier 2 engine initialized")
                else:
                    logger.info("Tier 2 requested but provider is not available")
            except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
                logger.warning("Failed to initialize Tier 2 engine", error=str(e))

    def _get_confidence_threshold(self) -> float:
        """Get confidence threshold based on sensitivity preset."""
        if self.config.sensitivity == SensitivityPreset.PARANOID:
            return self.config.paranoid_threshold
        if self.config.sensitivity == SensitivityPreset.RELAXED:
            return self.config.relaxed_threshold
        return self.config.balanced_threshold

    def _get_ml_threshold(self) -> float:
        """Get ML classifier threshold based on sensitivity preset."""
        if self.config.sensitivity == SensitivityPreset.PARANOID:
            return self.config.ml_threshold_paranoid
        if self.config.sensitivity == SensitivityPreset.RELAXED:
            return self.config.ml_threshold_relaxed
        return self.config.ml_threshold_balanced

    def _merge_verdicts(self, verdicts: list[Verdict]) -> Verdict:
        """Merge multiple verdicts into a single unified verdict.

        Precedence: BLOCK > ASK > SANITIZE > ALLOW
        Confidence: Maximum confidence among top decisions
        Threats: Aggregated from all verdicts.

        Args:
            verdicts: List of verdicts to merge.

        Returns:
            Unified verdict.
        """
        if not verdicts:
            return Verdict(
                decision=ActionDecision.ALLOW,
                confidence=0.10,
                tier_source=TierSource.TIER1_HEURISTICS,
                threats=[],
                reason="No detection components returned a verdict",
                latency_ms=0.0,
            )

        # Collect all threats
        all_threats: list[ThreatMatch] = []
        for v in verdicts:
            all_threats.extend(v.threats)

        # Priority mapping
        decision_priority: dict[ActionDecision, int] = {
            ActionDecision.BLOCK: 4,
            ActionDecision.ASK: 3,
            ActionDecision.SANITIZE: 2,
            ActionDecision.ALLOW: 1,
        }

        # Sort verdicts by decision priority (highest first)
        sorted_verdicts = sorted(
            verdicts,
            key=lambda v: decision_priority.get(v.decision, 0),
            reverse=True,
        )

        best_verdict = sorted_verdicts[0]

        # Apply sensitivity threshold
        threshold = self._get_confidence_threshold()
        if best_verdict.decision == ActionDecision.BLOCK and best_verdict.confidence < threshold:
            # Downgrade to ASK if confidence is below threshold in non-paranoid modes
            if self.config.sensitivity != SensitivityPreset.PARANOID:
                final_decision = ActionDecision.ASK
            else:
                final_decision = best_verdict.decision
        else:
            final_decision = best_verdict.decision

        # Calculate total latency
        total_latency = sum(v.latency_ms for v in verdicts)

        # Determine tier source from highest priority verdict
        tier_source = best_verdict.tier_source

        # Build summary reason
        if all_threats:
            threat_summaries = [f"{t.rule_name} ({t.severity.value})" for t in all_threats[:3]]
            reason = f"Threats detected: {', '.join(threat_summaries)}"
            if len(all_threats) > 3:
                reason += f" (+{len(all_threats) - 3} more)"
        else:
            reason = "No threats detected"

        return Verdict(
            decision=final_decision,
            confidence=best_verdict.confidence,
            tier_source=tier_source,
            threats=all_threats,
            reason=reason,
            latency_ms=total_latency,
        )

    def evaluate(self, text: str) -> EvaluationResult:
        """Evaluate text for security threats.

        Args:
            text: Input text to evaluate.

        Returns:
            Complete evaluation result with verdict and details.
        """
        from vinci_adr.sensor.decoders import decode_all
        from vinci_adr.sensor.extractors import extract_all

        start_time = time.perf_counter()

        # Step 1: Decode/deobfuscate
        decoded = decode_all(text)
        analysis_text = decoded.decoded

        # Step 2: Extract artifacts
        artifacts = extract_all(analysis_text)

        # Step 3: Run Tier 1 components
        tier1_verdicts: dict[str, Verdict] = {}
        verdicts_list: list[Verdict] = []

        if self._heuristics:
            v = self._heuristics.evaluate(analysis_text)
            tier1_verdicts["heuristics"] = v
            verdicts_list.append(v)

        if self._secrets:
            v = self._secrets.evaluate(analysis_text)
            tier1_verdicts["secrets"] = v
            verdicts_list.append(v)

        if self._ml and self._ml.is_available:
            v = self._ml.evaluate(analysis_text)
            tier1_verdicts["ml"] = v
            verdicts_list.append(v)

        if self._wolf and self._wolf.is_available:
            v = self._wolf.evaluate(analysis_text)
            tier1_verdicts["wolf"] = v
            verdicts_list.append(v)

        if self._jailbreak:
            # Note: With lazy loading (auto_load=False), is_available returns False
            # until the first classify() call. We call evaluate() anyway to trigger
            # lazy loading - the classify() method handles initialization.
            v = self._jailbreak.evaluate(analysis_text)
            tier1_verdicts["jailbreak"] = v
            verdicts_list.append(v)

        if self._vector and self._vector.is_available:
            v = self._vector.evaluate(analysis_text)
            tier1_verdicts["vector"] = v
            verdicts_list.append(v)

        # Step 4: Merge verdicts
        final_verdict = self._merge_verdicts(verdicts_list)

        # If decoding revealed hidden content, boost suspicion
        if decoded.is_suspicious and final_verdict.decision == ActionDecision.ALLOW:
            final_verdict = Verdict(
                decision=ActionDecision.ASK,
                confidence=0.60,
                tier_source=final_verdict.tier_source,
                threats=final_verdict.threats,
                reason=f"Obfuscation detected ({', '.join(decoded.transformations)})",
                latency_ms=final_verdict.latency_ms,
            )

        # Step 5: Tier 2 escalation — only ambiguous (ASK) cases go to deep reasoning.
        tier2_result: Tier2Result | None = None
        if (
            self._tier2 is not None
            and self._tier2.is_available
            and final_verdict.decision == ActionDecision.ASK
        ):
            from vinci_adr.core.schema import Tier2Input

            tier2_input = Tier2Input(
                content=analysis_text,
                tier1_decision=final_verdict.decision,
                tier1_reason=final_verdict.reason,
                threats=final_verdict.threats,
                artifacts=artifacts,
                obfuscation=decoded.transformations,
            )
            tier2_result = self._tier2.evaluate(tier2_input)
            logger.info(
                "Tier 2 escalation",
                tier1_decision=final_verdict.decision.value,
                tier2_decision=tier2_result.verdict.decision.value,
            )
            final_verdict = tier2_result.verdict

        total_latency = (time.perf_counter() - start_time) * 1000.0

        return EvaluationResult(
            verdict=final_verdict,
            decoded=decoded,
            artifacts=artifacts,
            tier1_verdicts=tier1_verdicts,
            total_latency_ms=total_latency,
            tier2=tier2_result,
        )

    def evaluate_event(self, event: AgentEvent) -> EvaluationResult:
        """Evaluate an agent event for security threats.

        Args:
            event: Agent event to evaluate.

        Returns:
            Complete evaluation result.
        """
        # Combine relevant fields for analysis
        text_parts: list[str] = [event.user_intent, event.tool_name]
        if event.llm_reasoning:
            text_parts.append(event.llm_reasoning)
        if isinstance(event.tool_input, str):
            text_parts.append(event.tool_input)
        elif isinstance(event.tool_input, dict):
            text_parts.extend(str(v) for v in event.tool_input.values())
        elif isinstance(event.tool_input, (list, tuple)):
            text_parts.extend(str(v) for v in event.tool_input)

        combined_text = " ".join(text_parts)
        return self.evaluate(combined_text)

    def quick_check(self, text: str) -> ActionDecision:
        """Quick check returning only the decision.

        Args:
            text: Input text to check.

        Returns:
            ActionDecision (ALLOW, BLOCK, ASK, SANITIZE).
        """
        result = self.evaluate(text)
        return result.verdict.decision

    @property
    def component_status(self) -> dict[str, bool]:
        """Returns the availability status of each component."""
        return {
            "heuristics": self._heuristics is not None,
            "secrets": self._secrets is not None,
            "ml": self._ml is not None and self._ml.is_available,
            "wolf": self._wolf is not None and self._wolf.is_available,
            "jailbreak": self._jailbreak is not None and bool(self._jailbreak.is_available),
            "vector": self._vector is not None and self._vector.is_available,
            "tier2": self._tier2 is not None and self._tier2.is_available,
        }


# Aliases for compatibility
ADRAegisEngine = VinciADREngine
VinciEngine = VinciADREngine
