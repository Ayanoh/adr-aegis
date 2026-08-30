"""Orchestrator for Tier 2 Deep dual-agent reasoning."""

import time
from dataclasses import dataclass

import structlog

from vinci_adr.core.schema import ActionDecision, Tier2Assessment, Tier2Input, TierSource, Verdict
from vinci_adr.tier2_deep.agents import CriticAgent, ForensicAgent, Tier2ParsingError
from vinci_adr.tier2_deep.llm_provider import LLMProvider, LLMProviderError

logger = structlog.get_logger()


@dataclass
class Tier2Result:
    """Outcome of a Tier 2 dual-agent evaluation.

    Attributes:
        verdict: Final synthesized verdict (TIER2_COGNITIVE).
        forensic: Forensic assessment (None if the reasoner failed/degraded).
        critic: Critic assessment (None if the reasoner failed/degraded).
    """

    verdict: Verdict
    forensic: Tier2Assessment | None = None
    critic: Tier2Assessment | None = None


class Tier2Engine:
    """Orchestrates the Forensic Analyst and Critic dual-agent reasoning chain."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        temperature: float = 0.0,
    ) -> None:
        """Initializes the Tier 2 reasoning engine.

        Args:
            provider: The LLMProvider used by cognitive agents.
            temperature: Sampling temperature for agent inferences.
        """
        self._provider = provider
        self.forensic = ForensicAgent(provider, temperature=temperature)
        self.critic = CriticAgent(provider, temperature=temperature)

    @property
    def is_available(self) -> bool:
        """Returns True if the underlying LLM provider is available."""
        return self._provider.is_available

    def evaluate(self, ctx: Tier2Input) -> Tier2Result:
        """Executes the dual-agent Forensic -> Critic evaluation pipeline.

        Args:
            ctx: Context of the flagged action.

        Returns:
            Tier2Result containing the final Verdict and individual assessments.
        """
        if not self.is_available:
            return Tier2Result(verdict=self._degraded_verdict(ctx, "Tier 2 provider unavailable"))

        start = time.perf_counter()
        try:
            forensic_assessment = self.forensic.analyze(ctx)
            critic_assessment = self.critic.review(ctx, forensic_assessment)
        except (LLMProviderError, Tier2ParsingError) as e:
            logger.warning("Tier 2 evaluation degraded", error=str(e))
            return Tier2Result(verdict=self._degraded_verdict(ctx, f"Tier 2 failed: {e}"))

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        verdict = self._synthesize(ctx, forensic_assessment, critic_assessment, elapsed_ms)
        return Tier2Result(
            verdict=verdict,
            forensic=forensic_assessment,
            critic=critic_assessment,
        )

    def _synthesize(
        self,
        ctx: Tier2Input,
        forensic: Tier2Assessment,
        critic: Tier2Assessment,
        elapsed_ms: float,
    ) -> Verdict:
        """Synthesizes Forensic and Critic assessments into a final cognitive Verdict.

        Applies defense-in-depth safety guardrail:
        Never silently clear a high-confidence Forensic threat (confidence >= 0.90) to ALLOW.

        Args:
            ctx: Original Tier2Input.
            forensic: Forensic Analyst assessment.
            critic: Critic assessment.
            elapsed_ms: Execution duration in ms.

        Returns:
            Synthesized Verdict.
        """
        decision = critic.recommended_decision
        confidence = critic.confidence

        # Defense-in-depth: if forensic found malice with very high confidence (>=0.90),
        # require human confirmation (ASK) instead of unilateral silent ALLOW.
        if (
            forensic.is_malicious
            and forensic.confidence >= 0.90
            and decision == ActionDecision.ALLOW
        ):
            decision = ActionDecision.ASK

        reason = f"Tier2 dual-agent — Forensic: {forensic.rationale} || Critic: {critic.rationale}"

        return Verdict(
            decision=decision,
            confidence=confidence,
            tier_source=TierSource.TIER2_COGNITIVE,
            threats=ctx.threats,
            reason=reason,
            latency_ms=elapsed_ms,
        )

    def _degraded_verdict(self, ctx: Tier2Input, reason: str) -> Verdict:
        """Produces a fail-safe degraded verdict requiring human review (ASK).

        Args:
            ctx: Original Tier2Input context.
            reason: Degradation explanation.

        Returns:
            Safe fallback Verdict.
        """
        return Verdict(
            decision=ActionDecision.ASK,
            confidence=0.50,
            tier_source=TierSource.TIER2_COGNITIVE,
            threats=ctx.threats,
            reason=f"Tier 2 degraded: {reason}",
            latency_ms=0.0,
        )
