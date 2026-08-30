"""Cognitive agents (Forensic Analyst and Critic) for Tier 2 Deep reasoning."""

import json
import re

import structlog
from pydantic import ValidationError

from vinci_adr.core.schema import Tier2Assessment, Tier2Input
from vinci_adr.tier2_deep.llm_provider import LLMProvider
from vinci_adr.tier2_deep.prompts import (
    CRITIC_SYSTEM_PROMPT,
    FORENSIC_SYSTEM_PROMPT,
    build_critic_prompt,
    build_forensic_prompt,
)

logger = structlog.get_logger()


class Tier2ParsingError(RuntimeError):
    """Raised when an agent's LLM output cannot be parsed into a Tier2Assessment."""


def _strip_code_fences(raw: str) -> str:
    """Removes Markdown code fences (e.g. ```json ... ```) from raw LLM output.

    Args:
        raw: Raw text from LLM.

    Returns:
        Stripped string suitable for JSON parsing.
    """
    text = raw.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return text


def parse_assessment(raw: str, source_agent: str) -> Tier2Assessment:
    """Parses and validates a raw LLM output into a Tier2Assessment model.

    Args:
        raw: Raw string response produced by LLM.
        source_agent: Name of the agent producing the assessment ("forensic" or "critic").

    Returns:
        Validated Tier2Assessment instance.

    Raises:
        Tier2ParsingError: If parsing or Pydantic validation fails.
    """
    cleaned = _strip_code_fences(raw)
    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            raise TypeError("Expected a JSON object mapping")
        data["source_agent"] = source_agent
        return Tier2Assessment(**data)
    except (json.JSONDecodeError, ValidationError, TypeError, ValueError, KeyError) as e:
        logger.warning(
            "Failed to parse Tier 2 agent assessment",
            source_agent=source_agent,
            error=str(e),
        )
        raise Tier2ParsingError(
            f"Failed to parse {source_agent} assessment into Tier2Assessment: {e}"
        ) from e


class ForensicAgent:
    """Investigates ambiguous flagged actions to determine genuine malice and context."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> None:
        """Initializes the Forensic Analyst agent.

        Args:
            provider: The LLMProvider to use for inference.
            temperature: Sampling temperature (0.0 for deterministic reasoning).
            max_tokens: Maximum tokens in response.
        """
        self.provider = provider
        self.temperature = temperature
        self.max_tokens = max_tokens

    def analyze(self, ctx: Tier2Input) -> Tier2Assessment:
        """Performs initial forensic investigation of the flagged action.

        Args:
            ctx: Context of the action flagged by Tier 1.

        Returns:
            Structured Tier2Assessment from the forensic agent.

        Raises:
            LLMProviderError: If the LLM provider fails.
            Tier2ParsingError: If output cannot be parsed.
        """
        prompt = build_forensic_prompt(ctx)
        raw = self.provider.generate(
            prompt,
            system=FORENSIC_SYSTEM_PROMPT,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            json_mode=True,
        )
        return parse_assessment(raw, source_agent="forensic")


class CriticAgent:
    """Adversarially reviews forensic conclusions to eliminate false positives/negatives."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> None:
        """Initializes the Critic agent.

        Args:
            provider: The LLMProvider to use for inference.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
        """
        self.provider = provider
        self.temperature = temperature
        self.max_tokens = max_tokens

    def review(self, ctx: Tier2Input, forensic: Tier2Assessment) -> Tier2Assessment:
        """Adversarially reviews the Forensic Analyst's findings and issues final adjudication.

        Args:
            ctx: Context of the action under review.
            forensic: Initial assessment from the Forensic agent.

        Returns:
            Structured Tier2Assessment containing the Critic's adjudication.

        Raises:
            LLMProviderError: If the LLM provider fails.
            Tier2ParsingError: If output cannot be parsed.
        """
        prompt = build_critic_prompt(ctx, forensic)
        raw = self.provider.generate(
            prompt,
            system=CRITIC_SYSTEM_PROMPT,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            json_mode=True,
        )
        return parse_assessment(raw, source_agent="critic")
