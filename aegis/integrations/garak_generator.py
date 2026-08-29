"""Garak generator integration for ADR-AEGIS.

Routes garak attack probes through ADR-AEGIS decision engine instead of a real LLM.
Returns markers [AEGIS_BLOCKED] or [AEGIS_ALLOWED] to evaluate ADR-AEGIS defense capabilities.
"""

from __future__ import annotations

from typing import Any

from garak.attempt import Conversation, Message
from garak.generators.base import Generator

from aegis.core.engine import ADRAegisEngine, EngineConfig, SensitivityPreset
from aegis.core.schema import ActionDecision


class AegisGenerator(Generator):
    """Routes garak attack probes through ADR-AEGIS instead of a real LLM."""

    generator_family_name = "aegis"
    name = "ADRAegis"
    supports_multiple_generations = False

    def __init__(
        self,
        name: str = "",
        config_root: Any = None,
        *,
        engine: ADRAegisEngine | None = None,
        sensitivity: SensitivityPreset = SensitivityPreset.BALANCED,
    ) -> None:
        """Initialize the AegisGenerator.

        Args:
            name: Generator name.
            config_root: Garak config root.
            engine: Optional pre-configured ADRAegisEngine.
            sensitivity: Sensitivity preset to use if creating a new engine.
        """
        if not name:
            name = self.name
        self.name = name
        super().__init__(name=name, config_root=config_root)

        if engine is not None:
            self.engine = engine
        else:
            self.engine = ADRAegisEngine(
                EngineConfig(
                    sensitivity=sensitivity,
                    enable_tier2=False,
                    enable_jailbreak_classifier=False,
                )
            )

    def _call_model(
        self, prompt: Conversation | Any, generations_this_call: int = 1
    ) -> list[Message]:
        """Evaluate the attack prompt through ADR-AEGIS and return a block/allow marker.

        Args:
            prompt: Garak Conversation or prompt object.
            generations_this_call: Number of generations requested.

        Returns:
            List of Message objects containing [AEGIS_BLOCKED] or [AEGIS_ALLOWED].
        """
        if hasattr(prompt, "last_message") and callable(prompt.last_message):
            try:
                msg = prompt.last_message()
                text = msg.text if hasattr(msg, "text") else str(msg)
            except (RuntimeError, ValueError, TypeError, AttributeError):
                text = str(prompt)
        elif hasattr(prompt, "text"):
            text = str(prompt.text)
        else:
            text = str(prompt)

        decision = self.engine.quick_check(text)
        marker = "[AEGIS_BLOCKED]" if decision != ActionDecision.ALLOW else "[AEGIS_ALLOWED]"
        return [Message(marker)] * generations_this_call
