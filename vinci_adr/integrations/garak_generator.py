"""Garak generator integration for Vinci ADR.

Routes garak attack probes through Vinci ADR decision engine instead of a real LLM.
Returns markers [VINCI_BLOCKED] or [VINCI_ALLOWED] to evaluate Vinci ADR defense capabilities.
"""

from __future__ import annotations

from typing import Any

from garak.attempt import Conversation, Message
from garak.generators.base import Generator

from vinci_adr.core.engine import VinciADREngine, EngineConfig, SensitivityPreset
from vinci_adr.core.schema import ActionDecision


class VinciGenerator(Generator):
    """Routes garak attack probes through Vinci ADR instead of a real LLM."""

    generator_family_name = "vinci_adr"
    name = "VinciADR"
    supports_multiple_generations = False

    def __init__(
        self,
        name: str = "",
        config_root: Any = None,
        *,
        engine: VinciADREngine | None = None,
        sensitivity: SensitivityPreset = SensitivityPreset.BALANCED,
    ) -> None:
        """Initialize the VinciGenerator.

        Args:
            name: Generator name.
            config_root: Garak config root.
            engine: Optional pre-configured VinciADREngine.
            sensitivity: Sensitivity preset to use if creating a new engine.
        """
        if not name:
            name = self.name
        self.name = name
        super().__init__(name=name, config_root=config_root)

        if engine is not None:
            self.engine = engine
        else:
            self.engine = VinciADREngine(
                EngineConfig(
                    sensitivity=sensitivity,
                    enable_tier2=False,
                    enable_jailbreak_classifier=False,
                )
            )

    def _call_model(
        self, prompt: Conversation | Any, generations_this_call: int = 1
    ) -> list[Message]:
        """Evaluate the attack prompt through Vinci ADR and return a block/allow marker.

        Args:
            prompt: Garak Conversation or prompt object.
            generations_this_call: Number of generations requested.

        Returns:
            List of Message objects containing [VINCI_BLOCKED] or [VINCI_ALLOWED].
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
        marker = "[VINCI_BLOCKED]" if decision != ActionDecision.ALLOW else "[VINCI_ALLOWED]"
        return [Message(marker)] * generations_this_call


# Compatibility alias
AegisGenerator = VinciGenerator
