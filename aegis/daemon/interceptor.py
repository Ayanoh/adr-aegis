"""Core daemon interceptor for real-time tool call validation.

The AegisDaemon sits between an AI agent and its tools, intercepting every
tool call and validating it through ADR-AEGIS before allowing execution.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from aegis.core.engine import ADRAegisEngine, EngineConfig, EvaluationResult
from aegis.core.schema import ActionDecision

logger = structlog.get_logger()


class InterceptionDecision(str, Enum):
    """Decision made by the daemon for a tool call."""

    ALLOW = "allow"  # Tool call is safe, proceed
    BLOCK = "block"  # Tool call is dangerous, reject
    MODIFY = "modify"  # Tool call needs sanitization (future)
    ESCALATE = "escalate"  # Needs human approval (maps to ASK)


@dataclass
class InterceptionResult:
    """Result of daemon interception on a tool call.

    Attributes:
        decision: Final decision (ALLOW, BLOCK, MODIFY, ESCALATE).
        tool_name: Name of the intercepted tool.
        tool_input: Original input to the tool.
        sanitized_input: Modified input if MODIFY decision.
        evaluation: Full AEGIS evaluation result.
        latency_ms: Interception processing time.
        reason: Human-readable explanation.
    """

    decision: InterceptionDecision
    tool_name: str
    tool_input: dict[str, Any]
    sanitized_input: dict[str, Any] | None = None
    evaluation: EvaluationResult | None = None
    latency_ms: float = 0.0
    reason: str = ""


@dataclass
class DaemonConfig:
    """Configuration for the AEGIS Daemon.

    Attributes:
        engine_config: Configuration for the underlying AEGIS Engine.
        tool_whitelist: Tools that bypass interception entirely.
        tool_blacklist: Tools that are always blocked.
        escalation_callback: Function called when human approval is needed.
        log_all_calls: Whether to log every tool call (for audit).
        strict_mode: If True, ESCALATE becomes BLOCK (no human in loop).
    """

    engine_config: EngineConfig | None = None
    tool_whitelist: set[str] = field(default_factory=set)
    tool_blacklist: set[str] = field(default_factory=set)
    escalation_callback: Callable[[InterceptionResult], bool] | None = None
    log_all_calls: bool = True
    strict_mode: bool = False


class AegisDaemon:
    """Real-time interception daemon for AI agent tool calls.

    The daemon wraps around tool execution, analyzing each call through
    ADR-AEGIS before allowing it to proceed. It supports:
    - Automatic blocking of dangerous calls
    - Escalation to human for ambiguous cases
    - Whitelisting of trusted tools
    - Blacklisting of forbidden tools
    - Full audit logging

    Usage:
        daemon = AegisDaemon(config)
        result = daemon.intercept("bash", {"command": "rm -rf /"})
        if result.decision == InterceptionDecision.ALLOW:
            execute_tool(result.tool_name, result.tool_input)
    """

    def __init__(self, config: DaemonConfig | None = None) -> None:
        """Initialize the AEGIS Daemon.

        Args:
            config: Daemon configuration. Uses defaults if None.
        """
        self.config = config or DaemonConfig()
        self._engine = ADRAegisEngine(self.config.engine_config)
        self._call_count = 0
        self._block_count = 0
        logger.info(
            "AEGIS Daemon initialized",
            whitelist=list(self.config.tool_whitelist),
            blacklist=list(self.config.tool_blacklist),
            strict_mode=self.config.strict_mode,
        )

    def _serialize_input(self, tool_input: dict[str, Any]) -> str:
        """Convert tool input to text for AEGIS analysis.

        Args:
            tool_input: Dictionary of tool arguments.

        Returns:
            Text representation for security analysis.
        """
        parts: list[str] = []
        for key, value in tool_input.items():
            if isinstance(value, str):
                parts.append(f"{key}: {value}")
            elif isinstance(value, (list, tuple)):
                parts.append(f"{key}: {' '.join(str(v) for v in value)}")
            else:
                parts.append(f"{key}: {value}")
        return "\n".join(parts)

    def intercept(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> InterceptionResult:
        """Intercept and validate a tool call before execution.

        Args:
            tool_name: Name of the tool being called.
            tool_input: Arguments being passed to the tool.

        Returns:
            InterceptionResult with decision and details.
        """
        start_time = time.perf_counter()
        self._call_count += 1

        # Check blacklist first (always block)
        if tool_name in self.config.tool_blacklist:
            self._block_count += 1
            latency = (time.perf_counter() - start_time) * 1000.0
            logger.warning(
                "Tool blocked (blacklist)",
                tool=tool_name,
                latency_ms=latency,
            )
            return InterceptionResult(
                decision=InterceptionDecision.BLOCK,
                tool_name=tool_name,
                tool_input=tool_input,
                latency_ms=latency,
                reason=f"Tool '{tool_name}' is blacklisted",
            )

        # Check whitelist (always allow without analysis)
        if tool_name in self.config.tool_whitelist:
            latency = (time.perf_counter() - start_time) * 1000.0
            if self.config.log_all_calls:
                logger.info(
                    "Tool allowed (whitelist)",
                    tool=tool_name,
                    latency_ms=latency,
                )
            return InterceptionResult(
                decision=InterceptionDecision.ALLOW,
                tool_name=tool_name,
                tool_input=tool_input,
                latency_ms=latency,
                reason=f"Tool '{tool_name}' is whitelisted",
            )

        # Run AEGIS analysis on the tool call
        text_to_analyze = f"Tool: {tool_name}\n{self._serialize_input(tool_input)}"
        evaluation = self._engine.evaluate(text_to_analyze)

        # Map AEGIS decision to daemon decision
        aegis_decision = evaluation.verdict.decision

        if aegis_decision == ActionDecision.BLOCK:
            decision = InterceptionDecision.BLOCK
            self._block_count += 1
        elif aegis_decision == ActionDecision.ASK:
            if self.config.strict_mode:
                decision = InterceptionDecision.BLOCK
                self._block_count += 1
            else:
                decision = InterceptionDecision.ESCALATE
        elif aegis_decision == ActionDecision.SANITIZE:
            decision = InterceptionDecision.MODIFY
        else:
            decision = InterceptionDecision.ALLOW

        latency = (time.perf_counter() - start_time) * 1000.0

        result = InterceptionResult(
            decision=decision,
            tool_name=tool_name,
            tool_input=tool_input,
            evaluation=evaluation,
            latency_ms=latency,
            reason=evaluation.verdict.reason,
        )

        # Handle escalation if callback provided
        if decision == InterceptionDecision.ESCALATE and self.config.escalation_callback:
            approved = self.config.escalation_callback(result)
            if approved:
                result.decision = InterceptionDecision.ALLOW
                result.reason += " [Human approved]"
            else:
                result.decision = InterceptionDecision.BLOCK
                result.reason += " [Human denied]"
                self._block_count += 1

        # Logging
        if self.config.log_all_calls or result.decision != InterceptionDecision.ALLOW:
            log_fn = (
                logger.warning if result.decision == InterceptionDecision.BLOCK else logger.info
            )
            log_fn(
                "Tool intercepted",
                tool=tool_name,
                decision=result.decision.value,
                latency_ms=round(latency, 2),
            )

        return result

    @property
    def stats(self) -> dict[str, int]:
        """Return interception statistics."""
        return {
            "total_calls": self._call_count,
            "blocked_calls": self._block_count,
            "allowed_calls": self._call_count - self._block_count,
        }

    def wrap_tool(
        self,
        tool_fn: Callable[..., Any],
        tool_name: str | None = None,
    ) -> Callable[..., Any]:
        """Wrap a tool function with daemon interception.

        Args:
            tool_fn: The original tool function.
            tool_name: Override name for the tool.

        Returns:
            Wrapped function that intercepts calls.
        """
        name = tool_name or getattr(tool_fn, "__name__", "unnamed_tool")

        def wrapped(**kwargs: Any) -> Any:
            result = self.intercept(name, kwargs)

            if result.decision == InterceptionDecision.ALLOW:
                return tool_fn(**kwargs)
            if result.decision == InterceptionDecision.MODIFY and result.sanitized_input:
                return tool_fn(**result.sanitized_input)

            raise PermissionError(f"AEGIS Daemon blocked tool '{name}': {result.reason}")

        return wrapped
