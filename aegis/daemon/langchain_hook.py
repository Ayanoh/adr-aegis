"""LangChain integration for AEGIS Daemon.

Provides decorators and wrappers to protect LangChain tools
with real-time AEGIS security interception.

Supports:
- @aegis_tool decorator for individual tools
- AegisToolkit wrapper for tool collections
- AegisToolWrapper for individual tool conversion
- protect_agent_tools() utility function
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any

import structlog

from aegis.daemon.interceptor import (
    AegisDaemon,
    DaemonConfig,
    InterceptionDecision,
)

logger = structlog.get_logger()

# Conditional imports for LangChain (optional dependency)
if TYPE_CHECKING:
    from langchain_core.tools import BaseTool, StructuredTool


def _check_langchain_available() -> bool:
    """Check if LangChain is installed."""
    try:
        import langchain_core  # noqa: F401

        return True
    except ImportError:
        return False


LANGCHAIN_AVAILABLE = _check_langchain_available()


class AegisToolWrapper:
    """Wraps a LangChain tool with AEGIS daemon interception.

    Usage:
        from langchain_community.tools import ShellTool
        shell = ShellTool()
        protected_shell = AegisToolWrapper(shell, daemon).as_tool()
    """

    def __init__(
        self,
        tool: BaseTool | Any,
        daemon: AegisDaemon | None = None,
        config: DaemonConfig | None = None,
    ) -> None:
        """Initialize the wrapper.

        Args:
            tool: The LangChain tool to wrap.
            daemon: Pre-configured daemon instance.
            config: Daemon config (used if daemon not provided).
        """
        self.tool = tool
        self.daemon = daemon or AegisDaemon(config)
        self._tool_name = getattr(tool, "name", getattr(tool.__class__, "__name__", "unnamed_tool"))

    def _invoke(self, tool_input: str | dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """Intercept and run the tool.

        Args:
            tool_input: Input to the tool (string or dict).
            **kwargs: Additional arguments.

        Returns:
            Tool output if allowed.

        Raises:
            PermissionError: If the tool call is blocked.
        """
        if tool_input is None:
            input_dict = dict(kwargs)
            actual_input = kwargs
        elif isinstance(tool_input, str):
            input_dict = {"input": tool_input, **kwargs} if kwargs else {"input": tool_input}
            actual_input = tool_input if not kwargs else {"input": tool_input, **kwargs}
        elif isinstance(tool_input, dict):
            input_dict = dict(tool_input)
            input_dict.update(kwargs)
            actual_input = input_dict
        else:
            input_dict = {"input": str(tool_input), **kwargs}
            actual_input = input_dict

        result = self.daemon.intercept(self._tool_name, input_dict)

        if result.decision == InterceptionDecision.ALLOW:
            if hasattr(self.tool, "invoke"):
                return self.tool.invoke(actual_input, **kwargs)
            if callable(self.tool):
                return (
                    self.tool(**kwargs)
                    if kwargs and not isinstance(tool_input, str)
                    else self.tool(tool_input)
                )
            return None
        if result.decision == InterceptionDecision.ESCALATE:
            logger.warning(
                "Tool call escalated but no callback configured",
                tool=self._tool_name,
            )
            if hasattr(self.tool, "invoke"):
                return self.tool.invoke(actual_input, **kwargs)
            if callable(self.tool):
                return (
                    self.tool(**kwargs)
                    if kwargs and not isinstance(tool_input, str)
                    else self.tool(tool_input)
                )
            return None

        raise PermissionError(f"AEGIS blocked tool '{self._tool_name}': {result.reason}")

    def as_tool(self) -> StructuredTool:
        """Create a new LangChain tool with AEGIS protection.

        Returns:
            A StructuredTool that intercepts calls through AEGIS.
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain is not installed. Install with: pip install langchain-core"
            )

        from langchain_core.tools import StructuredTool

        return StructuredTool.from_function(
            func=self._invoke,
            name=f"aegis_{self._tool_name}",
            description=f"[AEGIS Protected] {getattr(self.tool, 'description', '')}",
        )


def aegis_tool(
    daemon: AegisDaemon | None = None,
    config: DaemonConfig | None = None,
) -> Any:
    """Decorator to protect a LangChain tool function with AEGIS.

    Usage:
        @aegis_tool()
        @tool
        def my_shell_tool(command: str) -> str:
            '''Run a shell command.'''
            return subprocess.run(command, shell=True, capture_output=True).stdout.decode()

    Args:
        daemon: Pre-configured daemon instance.
        config: Daemon config (used if daemon not provided).

    Returns:
        Decorated function with AEGIS protection.
    """
    _daemon = daemon or AegisDaemon(config)

    def decorator(func: Any) -> Any:
        tool_name = getattr(func, "name", getattr(func, "__name__", "unnamed"))

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Build input dict from args/kwargs
            input_dict: dict[str, Any] = dict(kwargs)
            if args:
                input_dict["_positional_args"] = args

            result = _daemon.intercept(tool_name, input_dict)

            if result.decision == InterceptionDecision.ALLOW:
                return func(*args, **kwargs)
            if result.decision == InterceptionDecision.ESCALATE:
                logger.warning(
                    "Tool call escalated, allowing without callback",
                    tool=tool_name,
                )
                return func(*args, **kwargs)

            raise PermissionError(f"AEGIS blocked tool '{tool_name}': {result.reason}")

        return wrapper

    return decorator


class AegisToolkit:
    """Wraps multiple LangChain tools with AEGIS protection.

    Usage:
        from langchain_community.agent_toolkits import FileManagementToolkit
        toolkit = FileManagementToolkit()
        protected_tools = AegisToolkit(toolkit.get_tools()).get_tools()
    """

    def __init__(
        self,
        tools: list[BaseTool | Any],
        daemon: AegisDaemon | None = None,
        config: DaemonConfig | None = None,
    ) -> None:
        """Initialize the toolkit wrapper.

        Args:
            tools: List of LangChain tools to protect.
            daemon: Pre-configured daemon instance.
            config: Daemon config (used if daemon not provided).
        """
        self.tools = tools
        self.daemon = daemon or AegisDaemon(config)

    def get_tools(self) -> list[StructuredTool]:
        """Get protected versions of all tools.

        Returns:
            List of AEGIS-protected tools.
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain is not installed. Install with: pip install langchain-core"
            )

        protected: list[StructuredTool] = []
        for tool in self.tools:
            wrapper = AegisToolWrapper(tool, daemon=self.daemon)
            protected.append(wrapper.as_tool())
        return protected


def protect_agent_tools(
    tools: list[BaseTool | Any],
    daemon: AegisDaemon | None = None,
    config: DaemonConfig | None = None,
) -> list[Any]:
    """Convenience function to protect a list of tools.

    Args:
        tools: LangChain tools to protect.
        daemon: Pre-configured daemon.
        config: Daemon config.

    Returns:
        List of protected tools ready for agent use.
    """
    toolkit = AegisToolkit(tools, daemon=daemon, config=config)
    return toolkit.get_tools()
