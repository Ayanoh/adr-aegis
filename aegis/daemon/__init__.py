"""AEGIS Daemon — Real-time action interception for AI agents."""

from aegis.daemon.interceptor import (
    AegisDaemon,
    DaemonConfig,
    InterceptionDecision,
    InterceptionResult,
)
from aegis.daemon.langchain_hook import (
    LANGCHAIN_AVAILABLE,
    AegisToolkit,
    AegisToolWrapper,
    aegis_tool,
    protect_agent_tools,
)
from aegis.daemon.mcp_interceptor import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_PARSE_ERROR,
    JSONRPC_SECURITY_POLICY_VIOLATION,
    AegisMCPMiddleware,
    create_jsonrpc_error_response,
)

__all__ = [
    "JSONRPC_INVALID_PARAMS",
    "JSONRPC_INVALID_REQUEST",
    "JSONRPC_PARSE_ERROR",
    "JSONRPC_SECURITY_POLICY_VIOLATION",
    "LANGCHAIN_AVAILABLE",
    "AegisDaemon",
    "AegisMCPMiddleware",
    "AegisToolWrapper",
    "AegisToolkit",
    "DaemonConfig",
    "InterceptionDecision",
    "InterceptionResult",
    "aegis_tool",
    "create_jsonrpc_error_response",
    "protect_agent_tools",
]
