"""MCP (Model Context Protocol) JSON-RPC Interceptor for AEGIS Daemon.

Provides real-time security interception for MCP servers and clients,
inspecting all `tools/call` JSON-RPC requests and enforcing ADR-AEGIS policies
before tool execution occurs.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import structlog

from aegis.daemon.interceptor import (
    AegisDaemon,
    DaemonConfig,
    InterceptionDecision,
)

logger = structlog.get_logger()

# Standard JSON-RPC 2.0 error codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_SECURITY_POLICY_VIOLATION = -32000


def create_jsonrpc_error_response(
    request_id: Any,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a compliant JSON-RPC 2.0 error response dictionary.

    Args:
        request_id: Identifier of the initiating request.
        code: JSON-RPC error code integer.
        message: Concise error message.
        data: Optional contextual details regarding the error or security block.

    Returns:
        JSON-RPC 2.0 error payload dictionary.
    """
    error_payload: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        error_payload["data"] = data

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": error_payload,
    }


class AegisMCPMiddleware:
    """JSON-RPC 2.0 Middleware and Proxy for Model Context Protocol (MCP).

    Intercepts JSON-RPC payloads, routes `tools/call` invocations through
    the AEGIS Daemon, and either permits request forwarding or returns
    an immediate JSON-RPC security error.

    Usage:
        mcp_guard = AegisMCPMiddleware(daemon)
        is_allowed, response = mcp_guard.process_request(raw_json_string)
        if not is_allowed:
            send_to_client(response)  # Security violation response
        else:
            forward_to_mcp_server(response)
    """

    def __init__(
        self,
        daemon: AegisDaemon | None = None,
        config: DaemonConfig | None = None,
    ) -> None:
        """Initialize the MCP Middleware.

        Args:
            daemon: Pre-configured AegisDaemon instance.
            config: Optional daemon configuration (used if daemon is None).
        """
        self.daemon = daemon or AegisDaemon(config)
        logger.info("AegisMCPMiddleware initialized")

    def intercept_jsonrpc_dict(self, request: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Intercept and evaluate a parsed JSON-RPC request dictionary.

        Args:
            request: Parsed JSON-RPC 2.0 request dictionary.

        Returns:
            Tuple of (is_allowed: bool, forwarded_or_error_dict).
        """
        if not isinstance(request, dict):
            return False, create_jsonrpc_error_response(
                request_id=None,
                code=JSONRPC_INVALID_REQUEST,
                message="Invalid Request: payload must be a JSON object",
            )

        req_id = request.get("id")
        method = request.get("method")

        # Non-tool calls (initialize, tools/list, resources/list, ping, etc.) pass through
        if method != "tools/call":
            return True, request

        params = request.get("params")
        if not isinstance(params, dict):
            return False, create_jsonrpc_error_response(
                request_id=req_id,
                code=JSONRPC_INVALID_PARAMS,
                message="Invalid params: 'params' must be an object for tools/call",
            )

        tool_name = params.get("name", "unnamed_tool")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {"input": arguments}

        # Intercept tool call with AegisDaemon
        result = self.daemon.intercept(tool_name, arguments)

        if result.decision == InterceptionDecision.ALLOW:
            return True, request

        if result.decision == InterceptionDecision.MODIFY and result.sanitized_input is not None:
            modified_request = copy.deepcopy(request)
            modified_request["params"]["arguments"] = result.sanitized_input
            logger.info(
                "MCP tool call sanitized",
                tool=tool_name,
                latency_ms=result.latency_ms,
            )
            return True, modified_request

        # Decision is BLOCK or unapproved ESCALATE
        logger.warning(
            "MCP tool call blocked by AEGIS",
            tool=tool_name,
            reason=result.reason,
            decision=result.decision.value,
        )
        error_resp = create_jsonrpc_error_response(
            request_id=req_id,
            code=JSONRPC_SECURITY_POLICY_VIOLATION,
            message=f"AEGIS Security Policy Violation: {result.reason}",
            data={
                "tool": tool_name,
                "decision": result.decision.value,
                "reason": result.reason,
                "latency_ms": round(result.latency_ms, 2),
            },
        )
        return False, error_resp

    def process_request(
        self, request_payload: str | dict[str, Any]
    ) -> tuple[bool, str | dict[str, Any]]:
        """Process an incoming raw JSON string or dictionary request.

        Args:
            request_payload: Raw JSON string or dictionary representing JSON-RPC request.

        Returns:
            Tuple of (is_allowed: bool, forwarded_or_error_payload).
            If input was a string, output is formatted as a JSON string.
        """
        is_string_input = isinstance(request_payload, str)

        if is_string_input:
            try:
                parsed_request = json.loads(request_payload)
            except json.JSONDecodeError as err:
                error_dict = create_jsonrpc_error_response(
                    request_id=None,
                    code=JSONRPC_PARSE_ERROR,
                    message=f"Parse error: {err}",
                )
                return False, json.dumps(error_dict)
        else:
            parsed_request = request_payload

        is_allowed, result_dict = self.intercept_jsonrpc_dict(parsed_request)

        if is_string_input:
            return is_allowed, json.dumps(result_dict)
        return is_allowed, result_dict

    def wrap_handler(
        self,
        handler_fn: Callable[[str, dict[str, Any]], Any],
    ) -> Callable[[str, dict[str, Any]], Any]:
        """Wrap an in-process MCP tool dispatch handler.

        Args:
            handler_fn: Function with signature (tool_name, arguments) -> result.

        Returns:
            Protected handler function checking AEGIS before execution.
        """

        def protected_handler(tool_name: str, arguments: dict[str, Any]) -> Any:
            result = self.daemon.intercept(tool_name, arguments)

            if result.decision == InterceptionDecision.ALLOW:
                return handler_fn(tool_name, arguments)
            if (
                result.decision == InterceptionDecision.MODIFY
                and result.sanitized_input is not None
            ):
                return handler_fn(tool_name, result.sanitized_input)

            raise PermissionError(
                f"AEGIS MCP Interceptor blocked tool '{tool_name}': {result.reason}"
            )

        return protected_handler
