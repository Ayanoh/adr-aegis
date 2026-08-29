"""Unit tests for AegisMCPMiddleware and JSON-RPC MCP interception."""

import json
from unittest.mock import MagicMock

import pytest

from aegis.daemon.interceptor import (
    DaemonConfig,
    InterceptionDecision,
    InterceptionResult,
)
from aegis.daemon.mcp_interceptor import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_PARSE_ERROR,
    JSONRPC_SECURITY_POLICY_VIOLATION,
    AegisMCPMiddleware,
)


def test_mcp_allows_safe_tool_call() -> None:
    """Safe tools/call request is allowed and forwarded."""
    config = DaemonConfig(tool_whitelist={"calculator"})
    middleware = AegisMCPMiddleware(config=config)

    request = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "calculator",
            "arguments": {"expression": "2 + 2"},
        },
    }

    is_allowed, forwarded = middleware.process_request(request)

    assert is_allowed is True
    assert forwarded == request


def test_mcp_blocks_malicious_tool_call() -> None:
    """Dangerous tools/call request is blocked with JSON-RPC error -32000."""
    config = DaemonConfig(strict_mode=True)
    middleware = AegisMCPMiddleware(config=config)

    request = {
        "jsonrpc": "2.0",
        "id": "req-danger",
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {"command": "rm -rf / --no-preserve-root"},
        },
    }

    is_allowed, error_resp = middleware.process_request(request)

    assert is_allowed is False
    assert isinstance(error_resp, dict)
    assert error_resp["jsonrpc"] == "2.0"
    assert error_resp["id"] == "req-danger"
    assert "error" in error_resp
    assert error_resp["error"]["code"] == JSONRPC_SECURITY_POLICY_VIOLATION
    assert "AEGIS Security Policy Violation" in error_resp["error"]["message"]
    assert error_resp["error"]["data"]["tool"] == "bash"
    assert error_resp["error"]["data"]["decision"] == "block"


def test_mcp_passes_non_tool_calls() -> None:
    """Non-tool requests like initialize, tools/list pass through transparently."""
    middleware = AegisMCPMiddleware()

    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "TestClient", "version": "1.0"},
        },
    }

    is_allowed, forwarded = middleware.process_request(init_request)
    assert is_allowed is True
    assert forwarded == init_request

    list_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    is_allowed2, forwarded2 = middleware.process_request(list_request)
    assert is_allowed2 is True
    assert forwarded2 == list_request


def test_mcp_handles_string_payload() -> None:
    """Raw JSON strings are parsed, evaluated, and serialized back properly."""
    config = DaemonConfig(tool_whitelist={"search"})
    middleware = AegisMCPMiddleware(config=config)

    raw_json = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"query": "Cybersecurity AI papers"},
            },
        }
    )

    is_allowed, out_str = middleware.process_request(raw_json)

    assert is_allowed is True
    assert isinstance(out_str, str)
    parsed = json.loads(out_str)
    assert parsed["id"] == 100
    assert parsed["params"]["name"] == "search"


def test_mcp_blacklist_enforcement() -> None:
    """Blacklisted MCP tools are blocked immediately."""
    config = DaemonConfig(tool_blacklist={"exec_raw_code"})
    middleware = AegisMCPMiddleware(config=config)

    request = {
        "jsonrpc": "2.0",
        "id": "blk-1",
        "method": "tools/call",
        "params": {
            "name": "exec_raw_code",
            "arguments": {"code": "print('hello')"},
        },
    }

    is_allowed, error_resp = middleware.process_request(request)

    assert is_allowed is False
    assert error_resp["error"]["code"] == JSONRPC_SECURITY_POLICY_VIOLATION
    assert "blacklisted" in error_resp["error"]["data"]["reason"].lower()


def test_mcp_whitelist_bypass() -> None:
    """Whitelisted tools bypass heavy scanning."""
    config = DaemonConfig(tool_whitelist={"trusted_read"})
    middleware = AegisMCPMiddleware(config=config)

    request = {
        "jsonrpc": "2.0",
        "id": "wht-1",
        "method": "tools/call",
        "params": {
            "name": "trusted_read",
            "arguments": {"file": "report.pdf"},
        },
    }

    is_allowed, forwarded = middleware.process_request(request)
    assert is_allowed is True
    assert forwarded == request


def test_mcp_wrap_handler() -> None:
    """wrap_handler wraps in-process MCP tool handlers with security."""
    config = DaemonConfig(tool_blacklist={"blocked_handler"})
    middleware = AegisMCPMiddleware(config=config)

    handler_called = False

    def my_handler(tool_name: str, args: dict) -> str:
        nonlocal handler_called
        handler_called = True
        return f"Executed {tool_name} with {args}"

    wrapped = middleware.wrap_handler(my_handler)

    # Safe call executes handler
    res = wrapped("safe_tool", {"param": 123})
    assert handler_called is True
    assert "Executed safe_tool" in res

    # Blacklisted call raises PermissionError
    with pytest.raises(PermissionError) as exc_info:
        wrapped("blocked_handler", {"param": 456})

    assert "AEGIS MCP Interceptor blocked tool" in str(exc_info.value)


def test_mcp_invalid_json_handling() -> None:
    """Malformed JSON string returns standard JSON-RPC parse error code -32700."""
    middleware = AegisMCPMiddleware()

    malformed_json = '{"jsonrpc": "2.0", "method": "tools/call", INVALID_JSON'

    is_allowed, error_resp_str = middleware.process_request(malformed_json)

    assert is_allowed is False
    assert isinstance(error_resp_str, str)
    error_dict = json.loads(error_resp_str)
    assert error_dict["error"]["code"] == JSONRPC_PARSE_ERROR
    assert "Parse error" in error_dict["error"]["message"]


def test_mcp_invalid_params_handling() -> None:
    """tools/call with missing or non-dict params returns error code -32602."""
    middleware = AegisMCPMiddleware()

    bad_request = {
        "jsonrpc": "2.0",
        "id": "bad-p",
        "method": "tools/call",
        "params": "not a dictionary",
    }

    is_allowed, error_resp = middleware.process_request(bad_request)

    assert is_allowed is False
    assert error_resp["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_mcp_sanitized_input_modification() -> None:
    """Sanitized tool arguments are properly updated in modified JSON-RPC request."""
    mock_daemon = MagicMock()
    mock_result = InterceptionResult(
        decision=InterceptionDecision.MODIFY,
        tool_name="file_writer",
        tool_input={"content": "malicious<script>"},
        sanitized_input={"content": "clean_content"},
        reason="Sanitized XSS script payload",
    )
    mock_daemon.intercept.return_value = mock_result

    middleware = AegisMCPMiddleware(daemon=mock_daemon)

    request = {
        "jsonrpc": "2.0",
        "id": "mod-1",
        "method": "tools/call",
        "params": {
            "name": "file_writer",
            "arguments": {"content": "malicious<script>"},
        },
    }

    is_allowed, mod_req = middleware.process_request(request)

    assert is_allowed is True
    assert mod_req["params"]["arguments"] == {"content": "clean_content"}
