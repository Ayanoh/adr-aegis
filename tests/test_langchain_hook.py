"""Unit tests for LangChain integration."""

from unittest.mock import MagicMock

import pytest

from aegis.daemon.interceptor import DaemonConfig

# Skip all tests if LangChain not installed
langchain_available = False
try:
    import langchain_core  # noqa: F401

    langchain_available = True
except ImportError:
    pass

pytestmark = pytest.mark.skipif(not langchain_available, reason="LangChain not installed")


def test_aegis_tool_wrapper_allows_safe_input() -> None:
    """AegisToolWrapper allows safe tool inputs."""
    from aegis.daemon.langchain_hook import AegisToolWrapper

    mock_tool = MagicMock()
    mock_tool.name = "read_file"
    mock_tool.description = "Read a file"
    mock_tool.invoke.return_value = "file contents"

    wrapper = AegisToolWrapper(mock_tool)
    result = wrapper._invoke({"path": "/home/user/readme.txt"})

    assert result == "file contents"
    mock_tool.invoke.assert_called_once()


def test_aegis_tool_wrapper_blocks_malicious_input() -> None:
    """AegisToolWrapper blocks dangerous tool inputs."""
    from aegis.daemon.langchain_hook import AegisToolWrapper

    mock_tool = MagicMock()
    mock_tool.name = "shell"
    mock_tool.description = "Run shell command"

    config = DaemonConfig(strict_mode=True)
    wrapper = AegisToolWrapper(mock_tool, config=config)

    with pytest.raises(PermissionError):
        wrapper._invoke({"command": "rm -rf / --no-preserve-root"})


def test_aegis_tool_wrapper_blacklist() -> None:
    """AegisToolWrapper respects blacklist."""
    from aegis.daemon.langchain_hook import AegisToolWrapper

    mock_tool = MagicMock()
    mock_tool.name = "forbidden_tool"

    config = DaemonConfig(tool_blacklist={"forbidden_tool"})
    wrapper = AegisToolWrapper(mock_tool, config=config)

    with pytest.raises(PermissionError):
        wrapper._invoke({"any": "input"})


def test_aegis_toolkit_wraps_multiple_tools() -> None:
    """AegisToolkit wraps all tools in a list."""
    from aegis.daemon.langchain_hook import AegisToolkit

    mock_tool1 = MagicMock()
    mock_tool1.name = "tool1"
    mock_tool1.description = "First tool"

    mock_tool2 = MagicMock()
    mock_tool2.name = "tool2"
    mock_tool2.description = "Second tool"

    toolkit = AegisToolkit([mock_tool1, mock_tool2])
    protected = toolkit.get_tools()

    assert len(protected) == 2
    assert all("aegis_" in t.name for t in protected)


def test_aegis_tool_decorator() -> None:
    """@aegis_tool decorator protects functions."""
    from aegis.daemon.langchain_hook import aegis_tool

    @aegis_tool()
    def safe_function(x: int) -> int:
        return x * 2

    # Should work for safe input
    result = safe_function(x=5)
    assert result == 10


def test_protect_agent_tools() -> None:
    """protect_agent_tools convenience function works."""
    from aegis.daemon.langchain_hook import protect_agent_tools

    mock_tool = MagicMock()
    mock_tool.name = "my_tool"
    mock_tool.description = "My tool"

    protected = protect_agent_tools([mock_tool])

    assert len(protected) == 1


def test_langchain_available_flag() -> None:
    """LANGCHAIN_AVAILABLE flag is set correctly."""
    from aegis.daemon.langchain_hook import LANGCHAIN_AVAILABLE

    assert LANGCHAIN_AVAILABLE is True
