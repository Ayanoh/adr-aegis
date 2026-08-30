"""Imports and converts secret detection patterns from Gitleaks TOML rules.

Downloads the official Gitleaks configuration rules (or reads from a local file),
validates regex compatibility with Python's `re` engine, maps severities, and generates
`vinci_adr/tier1_fast/gitleaks_patterns.py` for integration with `SecretsScanner`.

Source: https://github.com/gitleaks/gitleaks
License: MIT
"""

import argparse
import re
import sys
import tomllib
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import structlog

logger = structlog.get_logger()

DEFAULT_GITLEAKS_URL = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
)
DEFAULT_OUTPUT_PATH = Path("vinci_adr/tier1_fast/gitleaks_patterns.py")

# Existing pattern IDs in vinci_adr/tier1_fast/secrets_scanner.py to prevent duplicates
EXISTING_PATTERN_IDS: set[str] = {
    "aws-access-token",  # Covered by aws_access_key_id
    "github-pat",
    "github-oauth",
    "github-app",
    "github-refresh",
    "openai-api-key",
    "anthropic-api-key",
    "google-api-key",
    "slack-token",
    "slack-webhook",
    "generic-api-key",
}


def parse_args() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Import Gitleaks secret detection rules into Vinci ADR."
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_GITLEAKS_URL,
        help=f"URL to gitleaks.toml (default: {DEFAULT_GITLEAKS_URL})",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Optional local path to gitleaks.toml (skips download).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output Python file path (default: {DEFAULT_OUTPUT_PATH})",
    )
    return parser.parse_args()


def load_gitleaks_toml(url: str, input_path: Path | None = None) -> dict:
    """Loads and parses the Gitleaks TOML configuration.

    Args:
        url: Remote URL to fetch.
        input_path: Optional local file path.

    Returns:
        Parsed TOML dictionary.

    Raises:
        RuntimeError: If fetching or parsing fails.
    """
    if input_path and input_path.exists():
        logger.info("Reading Gitleaks TOML from local file", path=str(input_path))
        try:
            content = input_path.read_bytes()
            return tomllib.loads(content.decode("utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise RuntimeError(f"Failed to read local Gitleaks TOML: {e}") from e

    logger.info("Fetching Gitleaks TOML from URL", url=url)
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Vinci ADR-Importer/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            content = resp.read()
            return tomllib.loads(content.decode("utf-8"))
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        tomllib.TOMLDecodeError,
    ) as e:
        raise RuntimeError(f"Failed to fetch or parse Gitleaks TOML: {e}") from e


def map_severity_enum_name(rule_id: str, description: str, keywords: list[str]) -> str:
    """Determines threat severity from Gitleaks rule metadata.

    Args:
        rule_id: Unique rule identifier.
        description: Rule description.
        keywords: Associated keyword strings.

    Returns:
        ThreatSeverity enum identifier string.
    """
    haystack = f"{rule_id} {description} {' '.join(keywords)}".lower()

    # Contient "aws", "gcp", "azure", "private.key", "database" → CRITICAL
    critical_terms = [
        "aws",
        "gcp",
        "azure",
        "private.key",
        "private_key",
        "database",
        "postgres",
        "mysql",
        "mongodb",
    ]
    if any(term in haystack for term in critical_terms):
        return "ThreatSeverity.CRITICAL"

    # Contient "api.key", "token", "secret", "password" → HIGH
    high_terms = [
        "api.key",
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "jwt",
        "stripe",
        "discord",
    ]
    if any(term in haystack for term in high_terms):
        return "ThreatSeverity.HIGH"

    # Autres → MEDIUM
    return "ThreatSeverity.MEDIUM"


def import_patterns(
    rules: list[dict],
) -> tuple[list[tuple[str, str, float, str]], int, int, int]:
    """Filters, validates, and transforms Gitleaks rules into Python pattern specifications.

    Args:
        rules: List of raw rule dicts from Gitleaks TOML.

    Returns:
        Tuple of (valid_patterns, read_count, written_count, skipped_count).
    """
    valid_patterns: list[tuple[str, str, float, str]] = []
    seen_ids: set[str] = set()

    read_count = len(rules)
    written_count = 0
    skipped_count = 0

    for rule in rules:
        rule_id = rule.get("id", "").strip()
        if not rule_id:
            skipped_count += 1
            continue

        if rule_id in EXISTING_PATTERN_IDS or rule_id in seen_ids:
            logger.debug("Skipping existing/duplicate pattern ID", rule_id=rule_id)
            skipped_count += 1
            continue

        regex_str = rule.get("regex", "")
        if not regex_str:
            skipped_count += 1
            continue

        # Normalize common POSIX classes from Go regexes for Python re compatibility
        regex_str = (
            regex_str.replace("[[:alnum:]]", "[a-zA-Z0-9]")
            .replace("[[:alpha:]]", "[a-zA-Z]")
            .replace("[[:digit:]]", "[0-9]")
            .replace("[[:space:]]", r"\s")
        )

        # Validate with Python re engine
        try:
            re.compile(regex_str)
        except re.error as e:
            logger.debug(
                "Skipping regex incompatible with Python re",
                rule_id=rule_id,
                error=str(e),
            )
            skipped_count += 1
            continue

        entropy = float(rule.get("entropy", 3.0))
        if entropy <= 0.0:
            entropy = 3.0

        description = rule.get("description", "")
        keywords = rule.get("keywords", [])
        severity_enum = map_severity_enum_name(rule_id, description, keywords)

        valid_patterns.append((rule_id, regex_str, entropy, severity_enum))
        seen_ids.add(rule_id)
        written_count += 1

    return valid_patterns, read_count, written_count, skipped_count


def generate_python_file(patterns: list[tuple[str, str, float, str]], output_path: Path) -> None:
    """Writes the compiled pattern file in Python format.

    Args:
        patterns: List of valid pattern tuples.
        output_path: Target path to write.
    """
    now_utc = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")

    lines = [
        '"""Gitleaks patterns - auto-generated, do not edit manually.',
        "",
        "Source: https://github.com/gitleaks/gitleaks",
        "License: MIT",
        f"Generated: {now_utc}",
        '"""',
        "",
        "import re",
        "",
        "from vinci_adr.core.schema import ThreatSeverity",
        "",
        "# (name, compiled_pattern, min_entropy, severity)",
        "GITLEAKS_PATTERNS: list[tuple[str, re.Pattern[str], float, ThreatSeverity]] = [",
    ]

    for rule_id, regex_str, entropy, severity in patterns:
        repr_id = repr(rule_id)
        repr_regex = repr(regex_str)
        lines.append(f"    ({repr_id}, re.compile({repr_regex}), {entropy:.1f}, {severity}),")

    lines.append("]")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Generated Gitleaks patterns file", path=str(output_path), count=len(patterns))


def main() -> None:
    """Main execution function."""
    args = parse_args()

    try:
        data = load_gitleaks_toml(args.url, args.input)
    except RuntimeError as e:
        print(f"[!] Error loading Gitleaks TOML: {e}", file=sys.stderr)
        sys.exit(1)

    rules = data.get("rules", [])
    patterns, read_count, written_count, skipped_count = import_patterns(rules)

    generate_python_file(patterns, args.output)

    print("=" * 60)
    print(" Gitleaks Patterns Import Summary")
    print("=" * 60)
    print(f" Patterns lus      : {read_count}")
    print(f" Patterns écrits   : {written_count}")
    print(f" Patterns skippés  : {skipped_count}")
    print(f" Fichier généré    : {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
