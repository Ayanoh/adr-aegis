"""Imports and converts SigmaHQ behavioral detection rules into ADR-AEGIS ThreatRules.

Focuses specifically on high-value text and command-level threat detection categories:
- Windows Process Creation (Command Line / LOLBins)
- Linux Process Creation (Shell attacks / Exfiltration)
- PowerShell Script and Module Execution
- Network / DNS Exfiltration

Source: https://github.com/SigmaHQ/sigma
License: Detection Rule License (DRL) / Apache 2.0
"""

import argparse
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import ValidationError

from aegis.core.rules import ThreatRule
from aegis.core.schema import ActionDecision, ThreatSeverity

logger = structlog.get_logger()

DEFAULT_SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git"
DEFAULT_SIGMA_DIR = Path("/tmp/sigma-rules")
DEFAULT_OUTPUT_DIR = Path("rules/sigma")

# Target categories mapped to output filename, category name, and ID prefix
CATEGORY_CONFIGS: dict[str, dict[str, str]] = {
    "rules/windows/process_creation": {
        "file": "windows_process_creation.yaml",
        "category": "windows_command",
        "prefix": "SIG-WIN-CMD",
    },
    "rules/linux/process_creation": {
        "file": "linux_process_creation.yaml",
        "category": "linux_command",
        "prefix": "SIG-LNX-CMD",
    },
    "rules/windows/powershell": {
        "file": "powershell.yaml",
        "category": "powershell_execution",
        "prefix": "SIG-PS-EXEC",
    },
    "rules/network": {
        "file": "network.yaml",
        "category": "network_exfiltration",
        "prefix": "SIG-NET-EXFIL",
    },
}

SEVERITY_ACTION_MAP: dict[str, tuple[ThreatSeverity, ActionDecision]] = {
    "critical": (ThreatSeverity.CRITICAL, ActionDecision.BLOCK),
    "high": (ThreatSeverity.HIGH, ActionDecision.BLOCK),
    "medium": (ThreatSeverity.MEDIUM, ActionDecision.ASK),
    "low": (ThreatSeverity.LOW, ActionDecision.ALLOW),
    "informational": (ThreatSeverity.INFO, ActionDecision.ALLOW),
    "info": (ThreatSeverity.INFO, ActionDecision.ALLOW),
}


def parse_args() -> argparse.Namespace:
    """Parses CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Import Sigma detection rules into ADR-AEGIS format."
    )
    parser.add_argument(
        "--sigma-dir",
        type=Path,
        default=DEFAULT_SIGMA_DIR,
        help=f"Path to cloned Sigma repository (default: {DEFAULT_SIGMA_DIR})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for ADR-AEGIS rules (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--repo-url",
        default=DEFAULT_SIGMA_REPO,
        help=f"Git repository URL to clone if missing (default: {DEFAULT_SIGMA_REPO})",
    )
    return parser.parse_args()


def ensure_sigma_repository(sigma_dir: Path, repo_url: str) -> None:
    """Ensures the Sigma repository exists locally, cloning shallowly if needed.

    Args:
        sigma_dir: Target directory for the Sigma clone.
        repo_url: Git clone URL.
    """
    if sigma_dir.exists() and any(sigma_dir.iterdir()):
        logger.info("Using existing Sigma directory", path=str(sigma_dir))
        return

    logger.info("Cloning Sigma repository shallowly", url=repo_url, path=str(sigma_dir))
    sigma_dir.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", repo_url, str(sigma_dir)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("Successfully cloned Sigma repository")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.error("Failed to clone Sigma repository", error=str(e))
        raise RuntimeError(f"Could not clone Sigma repository from {repo_url}: {e}") from e


def wildcard_to_regex(val: str, is_windash: bool = False) -> str:
    """Converts a Sigma glob/wildcard expression into a regular expression.

    Args:
        val: Input glob string.
        is_windash: If True, treats leading dash as [-/] for Windows CLI compatibility.

    Returns:
        Converted regex string.
    """
    val = val.strip()
    if not val:
        return ""
    if is_windash and val.startswith("-"):
        val = "[-/]" + val[1:]

    parts = []
    for token in re.split(r"(\*|\?)", val):
        if token == "*":
            parts.append(".*")
        elif token == "?":
            parts.append(".")
        else:
            parts.append(re.escape(token))
    return "".join(parts)


COMMON_WORDS: set[str] = {
    "dir",
    "echo",
    "copy",
    "type",
    "cat",
    "ls",
    "set",
    "cd",
    "sh",
    "bash",
    "dash",
    "ksh",
    "zsh",
    "csh",
    "tcsh",
    "fish",
    "find",
    "curl",
    "wget",
    "base64",
    "certutil",
    "cmd",
    "powershell",
    "pwsh",
    "whoami",
    "id",
    "hostname",
    "hostname.exe",
    "net",
    "net.exe",
    "route",
    "sc",
    "ping",
    "tasklist",
    "attrib",
    "reg",
    "chcp",
    "systeminfo",
    "quser",
    "wmic",
    "tar",
    "gzip",
    "unzip",
    "sudo",
    "grep",
    "awk",
    "sed",
    "head",
    "tail",
    "less",
    "true",
    "false",
    "none",
    "null",
    "test",
    "admin",
    "user",
    "help",
    "info",
    "status",
    "start",
    "stop",
    "restart",
    "query",
    "list",
    "get",
    "add",
    "del",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "java",
    "php",
    "docker",
    "git",
    "env",
    "xargs",
    "eval",
    "install",
    "update",
    "build",
    "make",
}


def _is_generic_token(token: str) -> bool:
    """Returns True if a token represents only a generic common utility name."""
    clean = re.sub(r"[^a-zA-Z0-9_-]", "", token).lower()
    if clean in COMMON_WORDS:
        return True
    if token.startswith(("/bin/", "/usr/bin/", "/usr/local/bin/")):
        base = token.split("/")[-1].lower()
        return base in COMMON_WORDS
    return False


def _extract_clause_patterns(clause: Any) -> list[str]:
    """Extracts candidate patterns from a single selection clause."""
    patterns: list[str] = []
    if isinstance(clause, list):
        for item in clause:
            patterns.extend(_extract_clause_patterns(item))
    elif isinstance(clause, dict):
        field_lookaheads: list[str] = []
        for fkey, fval in clause.items():
            fkey_lower = fkey.lower()
            is_windash = "windash" in fkey_lower

            # Skip SIEM-only kernel / parent fields that cannot be matched in agent command text
            if any(
                k in fkey_lower
                for k in (
                    "parentimage",
                    "parentcommandline",
                    "hashes",
                    "user",
                    "integritylevel",
                    "eventid",
                    "calltrace",
                    "processid",
                    "threadid",
                )
            ):
                continue

            if any(
                k in fkey_lower
                for k in (
                    "commandline",
                    "scriptblocktext",
                    "keywords",
                    "queryname",
                    "targetfilename",
                    "image",
                    "originalfilename",
                )
            ):
                if isinstance(fval, list):
                    if "all" in fkey_lower:
                        parts = [
                            f"(?=.*{wildcard_to_regex(str(v), is_windash)})"
                            for v in fval
                            if str(v).strip()
                        ]
                        if parts:
                            field_lookaheads.append("".join(parts))
                    else:
                        alts = [
                            wildcard_to_regex(str(x), is_windash)
                            for x in fval
                            if str(x).strip()
                            and len(str(x).strip()) >= 3
                            and not _is_generic_token(str(x).strip())
                        ]
                        if alts:
                            bounded_alts = [
                                rf"\b{a}\b" if re.match(r"^[a-zA-Z0-9_-]+$", a) else a for a in alts
                            ]
                            if len(bounded_alts) == 1:
                                field_lookaheads.append(bounded_alts[0])
                            else:
                                field_lookaheads.append("(?:" + "|".join(bounded_alts) + ")")
                elif isinstance(fval, (str, int, float)):
                    s = str(fval).strip()
                    if s and len(s) >= 4 and not _is_generic_token(s):
                        reg = wildcard_to_regex(s, is_windash)
                        if re.match(r"^[a-zA-Z0-9_-]+$", reg):
                            reg = rf"\b{reg}\b"
                        field_lookaheads.append(reg)

        if len(field_lookaheads) >= 2:
            lookaheads = [f"(?=.*{f})" if not f.startswith("(?=") else f for f in field_lookaheads]
            patterns.append("".join(lookaheads) + ".*")
        elif len(field_lookaheads) == 1:
            p = field_lookaheads[0]
            if len(p.strip()) >= 4 and not _is_generic_token(p):
                patterns.append(p)

    elif isinstance(clause, (str, int, float)):
        s = str(clause).strip()
        if s and len(s) >= 4 and not _is_generic_token(s):
            reg = wildcard_to_regex(s)
            if re.match(r"^[a-zA-Z0-9_-]+$", reg):
                reg = rf"\b{reg}\b"
            patterns.append(reg)

    return patterns


def extract_patterns_from_detection(detection: dict[str, Any]) -> list[str]:
    """Extracts valid textual command/payload regex patterns from a Sigma detection definition.

    Args:
        detection: Raw detection block from Sigma rule.

    Returns:
        List of valid compiled regex strings.
    """
    if not isinstance(detection, dict):
        return []

    condition = str(detection.get("condition", "")).lower()

    # If condition is 'all of selection*' or 'all of them', combine blocks with lookaheads
    if "all of" in condition:
        block_clauses: list[str] = []
        for key, val in detection.items():
            if key in ("condition", "timeframe"):
                continue
            clause_pats = _extract_clause_patterns(val)
            if clause_pats:
                valid_clause_pats = [p for p in clause_pats if p]
                if valid_clause_pats:
                    if len(valid_clause_pats) == 1:
                        block_clauses.append(valid_clause_pats[0])
                    else:
                        block_clauses.append("(?:" + "|".join(valid_clause_pats) + ")")

        if len(block_clauses) >= 2:
            lookaheads = [f"(?=.*{b})" if not b.startswith("(?=") else b for b in block_clauses]
            combined = "".join(lookaheads) + ".*"
            try:
                re.compile(combined, re.IGNORECASE)
                return [combined]
            except re.error:
                pass

    # 1 of selection* or single block search
    raw_patterns: list[str] = []
    for key, val in detection.items():
        if key in ("condition", "timeframe"):
            continue
        pats = _extract_clause_patterns(val)
        raw_patterns.extend(pats)

    valid_patterns: list[str] = []
    seen: set[str] = set()
    for p in raw_patterns:
        if p not in seen:
            try:
                re.compile(p, re.IGNORECASE)
                valid_patterns.append(p)
                seen.add(p)
            except re.error:
                pass

    return valid_patterns


def process_sigma_rule(
    raw_data: dict[str, Any],
    rule_id: str,
    category: str,
) -> ThreatRule | None:
    """Converts a raw Sigma YAML dict into a validated ThreatRule.

    Args:
        raw_data: Parsed Sigma YAML dictionary.
        rule_id: Formatted unique ID for ADR-AEGIS.
        category: Assigned category string.

    Returns:
        ThreatRule instance if valid, None otherwise.
    """
    title = raw_data.get("title", "").strip()
    if not title:
        return None

    detection = raw_data.get("detection", {})
    patterns = extract_patterns_from_detection(detection)
    if not patterns:
        return None

    level = str(raw_data.get("level", "medium")).lower()
    severity, action = SEVERITY_ACTION_MAP.get(level, (ThreatSeverity.MEDIUM, ActionDecision.ASK))

    tags = [str(t).strip() for t in raw_data.get("tags", []) if str(t).strip()]
    if "sigma" not in tags:
        tags.insert(0, "sigma")

    # Find MITRE ATT&CK technique if present
    mitre_id: str | None = None
    for t in tags:
        if t.startswith("attack.t"):
            mitre_id = t
            break

    sigma_uuid = raw_data.get("id", "")
    description = raw_data.get("description", title)
    if sigma_uuid:
        description = f"{description} [source: Sigma {sigma_uuid}]"

    try:
        rule = ThreatRule(
            id=rule_id,
            name=title,
            description=description,
            category=category,
            patterns=patterns[:10],  # Cap per rule to keep matching fast
            severity=severity,
            action=action,
            mitre_atlas_id=mitre_id,
            enabled=True,
            tags=tags,
        )
        return rule
    except (ValidationError, ValueError, TypeError) as e:
        logger.debug("Failed to validate ThreatRule", rule_id=rule_id, error=str(e))
        return None


def import_sigma_category(
    sigma_dir: Path,
    rel_subdir: str,
    cat_config: dict[str, str],
    global_seen_ids: set[str],
) -> tuple[list[dict[str, Any]], int, int, int]:
    """Imports rules for a specific category directory.

    Args:
        sigma_dir: Base Sigma repository path.
        rel_subdir: Relative subdirectory to scan.
        cat_config: Configuration dictionary for the category.
        global_seen_ids: Set of IDs across all categories to prevent collisions.

    Returns:
        Tuple of (rule_dicts, read_count, converted_count, skipped_count).
    """
    target_path = sigma_dir / rel_subdir
    if not target_path.exists():
        logger.warning("Target directory does not exist", path=str(target_path))
        return [], 0, 0, 0

    read_count = 0
    converted_rules: list[dict[str, Any]] = []
    skipped_count = 0
    seq = 1

    prefix = cat_config["prefix"]
    category = cat_config["category"]

    for root, _, files in os.walk(target_path):
        for fname in sorted(files):
            if not fname.endswith((".yml", ".yaml")):
                continue

            read_count += 1
            file_path = os.path.join(root, fname)
            try:
                with open(file_path, encoding="utf-8") as f:
                    raw_data = yaml.safe_load(f)
                if not isinstance(raw_data, dict):
                    skipped_count += 1
                    continue

                rule_id = f"{prefix}-{seq:04d}"
                while rule_id in global_seen_ids:
                    seq += 1
                    rule_id = f"{prefix}-{seq:04d}"

                threat_rule = process_sigma_rule(raw_data, rule_id, category)
                if threat_rule is None:
                    skipped_count += 1
                    continue

                global_seen_ids.add(rule_id)
                seq += 1
                converted_rules.append(threat_rule.model_dump(mode="json"))
            except (OSError, yaml.YAMLError) as e:
                logger.debug("Error parsing Sigma YAML file", file=fname, error=str(e))
                skipped_count += 1

    return converted_rules, read_count, len(converted_rules), skipped_count


def write_rule_file(rules: list[dict[str, Any]], output_file: Path) -> None:
    """Writes converted rules to a YAML file with header attribution.

    Args:
        rules: List of ThreatRule dictionaries.
        output_file: Destination YAML file path.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    now_utc = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")

    header = (
        "# Rules imported from the SigmaHQ project.\n"
        "# Original author: SigmaHQ — License: Detection Rule License (DRL) / Apache 2.0\n"
        f"# Auto-generated by scripts/import_sigma_rules.py on {now_utc} — DO NOT EDIT BY HAND.\n\n"
    )

    yaml_content = yaml.dump(
        rules,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )

    output_file.write_text(header + yaml_content, encoding="utf-8")
    logger.info("Wrote Sigma rules file", path=str(output_file), count=len(rules))


def main() -> None:
    """Main execution entry point."""
    args = parse_args()

    ensure_sigma_repository(args.sigma_dir, args.repo_url)

    global_seen_ids: set[str] = set()
    total_read = 0
    total_converted = 0
    total_skipped = 0

    print("=" * 65)
    print(" Sigma Rules Import — ADR-AEGIS")
    print("=" * 65)

    for rel_subdir, config in CATEGORY_CONFIGS.items():
        rules, read_c, conv_c, skip_c = import_sigma_category(
            args.sigma_dir, rel_subdir, config, global_seen_ids
        )
        total_read += read_c
        total_converted += conv_c
        total_skipped += skip_c

        if rules:
            out_file = args.output_dir / config["file"]
            write_rule_file(rules, out_file)
            print(f" • {config['category']:<22}: {conv_c:>4} règles -> {out_file}")

    print("-" * 65)
    print(f" Total règles lues       : {total_read}")
    print(f" Total règles converties : {total_converted}")
    print(f" Total règles skippées   : {total_skipped}")
    print("=" * 65)


if __name__ == "__main__":
    main()
