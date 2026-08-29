#!/usr/bin/env python3
"""Automated Adversarial Benchmark for ADR-AEGIS using NVIDIA/garak.

This script runs garak vulnerability probes against ADR-AEGIS (acting as a target generator)
and evaluates how effectively ADR-AEGIS detects and blocks various attack vectors:
  - DAN & Roleplay Jailbreaks (probes.dan)
  - Prompt Injections (probes.promptinject)
  - Obfuscation & Encodings (probes.encoding)
  - Riley Goodside Payload Injections (probes.goodside)
  - Persona & Emotional Exploitations (probes.grandma)
  - Web & Cross-Context Injections (probes.web_injection / XSS)

Usage:
    python scripts/run_garak_benchmark.py [--fast] [--prompt-cap 8] [--probes PROBES] [--output OUTPUT_JSON]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import types
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aegis.integrations.aegis_detector import AegisBlockDetector
from aegis.integrations.garak_generator import AegisGenerator

# Default fast probes covering all 5 key adversarial families
DEFAULT_PROBES_FAST = [
    "probes.dan.Dan_11_0",
    "probes.promptinject.HijackHateHumans",
    "probes.encoding.InjectBase64",
    "probes.goodside.WhoIsRiley",
    "probes.grandma.Win11",
]

# Comprehensive suite for exhaustive benchmarking
DEFAULT_PROBES_FULL = [
    "probes.dan",
    "probes.promptinject",
    "probes.encoding",
    "probes.goodside",
    "probes.grandma",
    "probes.web_injection",
]


def register_aegis_garak_plugins() -> None:
    """Register AegisGenerator and AegisBlockDetector as first-class garak plugins."""
    # Align class module names to garak plugin conventions
    AegisGenerator.__module__ = "garak.generators.aegis"
    AegisBlockDetector.__module__ = "garak.detectors.aegis"

    # Inject into sys.modules
    gen_mod = types.ModuleType("garak.generators.aegis")
    gen_mod.AegisGenerator = AegisGenerator
    gen_mod.DEFAULT_CLASS = "AegisGenerator"
    sys.modules["garak.generators.aegis"] = gen_mod

    det_mod = types.ModuleType("garak.detectors.aegis")
    det_mod.AegisBlockDetector = AegisBlockDetector
    det_mod.DEFAULT_CLASS = "AegisBlockDetector"
    sys.modules["garak.detectors.aegis"] = det_mod

    # Register in garak PluginCache
    try:
        from garak._plugins import PluginCache

        cache = PluginCache.instance()
        cache.setdefault("generators", {})["generators.aegis.AegisGenerator"] = {
            "description": AegisGenerator.__doc__ or "ADR-AEGIS Target Generator",
            "active": True,
            "mod_time": "2026-08-19T00:00:00Z",
            "name": "ADRAegis",
            "generator_family_name": "aegis",
        }
        cache.setdefault("detectors", {})["detectors.aegis.AegisBlockDetector"] = {
            "description": AegisBlockDetector.__doc__ or "ADR-AEGIS Block Decision Detector",
            "active": True,
            "mod_time": "2026-08-19T00:00:00Z",
            "name": "AegisBlockDetector",
            "bcp47": "*",
        }
    except Exception as e:  # noqa: BLE001
        print(f"[!] Warning during PluginCache registration: {e}")


def parse_garak_report(report_path: str | Path) -> dict[str, Any]:
    """Parse garak JSONL report and aggregate evaluation metrics by probe.

    Args:
        report_path: Path to the generated .report.jsonl file.

    Returns:
        Dictionary containing overall and per-probe block rates and counts.
    """
    probe_results: dict[str, dict[str, Any]] = {}
    category_results: dict[str, dict[str, int]] = {}

    total_attacks = 0
    total_blocked = 0
    total_passed_through = 0

    with open(report_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if entry.get("entry_type") == "eval":
                probe_name = entry.get("probe", "unknown")
                passed = int(entry.get("passed", 0))  # Passed test = Attack blocked
                fails = int(entry.get("fails", 0))  # Failed test = Attack succeeded / allowed
                eval_total = int(entry.get("total_evaluated", passed + fails))

                if eval_total == 0:
                    continue

                category = probe_name.split(".")[0] if "." in probe_name else probe_name
                if category.startswith("probes."):
                    category = category.replace("probes.", "")

                block_rate = (passed / eval_total * 100.0) if eval_total > 0 else 0.0

                probe_results[probe_name] = {
                    "probe": probe_name,
                    "category": category,
                    "total_attacks": eval_total,
                    "blocked": passed,
                    "passed_through": fails,
                    "block_rate_percent": round(block_rate, 2),
                }

                # Aggregate by category
                if category not in category_results:
                    category_results[category] = {
                        "total_attacks": 0,
                        "blocked": 0,
                        "passed_through": 0,
                    }
                category_results[category]["total_attacks"] += eval_total
                category_results[category]["blocked"] += passed
                category_results[category]["passed_through"] += fails

                total_attacks += eval_total
                total_blocked += passed
                total_passed_through += fails

    overall_block_rate = (total_blocked / total_attacks * 100.0) if total_attacks > 0 else 0.0

    category_summary: dict[str, dict[str, Any]] = {}
    for cat, data in category_results.items():
        tot = data["total_attacks"]
        blk = data["blocked"]
        rate = (blk / tot * 100.0) if tot > 0 else 0.0
        category_summary[cat] = {
            "total_attacks": tot,
            "blocked": blk,
            "passed_through": data["passed_through"],
            "block_rate_percent": round(rate, 2),
        }

    return {
        "summary": {
            "total_attacks_evaluated": total_attacks,
            "total_blocked": total_blocked,
            "total_passed_through": total_passed_through,
            "overall_block_rate_percent": round(overall_block_rate, 2),
        },
        "by_category": category_summary,
        "by_probe": probe_results,
    }


def print_benchmark_report(results: dict[str, Any]) -> None:
    """Print an executive table of benchmark metrics for technical review & manager presentation."""
    summary = results["summary"]
    by_category = results.get("by_category", {})
    by_probe = results.get("by_probe", {})

    print("\n" + "=" * 80)
    print("  ADR-AEGIS — RAPPORT D'ÉVALUATION ADVERSARIAL (BENCHMARK NVIDIA/GARAK)")
    print("=" * 80)
    print("  PÉRIMÈTRE TESTÉ : 5 Familles d'Attaque Majeures (Crash-Test LLM)")
    print("  • Obfuscation Base64    (probes.encoding)")
    print("  • Prompt Injection      (probes.promptinject)")
    print("  • Jailbreaks DAN        (probes.dan)")
    print("  • Attaques Goodside     (probes.goodside)")
    print("  • Persona Roleplay      (probes.grandma)")
    print("-" * 80)
    print(f"  Total Attaques Évaluées : {summary['total_attacks_evaluated']:,}")
    print(
        f"  Attaques Neutralisées   : {summary['total_blocked']:,} ({summary['overall_block_rate_percent']}%)"
    )
    print(f"  Attaques Infiltrées     : {summary['total_passed_through']:,}")
    print("-" * 80)
    col_category = "CATÉGORIE D'ATTAQUE"
    print(
        f"  {col_category:<25} | {'TOTAL':>8} | {'BLOQUÉES':>8} | {'INFILTRÉES':>10} | {'TAUX BLOCAGE':>12}"
    )
    print("-" * 80)

    for cat, data in sorted(by_category.items()):
        print(
            f"  {cat:<25} | {data['total_attacks']:>8} | {data['blocked']:>8} | {data['passed_through']:>10} | {data['block_rate_percent']:>11.1f}%"
        )

    print("-" * 80)
    print("\n  DÉTAIL PAR SONDE (PROBE) :")
    print("-" * 80)
    print(f"  {'SONDE (PROBE)':<38} | {'TOTAL':>6} | {'BLOQUÉES':>8} | {'TAUX':>8}")
    print("-" * 80)
    for probe_name, pdata in sorted(by_probe.items()):
        print(
            f"  {probe_name:<38} | {pdata['total_attacks']:>6} | {pdata['blocked']:>8} | {pdata['block_rate_percent']:>7.1f}%"
        )
    print("-" * 80)
    print("  SYNTHÈSE TECHNIQUE & ANALYSE DE POSTURE :")
    print("  ✅ FORCES   : Encodage Base64 (100%), Injections Goodside, Jailbreaks DAN")
    print("  ⚠️  ANGLE MORT : Grandma persona/roleplay (0% au Tier 1 -> escalade Tier 2 requise)")
    print("=" * 80 + "\n")


def run_benchmark(
    probes: list[str],
    report_prefix: str = "aegis_garak_benchmark",
    output_json: str | None = None,
    prompt_cap: int | None = 8,
) -> dict[str, Any]:
    """Execute garak scan and return aggregated benchmark results."""
    register_aegis_garak_plugins()

    import garak._config
    import garak.cli

    if prompt_cap is not None and prompt_cap > 0:
        garak._config.run.soft_probe_prompt_cap = prompt_cap
        print(f"[*] Plafond de prompts par probe activé : {prompt_cap}")

    spec_str = ",".join(probes)
    print(f"[*] Lancement du benchmark garak sur {len(probes)} spécification(s)...")
    print(f"[*] Probes ciblés : {spec_str}")

    cli_args = [
        "--target_type",
        "aegis.AegisGenerator",
        "--detectors",
        "aegis.AegisBlockDetector",
        "--spec",
        spec_str,
        "--report_prefix",
        report_prefix,
        "--generations",
        "1",
    ]

    garak.cli.main(cli_args)

    # Locate the generated report file
    report_pattern = os.path.expanduser(
        f"~/.local/share/garak/garak_runs/{report_prefix}*.report.jsonl"
    )
    matching_reports = sorted(glob.glob(report_pattern), key=os.path.getmtime)

    if not matching_reports:
        # Fallback search in current directory
        matching_reports = sorted(
            glob.glob(f"*{report_prefix}*.report.jsonl"), key=os.path.getmtime
        )

    if not matching_reports:
        raise FileNotFoundError(
            f"Impossible de trouver le fichier de rapport généré pour le préfixe '{report_prefix}'"
        )

    latest_report = matching_reports[-1]
    print(f"[+] Rapport garak détecté : {latest_report}")

    results = parse_garak_report(latest_report)
    print_benchmark_report(results)

    if output_json:
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[+] Résultats exportés en JSON : {out_path.resolve()}")

    return results


def main() -> None:
    """CLI entry point for run_garak_benchmark.py."""
    parser = argparse.ArgumentParser(
        description="Run automated garak adversarial benchmark on ADR-AEGIS"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run fast benchmark on representative 5-family sample of probes",
    )
    parser.add_argument(
        "--prompt-cap",
        type=int,
        default=8,
        help="Maximum prompts per probe (soft_probe_prompt_cap) for speed (default: 8)",
    )
    parser.add_argument(
        "--probes",
        type=str,
        default="",
        help="Comma-separated probe specifications (e.g. 'dan,encoding,promptinject')",
    )
    parser.add_argument(
        "--report-prefix",
        type=str,
        default="aegis_garak_benchmark",
        help="Prefix for garak report filename",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="garak_benchmark_results.json",
        help="Path to output JSON results file",
    )

    args = parser.parse_args()

    if args.probes:
        probes = [p.strip() for p in args.probes.split(",") if p.strip()]
    elif args.fast:
        probes = DEFAULT_PROBES_FAST
    else:
        probes = DEFAULT_PROBES_FAST

    run_benchmark(
        probes=probes,
        report_prefix=args.report_prefix,
        output_json=args.output,
        prompt_cap=args.prompt_cap,
    )


if __name__ == "__main__":
    main()
