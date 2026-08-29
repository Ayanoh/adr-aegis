"""Meta PurpleLlama Code Shield Scanner for Static Code Security Analysis."""

from __future__ import annotations

import re
import time
from typing import Any

import structlog

from aegis.code_shield.schema import (
    CodeShieldConfig,
    CodeShieldVerdict,
    CodeVulnerability,
    CWEType,
)

logger = structlog.get_logger()

# Severity weight mapping for risk score calculation
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.4,
    "low": 0.2,
}

# Detection rule specifications
CODE_RULES: list[dict[str, Any]] = [
    {
        "name": "SQL Injection (CWE-89) - Unsafe String Formatting/Concat",
        "cwe": CWEType.CWE_89_SQL_INJECTION,
        "pattern": re.compile(
            r'(?i)(?:(?:execute|cursor\.execute|db\.query|db\.execute)\s*\(\s*(?:f["\']|["\'].*?%|\w+\s*\+)|(?:SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM)\s+.*?f["\'])'
        ),
        "severity": "high",
        "suggestion": "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) instead of dynamic string formatting.",
    },
    {
        "name": "OS Command Injection (CWE-78) - subprocess with shell=True",
        "cwe": CWEType.CWE_78_COMMAND_INJECTION,
        "pattern": re.compile(
            r"(?i)subprocess\.(?:Popen|run|call|check_output|check_call)\s*\([^)]*?\bshell\s*=\s*True"
        ),
        "severity": "critical",
        "suggestion": "Pass command arguments as a list with shell=False (e.g., subprocess.run(['cmd', arg], shell=False)) to prevent command injection.",
    },
    {
        "name": "OS Command Injection (CWE-78) - os.system/popen execution",
        "cwe": CWEType.CWE_78_COMMAND_INJECTION,
        "pattern": re.compile(r"(?i)\bos\.(?:system|popen)\s*\("),
        "severity": "high",
        "suggestion": "Avoid os.system/os.popen; use subprocess.run with argument lists and shell=False.",
    },
    {
        "name": "Insecure Deserialization (CWE-502) - pickle / unsafe yaml loader",
        "cwe": CWEType.CWE_502_INSECURE_DESERIALIZATION,
        "pattern": re.compile(
            # Pattern handles nested parentheses (e.g., yaml.load(open(...), Loader=...))
            r"(?i)(?:\bpickle\.(?:loads|load)|\byaml\.unsafe_load|\byaml\.load\s*\(.*?Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)\b)"
        ),
        "severity": "critical",
        "suggestion": "Use safe serialization formats like JSON (json.loads) or yaml.safe_load instead of pickle or unsafe YAML loaders.",
    },
    {
        "name": "Dynamic Code Injection (CWE-94) - eval/exec usage",
        "cwe": CWEType.CWE_94_CODE_INJECTION,
        "pattern": re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*[^)]+"),
        "severity": "critical",
        "suggestion": "Avoid dynamic code execution with eval/exec. Use ast.literal_eval or safe mathematical expression parsers.",
    },
    {
        "name": "Cross-Site Scripting (CWE-79) - unsafe innerHTML / document.write",
        "cwe": CWEType.CWE_79_XSS,
        "pattern": re.compile(r"(?i)(?:\.innerHTML\s*=\s*[^;\n]+|\bdocument\.write\s*\()"),
        "severity": "high",
        "suggestion": "Use textContent or innerText instead of innerHTML, or sanitize untrusted content with a trusted HTML sanitizer before rendering.",
    },
    {
        "name": "Broken Cryptography (CWE-327) - MD5/SHA-1 or ECB Mode",
        "cwe": CWEType.CWE_327_BROKEN_CRYPTO,
        "pattern": re.compile(r"(?i)(?:hashlib\.(?:md5|sha1)\s*\(|\bDES\.new|\bMODE_ECB\b)"),
        "severity": "medium",
        "suggestion": "Use secure modern hash functions (SHA-256, SHA-512) or password hashing schemes (bcrypt, argon2) and avoid ECB cipher mode.",
    },
    {
        "name": "Path Traversal (CWE-22) - Unvalidated File Path Concat",
        "cwe": CWEType.CWE_22_PATH_TRAVERSAL,
        "pattern": re.compile(
            r'(?i)(?:open|file)\s*\(\s*(?:f["\'][^"\']*\{|\w+\s*\+\s*["\']?[a-zA-Z0-9_\-/]+)'
        ),
        "severity": "medium",
        "suggestion": "Sanitize user-provided file paths with os.path.basename or verify paths remain within the intended base directory using pathlib.Path.resolve().",
    },
]

MARKDOWN_CODE_BLOCK_PATTERN = re.compile(r"```([a-zA-Z0-9_\-\+]*)\n(.*?)```", re.DOTALL)


class CodeShieldScanner:
    """Static security analyzer for AI-generated code snippets and markdown responses.

    Inspects code against Top CWE vulnerabilities (SQLi, Command Injection,
    Insecure Deserialization, XSS, Eval/Exec, Broken Crypto).

    Usage:
        scanner = CodeShieldScanner()
        verdict = scanner.scan_code(ai_generated_python_code)
        if not verdict.is_secure:
            logger.warning("Vulnerable code generated", cwes=verdict.vulnerabilities)
    """

    def __init__(self, config: CodeShieldConfig | None = None) -> None:
        """Initialize the Code Shield Scanner.

        Args:
            config: Optional configuration for the scanner.
        """
        self.config = config or CodeShieldConfig()
        logger.info(
            "CodeShieldScanner initialized",
            strict_mode=self.config.strict_mode,
            max_acceptable_risk=self.config.max_acceptable_risk,
        )

    def extract_code_blocks(self, text: str) -> list[tuple[str, str]]:
        """Extract code blocks from a markdown document or return raw text as a block.

        Args:
            text: Markdown response or raw source code.

        Returns:
            List of tuples: (language_name, code_content).
        """
        if not text or not text.strip():
            return []

        matches = MARKDOWN_CODE_BLOCK_PATTERN.findall(text)
        if matches:
            return [
                (lang.strip().lower() or "generic", code.strip())
                for lang, code in matches
                if code.strip()
            ]

        # If no markdown blocks were found, treat the entire string as raw code
        return [("raw", text.strip())]

    def scan_code(self, code_or_markdown: str) -> CodeShieldVerdict:
        """Analyze code or markdown responses for CWE security vulnerabilities.

        Args:
            code_or_markdown: Source code string or markdown text containing code blocks.

        Returns:
            CodeShieldVerdict containing detected vulnerabilities, risk score, and status.
        """
        start_time = time.perf_counter()

        if not code_or_markdown or not code_or_markdown.strip():
            latency = (time.perf_counter() - start_time) * 1000.0
            return CodeShieldVerdict(
                is_secure=True,
                vulnerabilities=[],
                risk_score=0.0,
                language_detected=None,
                scanned_lines_count=0,
                latency_ms=round(latency, 2),
            )

        blocks = self.extract_code_blocks(code_or_markdown)
        detected_vulnerabilities: list[CodeVulnerability] = []
        total_lines = 0
        primary_lang: str | None = None

        for lang, code in blocks:
            if not primary_lang and lang != "raw":
                primary_lang = lang

            lines = code.splitlines()
            total_lines += len(lines)

            # Evaluate each rule against the code
            for rule in CODE_RULES:
                cwe: CWEType = rule["cwe"]
                if cwe not in self.config.enabled_cwes:
                    continue

                pattern: re.Pattern[str] = rule["pattern"]

                for line_idx, line in enumerate(lines, start=1):
                    match = pattern.search(line)
                    if match:
                        snippet = line.strip()
                        vuln = CodeVulnerability(
                            cwe_type=cwe,
                            severity=rule["severity"],
                            matched_pattern=rule["name"],
                            line_number=line_idx,
                            snippet=snippet,
                            remediation_suggestion=rule["suggestion"],
                        )
                        detected_vulnerabilities.append(vuln)

        # Calculate aggregated risk score
        risk_score = 0.0
        if detected_vulnerabilities:
            max_weight = max(
                SEVERITY_WEIGHTS.get(v.severity, 0.5) for v in detected_vulnerabilities
            )
            risk_score = min(1.0, round(max_weight, 2))

        # Determine security decision
        if self.config.strict_mode:
            is_secure = len(detected_vulnerabilities) == 0
        else:
            is_secure = risk_score <= self.config.max_acceptable_risk

        latency = (time.perf_counter() - start_time) * 1000.0

        return CodeShieldVerdict(
            is_secure=is_secure,
            vulnerabilities=detected_vulnerabilities,
            risk_score=risk_score,
            language_detected=primary_lang or "generic",
            scanned_lines_count=total_lines,
            latency_ms=round(latency, 2),
        )
