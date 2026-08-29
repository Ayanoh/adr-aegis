"""Unit tests for Meta PurpleLlama Code Shield security analyzer."""

from aegis.code_shield.scanner import CodeShieldScanner
from aegis.code_shield.schema import (
    CodeShieldConfig,
    CWEType,
)


def test_code_shield_allows_safe_code() -> None:
    """Safe Python code with parameterized database queries passes scan."""
    scanner = CodeShieldScanner()
    safe_code = """
def get_user_profile(cursor, user_id: int):
    query = "SELECT id, username, email FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
"""
    verdict = scanner.scan_code(safe_code)

    assert verdict.is_secure is True
    assert len(verdict.vulnerabilities) == 0
    assert verdict.risk_score == 0.0


def test_code_shield_detects_sql_injection() -> None:
    """SQL injection via f-string query formatting is detected (CWE-89)."""
    scanner = CodeShieldScanner()
    vulnerable_code = """
def get_user_by_name(cursor, name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
"""
    verdict = scanner.scan_code(vulnerable_code)

    assert verdict.is_secure is False
    assert any(v.cwe_type == CWEType.CWE_89_SQL_INJECTION for v in verdict.vulnerabilities)
    vuln = next(v for v in verdict.vulnerabilities if v.cwe_type == CWEType.CWE_89_SQL_INJECTION)
    assert "parameterized" in vuln.remediation_suggestion.lower()


def test_code_shield_detects_command_injection() -> None:
    """subprocess execution with shell=True is detected (CWE-78)."""
    scanner = CodeShieldScanner()
    vulnerable_code = """
import subprocess

def ping_host(host_ip: str):
    subprocess.run(f"ping -c 1 {host_ip}", shell=True)
"""
    verdict = scanner.scan_code(vulnerable_code)

    assert verdict.is_secure is False
    assert any(v.cwe_type == CWEType.CWE_78_COMMAND_INJECTION for v in verdict.vulnerabilities)


def test_code_shield_detects_insecure_deserialization() -> None:
    """pickle.loads on untrusted input is flagged (CWE-502)."""
    scanner = CodeShieldScanner()
    vulnerable_code = """
import pickle

def load_payload(raw_bytes: bytes):
    return pickle.loads(raw_bytes)
"""
    verdict = scanner.scan_code(vulnerable_code)

    assert verdict.is_secure is False
    assert any(
        v.cwe_type == CWEType.CWE_502_INSECURE_DESERIALIZATION for v in verdict.vulnerabilities
    )


def test_code_shield_detects_eval_exec() -> None:
    """Dynamic eval/exec execution is flagged (CWE-94)."""
    scanner = CodeShieldScanner()
    vulnerable_code = """
def calculate_expression(expr: str):
    return eval(expr)
"""
    verdict = scanner.scan_code(vulnerable_code)

    assert verdict.is_secure is False
    assert any(v.cwe_type == CWEType.CWE_94_CODE_INJECTION for v in verdict.vulnerabilities)


def test_code_shield_detects_insecure_crypto() -> None:
    """Usage of MD5 for cryptographic hashing is flagged (CWE-327)."""
    scanner = CodeShieldScanner()
    vulnerable_code = """
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
"""
    verdict = scanner.scan_code(vulnerable_code)

    assert any(v.cwe_type == CWEType.CWE_327_BROKEN_CRYPTO for v in verdict.vulnerabilities)


def test_code_shield_detects_xss_in_javascript() -> None:
    """Direct innerHTML assignment in JavaScript is detected (CWE-79)."""
    scanner = CodeShieldScanner()
    js_code = """
function renderUserGreeting(userName) {
    document.getElementById('greeting').innerHTML = "<h1>Welcome " + userName + "</h1>";
}
"""
    verdict = scanner.scan_code(js_code)

    assert verdict.is_secure is False
    assert any(v.cwe_type == CWEType.CWE_79_XSS for v in verdict.vulnerabilities)


def test_code_shield_extracts_markdown_code_blocks() -> None:
    """Markdown text with multiple fenced code blocks is parsed and analyzed."""
    scanner = CodeShieldScanner()
    markdown_response = """
Here is the solution to query data and ping a server:

```python
import subprocess
subprocess.run("ping 127.0.0.1", shell=True)
```

And here is the database function:

```sql
SELECT * FROM products;
```
"""
    verdict = scanner.scan_code(markdown_response)

    assert verdict.is_secure is False
    assert verdict.language_detected == "python"
    assert verdict.scanned_lines_count > 0
    assert any(v.cwe_type == CWEType.CWE_78_COMMAND_INJECTION for v in verdict.vulnerabilities)


def test_code_shield_empty_code_handling() -> None:
    """Empty code strings return clean verdicts without errors."""
    scanner = CodeShieldScanner()

    verdict_empty = scanner.scan_code("")
    assert verdict_empty.is_secure is True
    assert len(verdict_empty.vulnerabilities) == 0

    verdict_whitespace = scanner.scan_code("   \n\t  ")
    assert verdict_whitespace.is_secure is True


def test_code_shield_strict_mode_risk_scoring() -> None:
    """Strict mode marks code with any vulnerability as is_secure=False."""
    # Non-strict config with high tolerance
    tolerant_config = CodeShieldConfig(strict_mode=False, max_acceptable_risk=0.90)
    tolerant_scanner = CodeShieldScanner(config=tolerant_config)

    # Low-severity crypto flaw (medium severity weight = 0.4, risk_score = 0.16)
    code = "import hashlib\ndef h(x): return hashlib.md5(x).hexdigest()"
    tolerant_verdict = tolerant_scanner.scan_code(code)
    assert tolerant_verdict.is_secure is True  # Risk 0.16 <= 0.90

    # Strict config rejects any vulnerability
    strict_config = CodeShieldConfig(strict_mode=True)
    strict_scanner = CodeShieldScanner(config=strict_config)
    strict_verdict = strict_scanner.scan_code(code)
    assert strict_verdict.is_secure is False
