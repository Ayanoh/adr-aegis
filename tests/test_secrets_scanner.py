"""Unit tests for aegis.tier1_fast.secrets_scanner module."""

from aegis.core.schema import ActionDecision, ThreatSeverity
from aegis.tier1_fast.secrets_scanner import (
    SecretFinding,
    SecretsScanner,
    calculate_entropy,
    is_false_positive,
)


def test_calculate_entropy_empty() -> None:
    """Verify entropy of empty string is 0.0."""
    assert calculate_entropy("") == 0.0


def test_calculate_entropy_single_char() -> None:
    """Verify entropy of uniform repeated characters is 0.0."""
    assert calculate_entropy("aaaa") == 0.0


def test_calculate_entropy_high() -> None:
    """Verify entropy of a high-randomness string is > 4.0."""
    high_entropy_str = "aB9#xK2$vL8@qZ5!wP3&"
    assert calculate_entropy(high_entropy_str) > 4.0


def test_is_false_positive_example() -> None:
    """Verify placeholder token is identified as a false positive."""
    assert is_false_positive("your_api_key_here") is True


def test_is_false_positive_real() -> None:
    """Verify realistic AWS key prefix is not classified as false positive."""
    assert is_false_positive("AKIAIOSFODNN7EXAMPLE") is False


def test_secret_finding_redacted() -> None:
    """Verify middle characters of detected secrets are properly masked."""
    # Test short secret (<= 8 chars)
    short_finding = SecretFinding(
        secret_type="test",
        value="12345678",
        full_match="12345678",
        entropy=3.0,
        confidence=0.8,
    )
    assert short_finding.redacted_value == "12***78"

    # Test long secret (> 8 chars)
    long_finding = SecretFinding(
        secret_type="aws_access_key_id",
        value="AKIAIOSFODNN7EXAMPLE",
        full_match="AKIAIOSFODNN7EXAMPLE",
        entropy=3.8,
        confidence=0.95,
    )
    assert long_finding.redacted_value == "AKIA***MPLE"


def test_scanner_aws_key() -> None:
    """Verify scanner detects AWS Access Key ID."""
    scanner = SecretsScanner()
    text = "Deploy config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in production"
    findings = scanner.scan(text)
    assert len(findings) == 1
    assert findings[0].secret_type == "aws_access_key_id"
    assert findings[0].value == "AKIAIOSFODNN7EXAMPLE"


def test_scanner_github_token() -> None:
    """Verify scanner detects GitHub Personal Access Tokens."""
    scanner = SecretsScanner()
    token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    text = f"git clone https://{token}@github.com/org/repo.git"
    findings = scanner.scan(text)
    assert len(findings) == 1
    assert findings[0].secret_type == "github_pat"
    assert findings[0].value == token


def test_scanner_openai_key() -> None:
    """Verify scanner detects OpenAI API keys."""
    scanner = SecretsScanner()
    openai_key = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
    text = f"export OPENAI_API_KEY={openai_key}"
    findings = scanner.scan(text)
    assert len(findings) == 1
    assert findings[0].secret_type == "openai_api_key"
    assert findings[0].value == openai_key


def test_scanner_private_key() -> None:
    """Verify scanner detects PEM Private Key blocks without requiring high entropy."""
    scanner = SecretsScanner()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    findings = scanner.scan(text)
    assert len(findings) == 1
    assert findings[0].secret_type == "private_key"


def test_scanner_database_uri() -> None:
    """Verify scanner detects database connection URIs containing credentials."""
    scanner = SecretsScanner()
    text = "DATABASE_URL=postgres://admin:SuperSecretPass123@db.prod.internal:5432/main"
    findings = scanner.scan(text)
    assert len(findings) >= 1
    assert any("postgres" in f.secret_type for f in findings)


def test_scanner_no_secrets() -> None:
    """Verify clean benign text returns no findings."""
    scanner = SecretsScanner()
    text = "def calculate_sum(a: int, b: int) -> int:\n    return a + b"
    findings = scanner.scan(text)
    assert len(findings) == 0


def test_scanner_false_positive_filtered() -> None:
    """Verify obvious test/dummy values are filtered out."""
    scanner = SecretsScanner()
    text = "api_key=test123"
    findings = scanner.scan(text)
    assert len(findings) == 0


def test_evaluate_critical() -> None:
    """Verify evaluate() produces a BLOCK verdict for critical credentials."""
    scanner = SecretsScanner()
    text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
    verdict = scanner.evaluate(text)
    assert verdict.decision == ActionDecision.BLOCK
    assert verdict.confidence >= 0.90
    assert len(verdict.threats) > 0
    assert verdict.threats[0].severity == ThreatSeverity.CRITICAL


def test_evaluate_clean() -> None:
    """Verify evaluate() produces an ALLOW verdict for benign text."""
    scanner = SecretsScanner()
    text = "pytest tests/ -v"
    verdict = scanner.evaluate(text)
    assert verdict.decision == ActionDecision.ALLOW
    assert verdict.confidence <= 0.20
    assert len(verdict.threats) == 0


def test_get_redacted_text() -> None:
    """Verify get_redacted_text() replaces detected secrets with [REDACTED:type]."""
    scanner = SecretsScanner()
    token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    text = f"Connecting with token {token} now"
    redacted = scanner.get_redacted_text(text)
    assert token not in redacted
    assert "[REDACTED:github_pat]" in redacted
