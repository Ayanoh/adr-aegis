"""Unit tests for Tier 2 Deep LLMProvider implementations (Mock and Gemini)."""

import io
import json
import urllib.error
import urllib.request
from typing import Self

import pytest

from aegis.tier2_deep.llm_provider import (
    GeminiProvider,
    LLMProviderError,
    MockLLMProvider,
)


def test_mock_llm_provider_availability_and_name() -> None:
    """Verify that MockLLMProvider is available and returns name 'mock'."""
    provider = MockLLMProvider()
    assert provider.is_available is True
    assert provider.name == "mock"


def test_mock_llm_provider_queue_and_default_response() -> None:
    """Verify MockLLMProvider returns queued responses then fallback default."""
    provider = MockLLMProvider(
        responses=["Response 1", "Response 2"],
        default_response="Default Fallback",
    )

    assert provider.generate("Prompt 1") == "Response 1"
    assert provider.generate("Prompt 2") == "Response 2"
    assert provider.generate("Prompt 3") == "Default Fallback"
    assert provider.generate("Prompt 4") == "Default Fallback"


def test_mock_llm_provider_records_calls() -> None:
    """Verify that generate() records call parameters in provider.calls."""
    provider = MockLLMProvider()
    provider.generate(
        prompt="Analyze this payload",
        system="You are a security forensic agent",
        temperature=0.2,
        max_tokens=512,
        json_mode=True,
    )

    assert len(provider.calls) == 1
    call = provider.calls[0]
    assert call["prompt"] == "Analyze this payload"
    assert call["system"] == "You are a security forensic agent"
    assert call["temperature"] == 0.2
    assert call["max_tokens"] == 512
    assert call["json_mode"] is True


def test_gemini_provider_no_key_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify GeminiProvider without API key is not available and raises on generate()."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    provider = GeminiProvider(api_key=None)

    assert provider.is_available is False
    with pytest.raises(LLMProviderError, match="GEMINI_API_KEY is missing or empty"):
        provider.generate("Test prompt")


def test_gemini_provider_auth_mode_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify auto-detection and explicit auth_mode resolution."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    # Auto-detection: AIza / AQ. prefix -> api_key
    provider_aiza = GeminiProvider(api_key="AIzaSyDummyKeyForTesting")
    assert provider_aiza.is_available is True
    assert provider_aiza._resolved_auth_mode == "api_key"
    assert provider_aiza.name == "gemini:gemini-3.6-flash"

    provider_aq = GeminiProvider(api_key="AQ.Ab8RN6KLBTO4slBHhCXxcSJfZibOv0gtg0uAf86gRAN_DtngjQ")
    assert provider_aq.is_available is True
    assert provider_aq._resolved_auth_mode == "api_key"

    # Auto-detection: other token -> bearer
    provider_oauth = GeminiProvider(api_key="ya29.a0AfH6SM...")
    assert provider_oauth.is_available is True
    assert provider_oauth._resolved_auth_mode == "bearer"

    # Explicit auth_mode overrides
    provider_explicit = GeminiProvider(api_key="AIzaKey", auth_mode="bearer")
    assert provider_explicit._resolved_auth_mode == "bearer"


def test_gemini_provider_generate_offline_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify successful parsing of Gemini API JSON response without network."""
    fake_response_data = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": '{"is_malicious": true, "confidence": 0.95}'}],
                    "role": "model",
                }
            }
        ]
    }
    encoded_json = json.dumps(fake_response_data).encode("utf-8")

    class MockHTTPResponse:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
            pass

        def read(self) -> bytes:
            return encoded_json

    def mock_urlopen(req: urllib.request.Request, timeout: float = 30.0) -> MockHTTPResponse:
        assert isinstance(req, urllib.request.Request)
        assert req.method == "POST"
        assert req.headers["Content-type"] == "application/json"
        body = json.loads(req.data.decode("utf-8"))
        assert body["contents"][0]["parts"][0]["text"] == "Check this command"
        assert body["generationConfig"]["responseMimeType"] == "application/json"
        return MockHTTPResponse()

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    provider = GeminiProvider(api_key="AIzaDummyTestKey")
    result = provider.generate(
        prompt="Check this command",
        system="Forensic Analyst",
        json_mode=True,
    )
    assert result == '{"is_malicious": true, "confidence": 0.95}'


def test_gemini_provider_error_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify specific error handling converts to LLMProviderError."""

    # 1. HTTP Error
    def mock_http_error(req: urllib.request.Request, timeout: float = 30.0) -> None:
        raise urllib.error.HTTPError(
            url="https://api",
            code=403,
            msg="Forbidden",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b'{"error": "API_KEY_INVALID"}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_http_error)
    provider = GeminiProvider(api_key="AIzaInvalidKey")
    with pytest.raises(LLMProviderError, match="HTTP 403"):
        provider.generate("test")

    # 2. Network / URLError
    def mock_url_error(req: urllib.request.Request, timeout: float = 30.0) -> None:
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", mock_url_error)
    with pytest.raises(LLMProviderError, match="network connection failed"):
        provider.generate("test")

    # 3. TimeoutError
    def mock_timeout(req: urllib.request.Request, timeout: float = 30.0) -> None:
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", mock_timeout)
    with pytest.raises(LLMProviderError, match="timed out"):
        provider.generate("test")
