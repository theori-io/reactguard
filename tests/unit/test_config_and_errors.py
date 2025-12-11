import importlib
import socket
import ssl

import httpx

from reactguard import config
from reactguard.config import DEFAULT_USER_AGENT
from reactguard.errors import ErrorCategory, categorize_exception, error_category_to_reason


def test_http_settings_env_overrides(monkeypatch):
    monkeypatch.setenv("REACTGUARD_HTTP_TIMEOUT", "5.5")
    monkeypatch.setenv("REACTGUARD_HTTP_RETRIES", "0")
    monkeypatch.setenv("REACTGUARD_HTTP_BACKOFF", "1.5")
    monkeypatch.setenv("REACTGUARD_HTTP_INITIAL_DELAY", "0.1")
    monkeypatch.setenv("REACTGUARD_HTTP_RETRY_BUDGET_MULTIPLIER", "2")
    monkeypatch.setenv("REACTGUARD_HTTP_RETRY_BUDGET_CAP", "50")
    monkeypatch.setenv("REACTGUARD_USER_AGENT", "CustomAgent/1.0")
    monkeypatch.setenv("REACTGUARD_HTTP_REDIRECTS", "false")
    monkeypatch.setenv("REACTGUARD_HTTP_VERIFY_SSL", "0")

    importlib.reload(config)
    settings = config.load_http_settings()

    assert settings.timeout == 5.5
    assert settings.max_retries == 0  # retry config clamps later
    assert settings.backoff_factor == 1.5
    assert settings.initial_delay == 0.1
    assert settings.retry_budget_multiplier == 2
    assert settings.retry_budget_cap == 50
    assert settings.user_agent == "CustomAgent/1.0"
    assert settings.allow_redirects is False
    assert settings.verify_ssl is False


def test_http_settings_invalid_env_fall_back(monkeypatch):
    monkeypatch.setenv("REACTGUARD_HTTP_TIMEOUT", "not-a-number")
    monkeypatch.setenv("REACTGUARD_HTTP_RETRIES", "ten")
    monkeypatch.setenv("REACTGUARD_HTTP_BACKOFF", "")
    monkeypatch.setenv("REACTGUARD_HTTP_INITIAL_DELAY", "-")

    importlib.reload(config)
    settings = config.load_http_settings()

    assert settings.timeout == config.HttpSettings.timeout
    assert settings.max_retries == config.HttpSettings.max_retries
    assert settings.backoff_factor == config.HttpSettings.backoff_factor
    assert settings.initial_delay == config.HttpSettings.initial_delay
    assert DEFAULT_USER_AGENT in settings.user_agent


def test_categorize_exception_mappings():
    assert categorize_exception(httpx.TimeoutException("t")) is ErrorCategory.TIMEOUT
    assert categorize_exception(httpx.ConnectError("c", request=None)) is ErrorCategory.CONNECTION_ERROR
    assert categorize_exception(ssl.SSLError("bad ssl")) is ErrorCategory.SSL_ERROR
    assert categorize_exception(socket.gaierror()) is ErrorCategory.DNS_ERROR
    assert categorize_exception(ConnectionResetError()) is ErrorCategory.CONNECTION_ERROR

    class WithResponse(Exception):
        def __init__(self, status_code):
            self.response = type("Resp", (), {"status_code": status_code})()

    assert categorize_exception(WithResponse(403)) is ErrorCategory.WAF_SUSPECTED
    assert categorize_exception(RuntimeError("other")) is ErrorCategory.UNKNOWN_ERROR


def test_error_category_to_reason():
    assert "timeout" in error_category_to_reason(ErrorCategory.TIMEOUT).lower()
    assert error_category_to_reason(None) == ""
    assert error_category_to_reason("unmapped") == "Probe failed due to network error"
