# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib

from reactguard import config
from reactguard.config import DEFAULT_USER_AGENT


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


def test_http_settings_redirects_truthy_variants(monkeypatch):
    importlib.reload(config)
    monkeypatch.setenv("REACTGUARD_HTTP_REDIRECTS", "1")
    importlib.reload(config)
    settings = config.load_http_settings()
    assert settings.allow_redirects is True

    monkeypatch.setenv("REACTGUARD_HTTP_REDIRECTS", "on")
    importlib.reload(config)
    settings = config.load_http_settings()
    assert settings.allow_redirects is True


def test_load_http_settings_reads_env_at_call_time(monkeypatch):
    importlib.reload(config)
    monkeypatch.setenv("REACTGUARD_HTTP_TIMEOUT", "7.7")
    assert config.load_http_settings().timeout == 7.7
    monkeypatch.setenv("REACTGUARD_HTTP_TIMEOUT", "8.8")
    assert config.load_http_settings().timeout == 8.8
