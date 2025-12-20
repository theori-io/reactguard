# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Configuration helpers for ReactGuard."""

import os
from dataclasses import dataclass

from .version import __version__

DEFAULT_USER_AGENT = f"ReactGuard/{__version__} (+https://reactguard.io; React2Shell scanner powered by Xint)"


def _float_env(name: str, default: float) -> float:
    try:
        value = os.getenv(name)
        return float(value) if value is not None else default
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        value = os.getenv(name)
        return int(value) if value is not None else default
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _optional_int_env(name: str, default: int | None) -> int | None:
    try:
        value = os.getenv(name)
        if value is None:
            return default
        parsed = int(value)
        return parsed if parsed > 0 else None
    except ValueError:
        return default


@dataclass
class HttpSettings:
    """HTTP client defaults."""

    timeout: float = 10.0
    max_retries: int = 2
    backoff_factor: float = 2.0
    initial_delay: float = 1.0
    retry_budget_multiplier: float = 10.0
    retry_budget_cap: float = 200.0
    user_agent: str = DEFAULT_USER_AGENT
    allow_redirects: bool = True
    verify_ssl: bool = True
    max_body_bytes: int = 16 * 1024 * 1024
    max_js_bytes: int | None = 16 * 1024 * 1024
    max_js_assets: int | None = 20

    @classmethod
    def from_env(cls) -> "HttpSettings":
        """Create settings from environment variables (evaluated at call time)."""
        max_body_bytes = _int_env("REACTGUARD_HTTP_MAX_BODY_BYTES", cls.max_body_bytes)
        if max_body_bytes <= 0:
            max_body_bytes = cls.max_body_bytes
        max_js_bytes = _optional_int_env("REACTGUARD_JS_MAX_BYTES", cls.max_js_bytes)
        max_js_assets = _optional_int_env("REACTGUARD_JS_MAX_ASSETS", cls.max_js_assets)
        return cls(
            timeout=_float_env("REACTGUARD_HTTP_TIMEOUT", cls.timeout),
            max_retries=_int_env("REACTGUARD_HTTP_RETRIES", cls.max_retries),
            backoff_factor=_float_env("REACTGUARD_HTTP_BACKOFF", cls.backoff_factor),
            initial_delay=_float_env("REACTGUARD_HTTP_INITIAL_DELAY", cls.initial_delay),
            retry_budget_multiplier=_float_env("REACTGUARD_HTTP_RETRY_BUDGET_MULTIPLIER", cls.retry_budget_multiplier),
            retry_budget_cap=_float_env("REACTGUARD_HTTP_RETRY_BUDGET_CAP", cls.retry_budget_cap),
            user_agent=os.getenv("REACTGUARD_USER_AGENT", cls.user_agent),
            allow_redirects=_bool_env("REACTGUARD_HTTP_REDIRECTS", cls.allow_redirects),
            verify_ssl=_bool_env("REACTGUARD_HTTP_VERIFY_SSL", cls.verify_ssl),
            max_body_bytes=max_body_bytes,
            max_js_bytes=max_js_bytes,
            max_js_assets=max_js_assets,
        )


def load_http_settings() -> HttpSettings:
    """Load HTTP settings from environment with sensible defaults."""
    return HttpSettings.from_env()
