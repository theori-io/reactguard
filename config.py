"""
    ReactGuard, framework- and vulnerability-detection tooling for CVE-2025-55182 (React2Shell).
    Copyright (C) 2025  Theori Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Configuration helpers for ReactGuard."""

import os
from dataclasses import dataclass

DEFAULT_USER_AGENT = "ReactGuard/0.5.1 (+https://reactguard.io) React2Shell scanner powered by Xint"


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


@dataclass
class HttpSettings:
    """HTTP client defaults."""

    timeout: float = _float_env("REACTGUARD_HTTP_TIMEOUT", 10.0)
    max_retries: int = _int_env("REACTGUARD_HTTP_RETRIES", 2)
    backoff_factor: float = _float_env("REACTGUARD_HTTP_BACKOFF", 2.0)
    initial_delay: float = _float_env("REACTGUARD_HTTP_INITIAL_DELAY", 1.0)
    user_agent: str = os.getenv("REACTGUARD_USER_AGENT", DEFAULT_USER_AGENT)
    allow_redirects: bool = os.getenv("REACTGUARD_HTTP_REDIRECTS", "true").lower() == "true"
    verify_ssl: bool = _bool_env("REACTGUARD_HTTP_VERIFY_SSL", True)


def load_http_settings() -> HttpSettings:
    """Load HTTP settings from environment with sensible defaults."""
    return HttpSettings()
