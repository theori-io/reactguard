from __future__ import annotations

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

"""Retry helper for HttpClient implementations."""

import time
from typing import Optional

from ..config import load_http_settings
from ..errors import ErrorCategory
from .client import HttpClient
from .models import HttpRequest, HttpResponse, RetryConfig


def build_default_retry_config() -> RetryConfig:
    """Create a RetryConfig from environment-backed HttpSettings."""
    settings = load_http_settings()
    cfg = RetryConfig.from_settings(settings)
    cfg.retry_on = {
        ErrorCategory.TIMEOUT.value,
        ErrorCategory.CONNECTION_ERROR.value,
        ErrorCategory.DNS_ERROR.value,
        ErrorCategory.UNKNOWN_ERROR.value,
    }
    cfg.retry_never = {ErrorCategory.WAF_SUSPECTED.value, ErrorCategory.SSL_ERROR.value}
    return cfg


def send_with_retries(
    client: HttpClient,
    request: HttpRequest,
    *,
    retry_config: Optional[RetryConfig] = None,
) -> HttpResponse:
    """Execute a request with basic retry/backoff semantics."""
    cfg = retry_config or build_default_retry_config()

    attempt = 0
    delay = cfg.initial_delay
    last_response: Optional[HttpResponse] = None
    base_timeout = request.timeout if request.timeout is not None else load_http_settings().timeout
    budget = 0.0
    if base_timeout and base_timeout > 0:
        budget = 10 * cfg.max_attempts * base_timeout
    deadline = time.monotonic() + budget if budget > 0 else None

    while attempt < cfg.max_attempts:
        if deadline is not None and time.monotonic() >= deadline:
            break
        response = client.request(request)
        last_response = response

        if response.ok:
            if attempt:
                response.meta["retry_count"] = attempt
            return response

        category = response.error_category or ""
        if category in cfg.retry_never or category not in cfg.retry_on:
            return response

        attempt += 1
        if attempt >= cfg.max_attempts:
            break
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            delay_to_sleep = min(delay, remaining)
        else:
            delay_to_sleep = delay
        time.sleep(delay_to_sleep)
        delay *= cfg.backoff_factor

    if last_response is not None:
        return last_response

    error_category = ErrorCategory.TIMEOUT.value if deadline else ErrorCategory.UNKNOWN_ERROR.value
    error_message = "Retry budget exhausted" if deadline else None
    return HttpResponse(ok=False, error_category=error_category, error_message=error_message)
