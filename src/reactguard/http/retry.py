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

from ..config import load_http_settings
from ..utils.context import get_scan_context
from .client import HttpClient
from .models import HttpRequest, HttpResponse, RetryConfig


def build_default_retry_config() -> RetryConfig:
    """Create a RetryConfig from environment-backed HttpSettings."""
    settings = load_http_settings()
    return RetryConfig.from_settings(settings)


def send_with_retries(
    client: HttpClient,
    request: HttpRequest,
    *,
    retry_config: RetryConfig | None = None,
) -> HttpResponse:
    """Execute a request with basic retry/backoff semantics."""
    cfg = retry_config or build_default_retry_config()
    settings = load_http_settings()
    context = get_scan_context()

    attempt = 0
    delay = cfg.initial_delay
    last_response: HttpResponse | None = None
    base_timeout = request.timeout if request.timeout is not None else (context.timeout if context.timeout is not None else settings.timeout)
    budget = 0.0
    if base_timeout and base_timeout > 0:
        budget = settings.retry_budget_multiplier * cfg.max_attempts * base_timeout
        if settings.retry_budget_cap and settings.retry_budget_cap > 0:
            budget = min(budget, settings.retry_budget_cap)
    deadline = time.monotonic() + budget if budget > 0 else None

    while attempt < cfg.max_attempts:
        if deadline is not None and time.monotonic() >= deadline:
            break
        try:
            response = client.request(request)
        except Exception as exc:  # noqa: BLE001
            response = HttpResponse(
                ok=False,
                error_message=str(exc),
                error_type=exc.__class__.__name__,
            )
        last_response = response

        if response.ok:
            if attempt:
                response.meta["retry_count"] = attempt
            return response

        # Only retry transport-level failures (no status code). Some adapters may set `ok=False`
        # for HTTP error responses, which should not be blindly retried.
        if response.status_code is not None:
            if attempt:
                response.meta.setdefault("retry_count", attempt)
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
        last_response.meta.setdefault("retry_count", attempt)
        last_response.meta.setdefault("retry_exhausted", True)
        return last_response

    error_message = "Retry budget exhausted" if deadline else None
    return HttpResponse(ok=False, error_message=error_message, meta={"retry_count": attempt, "retry_exhausted": True})
