# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Retry helper for HttpClient implementations."""

from __future__ import annotations

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
