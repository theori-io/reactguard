# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared HTTP helpers for scans and probes."""

from typing import Any

from ..config import DEFAULT_USER_AGENT, load_http_settings
from ..utils.context import get_scan_context
from .client import HttpClient
from .models import HttpRequest, HttpResponse, RetryConfig
from .retry import send_with_retries


def get_http_client() -> HttpClient:
    """Return the ambient HttpClient from ScanContext."""
    context = get_scan_context()
    if context.http_client is None:
        raise RuntimeError("No HttpClient configured; wrap the scan in scan_context(http_client=...)")
    return context.http_client


def request_with_retries(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    allow_redirects: bool = True,
) -> HttpResponse:
    """Execute an HTTP request with retries and return a typed response."""
    return _send_request(
        url,
        method=method,
        headers=headers,
        body=body,
        allow_redirects=allow_redirects,
        retry_config=None,
    )


def request_once(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    allow_redirects: bool = True,
) -> HttpResponse:
    """Execute a single HTTP request (no retries) and return a typed response."""
    return _send_request(
        url,
        method=method,
        headers=headers,
        body=body,
        allow_redirects=allow_redirects,
        retry_config=RetryConfig(max_attempts=1),
    )


def scan_with_retry(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    allow_redirects: bool = True,
) -> HttpResponse:
    """Execute an HTTP request with retries and return a typed response."""
    return request_with_retries(
        url,
        method=method,
        headers=headers,
        body=body,
        allow_redirects=allow_redirects,
    )


def _send_request(
    url: str,
    *,
    method: str,
    headers: dict[str, str] | None,
    body: str | bytes | None,
    allow_redirects: bool,
    retry_config: RetryConfig | None,
) -> HttpResponse:
    """Execute an HTTP request with a configurable retry policy."""
    context = get_scan_context()
    settings = context.http_settings or load_http_settings()
    request_headers = dict(headers or {})
    request_headers.setdefault("User-Agent", settings.user_agent)
    client = get_http_client()

    request = HttpRequest(
        url=url,
        method=method,
        headers=request_headers,
        body=body,
        timeout=None,
        allow_redirects=allow_redirects,
    )

    response = send_with_retries(client, request, retry_config=retry_config)
    if response.url is None:
        response.url = url
    return response


__all__ = [
    "DEFAULT_USER_AGENT",
    "get_http_client",
    "request_once",
    "request_with_retries",
    "scan_with_retry",
]
