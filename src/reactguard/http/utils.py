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

"""Shared HTTP helpers for scans and probes."""

import logging
from typing import Any

from ..config import DEFAULT_USER_AGENT, load_http_settings
from ..errors import ErrorCategory
from ..utils.context import get_scan_context
from .client import HttpClient, create_default_http_client
from .models import HttpRequest
from .retry import send_with_retries

_shared_http_client: HttpClient | None = None

logger = logging.getLogger(__name__)


def set_shared_http_client(client: HttpClient) -> None:
    """Inject a shared HttpClient instance (deprecated; prefer ScanContext.http_client)."""
    context = get_scan_context()
    if context.http_client is None:
        logger.debug("set_shared_http_client is deprecated; set ScanContext.http_client or pass http_client explicitly.")
    global _shared_http_client
    _shared_http_client = client


def get_http_client(refresh: bool = False) -> HttpClient:
    """Return the current HttpClient, preferring ScanContext over globals."""
    context = get_scan_context()
    if context.http_client is not None and not refresh:
        return context.http_client
    global _shared_http_client
    if _shared_http_client is None or refresh:
        _shared_http_client = create_default_http_client(load_http_settings())
    if context.http_client is None:
        logger.debug("Using deprecated shared HTTP client fallback; prefer ScanContext.http_client.")
    return _shared_http_client


def scan_with_retry(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    timeout: float | None = None,
    allow_redirects: bool = True,
    http_client: HttpClient | None = None,
) -> dict[str, Any]:
    """Execute an HTTP request with retries and return a normalized mapping."""
    settings = load_http_settings()
    context = get_scan_context()
    request_headers = dict(headers or {})
    request_headers.setdefault("User-Agent", settings.user_agent)
    effective_proxy_profile = proxy_profile if proxy_profile is not None else context.proxy_profile
    effective_correlation_id = correlation_id if correlation_id is not None else context.correlation_id
    client = http_client or context.http_client or get_http_client()
    effective_timeout = timeout if timeout is not None else (context.timeout if context.timeout is not None else settings.timeout)

    request = HttpRequest(
        url=url,
        method=method,
        headers=request_headers,
        body=body,
        timeout=effective_timeout,
        allow_redirects=allow_redirects,
        proxy=effective_proxy_profile,
        correlation_id=effective_correlation_id,
    )

    response = send_with_retries(client, request)

    return {
        "ok": response.ok,
        "status_code": response.status_code,
        "headers": response.headers,
        "body": response.text,
        "body_snippet": response.body_snippet,
        "url": response.url or url,
        "error_category": response.error_category or ErrorCategory.NONE.value,
        "error_message": response.error_message,
        "error_type": response.error_type,
    }


__all__ = [
    "DEFAULT_USER_AGENT",
    "ErrorCategory",
    "get_http_client",
    "scan_with_retry",
    "set_shared_http_client",
]
