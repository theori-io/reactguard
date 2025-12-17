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

from typing import Any

from ..config import DEFAULT_USER_AGENT, load_http_settings
from ..utils.context import get_scan_context
from .client import HttpClient
from .models import HttpRequest
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
) -> dict[str, Any]:
    """Execute an HTTP request with retries and return a normalized mapping."""
    return scan_with_retry(
        url,
        method=method,
        headers=headers,
        body=body,
        allow_redirects=allow_redirects,
    )


def scan_with_retry(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    allow_redirects: bool = True,
) -> dict[str, Any]:
    """Execute an HTTP request with retries and return a normalized mapping."""
    settings = load_http_settings()
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

    response = send_with_retries(client, request)

    result: dict[str, Any] = {
        "ok": response.ok,
        "status_code": response.status_code,
        "headers": response.headers,
        "body": response.text,
        "body_snippet": response.body_snippet,
        "url": response.url or url,
        "error_message": response.error_message,
        "error_type": response.error_type,
    }
    if result.get("ok") is False and result.get("error_message") and result.get("error") is None:
        result["error"] = result["error_message"]
    return result


__all__ = [
    "DEFAULT_USER_AGENT",
    "get_http_client",
    "request_with_retries",
    "scan_with_retry",
]
