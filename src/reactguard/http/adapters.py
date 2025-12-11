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

"""Adapters to integrate external scanners/workers with the HttpClient protocol."""

from typing import Any

from ..config import load_http_settings
from ..errors import ErrorCategory
from .client import HttpClient
from .models import HttpRequest, HttpResponse


class WorkerHttpClientAdapter(HttpClient):
    """
    Adapter for the existing worker scanner_client interface (`scan` method).
    """

    def __init__(self, scanner_client: Any):
        self._scanner_client = scanner_client

    def request(self, request: HttpRequest) -> HttpResponse:
        try:
            timeout = request.timeout
            if timeout is None:
                timeout = load_http_settings().timeout
            data = self._scanner_client.scan(
                request.url,
                method=request.method,
                headers=request.headers,
                body=request.body,
                proxy_profile=request.proxy,
                correlation_id=request.correlation_id,
                timeout=timeout,
                allow_redirects=request.allow_redirects,
            )
            return HttpResponse(
                ok=bool(data.get("ok")),
                status_code=data.get("status_code"),
                headers=dict(data.get("headers") or {}),
                text=data.get("body") or data.get("body_snippet") or "",
                content=(data.get("body") or "").encode("utf-8"),
                url=data.get("url") or request.url,
                error_category=data.get("error_category"),
                error_message=data.get("error_message"),
                error_type=data.get("error_type"),
                meta=data,
            )
        except Exception as exc:  # noqa: BLE001
            return HttpResponse(
                ok=False,
                error_category=ErrorCategory.UNKNOWN_ERROR.value,
                error_message=str(exc),
                error_type=type(exc).__name__,
            )


class StubHttpClient(HttpClient):
    """Deterministic, programmable HttpClient for tests."""

    def __init__(self, responses: dict[str, HttpResponse] | None = None):
        self._responses = responses or {}
        self.requests: list[HttpRequest] = []

    def add(self, url: str, response: HttpResponse) -> None:
        self._responses[url] = response

    def request(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if request.url in self._responses:
            return self._responses[request.url]
        return HttpResponse(ok=False, status_code=None, error_category=ErrorCategory.UNKNOWN_ERROR.value)

    def close(self) -> None:
        return None
