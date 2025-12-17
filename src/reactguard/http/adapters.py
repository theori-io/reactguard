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
from ..utils.context import get_scan_context
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
            context = get_scan_context()
            timeout = request.timeout
            if timeout is None:
                timeout = context.timeout if context.timeout is not None else load_http_settings().timeout
            scan_kwargs: dict[str, Any] = {
                "method": request.method,
                "headers": request.headers,
                "body": request.body,
                "timeout": timeout,
                "allow_redirects": request.allow_redirects,
            }

            optional_args: list[str] = []
            if context.proxy_profile is not None:
                scan_kwargs["proxy_profile"] = context.proxy_profile
                optional_args.append("proxy_profile")
            if context.correlation_id is not None:
                scan_kwargs["correlation_id"] = context.correlation_id
                optional_args.append("correlation_id")

            try:
                data = self._scanner_client.scan(request.url, **scan_kwargs)
            except TypeError as exc:
                if optional_args and "unexpected keyword argument" in str(exc):
                    for key in optional_args:
                        scan_kwargs.pop(key, None)
                    data = self._scanner_client.scan(request.url, **scan_kwargs)
                else:
                    raise

            normalized = dict(data or {})
            normalized["url"] = normalized.get("url") or request.url
            response = HttpResponse.from_mapping(normalized)
            response.meta = dict(normalized)
            return response
        except Exception as exc:  # noqa: BLE001
            return HttpResponse(
                ok=False,
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
        return HttpResponse(ok=False, status_code=None, error_message="No stubbed response configured")

    def close(self) -> None:
        return None
