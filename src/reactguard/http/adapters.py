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

import inspect
from typing import Any

from ..config import load_http_settings
from ..errors import ErrorCategory
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
            timeout = request.timeout
            if timeout is None:
                timeout = load_http_settings().timeout
            context = get_scan_context()
            scan_kwargs: dict[str, Any] = {
                "method": request.method,
                "headers": request.headers,
                "body": request.body,
                "timeout": timeout,
                "allow_redirects": request.allow_redirects,
            }

            if context.proxy_profile is not None or context.correlation_id is not None:
                try:
                    signature = inspect.signature(self._scanner_client.scan)
                    parameters = signature.parameters
                    accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values())
                    if context.proxy_profile is not None and (accepts_kwargs or "proxy_profile" in parameters):
                        scan_kwargs["proxy_profile"] = context.proxy_profile
                    if context.correlation_id is not None and (accepts_kwargs or "correlation_id" in parameters):
                        scan_kwargs["correlation_id"] = context.correlation_id
                except Exception:
                    if context.proxy_profile is not None:
                        scan_kwargs["proxy_profile"] = context.proxy_profile
                    if context.correlation_id is not None:
                        scan_kwargs["correlation_id"] = context.correlation_id

            try:
                data = self._scanner_client.scan(request.url, **scan_kwargs)
            except TypeError as exc:
                if ("proxy_profile" in scan_kwargs or "correlation_id" in scan_kwargs) and "unexpected keyword argument" in str(exc) and hasattr(self._scanner_client, "scan"):
                    scan_kwargs.pop("proxy_profile", None)
                    scan_kwargs.pop("correlation_id", None)
                    data = self._scanner_client.scan(request.url, **scan_kwargs)
                else:
                    raise

            raw_headers = data.get("headers") or {}
            headers: dict[str, str] = {}
            if isinstance(raw_headers, dict):
                for key, value in raw_headers.items():
                    if key is None:
                        continue
                    headers[str(key).lower()] = "" if value is None else str(value)
            else:
                try:
                    for key, value in dict(raw_headers).items():
                        if key is None:
                            continue
                        headers[str(key).lower()] = "" if value is None else str(value)
                except Exception:
                    headers = {}

            raw_body = data.get("body")
            raw_snippet = data.get("body_snippet")
            content: bytes = b""
            text: str = ""
            if isinstance(raw_body, (bytes, bytearray, memoryview)):
                content = bytes(raw_body)
                text = content.decode("utf-8", errors="replace")
            elif isinstance(raw_body, str):
                text = raw_body
                content = raw_body.encode("utf-8")
            elif isinstance(raw_snippet, (bytes, bytearray, memoryview)):
                content = bytes(raw_snippet)
                text = content.decode("utf-8", errors="replace")
            else:
                text = "" if raw_snippet is None else str(raw_snippet)
                content = text.encode("utf-8")

            return HttpResponse(
                ok=bool(data.get("ok")),
                status_code=data.get("status_code"),
                headers=headers,
                text=text,
                content=content,
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
