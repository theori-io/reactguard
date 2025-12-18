# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Adapters to integrate external scanners/workers with the HttpClient protocol."""

from __future__ import annotations

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
