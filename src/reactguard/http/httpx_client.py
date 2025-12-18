# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""httpx-backed HttpClient implementation."""

from __future__ import annotations

import httpx

from ..config import HttpSettings, load_http_settings
from ..utils.context import get_scan_context
from .client import HttpClient
from .models import HttpRequest, HttpResponse


class HttpxClient(HttpClient):
    """Synchronous httpx client wrapper."""

    def __init__(self, settings: HttpSettings | None = None, client: httpx.Client | None = None):
        self.settings = settings or load_http_settings()
        self._client = client or httpx.Client(
            follow_redirects=self.settings.allow_redirects,
            timeout=self.settings.timeout,
            verify=self.settings.verify_ssl,
        )

    def request(self, request: HttpRequest) -> HttpResponse:
        headers = dict(request.headers or {})
        headers.setdefault("User-Agent", self.settings.user_agent)

        try:
            max_body_bytes = self.settings.max_body_bytes
            if max_body_bytes <= 0:
                max_body_bytes = 16 * 1024 * 1024

            timeout = request.timeout
            if timeout is None:
                context_timeout = get_scan_context().timeout
                timeout = context_timeout if context_timeout is not None else self.settings.timeout

            with self._client.stream(
                request.method,
                request.url,
                headers=headers,
                content=request.body,
                timeout=timeout,
                follow_redirects=request.allow_redirects,
            ) as resp:
                content = bytearray()
                truncated = False
                for chunk in resp.iter_bytes():
                    if not chunk:
                        continue
                    remaining = max_body_bytes - len(content)
                    if remaining <= 0:
                        truncated = True
                        break
                    if len(chunk) > remaining:
                        content.extend(chunk[:remaining])
                        truncated = True
                        break
                    content.extend(chunk)

                encoding = resp.encoding or "utf-8"
                try:
                    text = bytes(content).decode(encoding, errors="replace")
                except LookupError:
                    text = bytes(content).decode("utf-8", errors="replace")

            return HttpResponse(
                ok=True,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=text,
                content=bytes(content),
                url=str(resp.url),
                meta={
                    "body_truncated": truncated,
                    "body_bytes_read": len(content),
                    "body_bytes_limit": max_body_bytes,
                },
            )
        except Exception as exc:  # noqa: BLE001
            return HttpResponse(
                ok=False,
                error_message=str(exc),
                error_type=type(exc).__name__,
            )

    def close(self) -> None:
        self._client.close()
