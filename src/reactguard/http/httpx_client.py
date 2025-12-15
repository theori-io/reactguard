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

"""httpx-backed HttpClient implementation."""


import httpx

from ..config import HttpSettings, load_http_settings
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

            with self._client.stream(
                request.method,
                request.url,
                headers=headers,
                content=request.body,
                timeout=request.timeout or self.settings.timeout,
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
