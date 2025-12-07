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

from typing import Optional

import httpx

from ..config import HttpSettings
from ..errors import categorize_exception
from .client import HttpClient
from .models import HttpRequest, HttpResponse


class HttpxClient(HttpClient):
    """Synchronous httpx client wrapper."""

    def __init__(
        self, settings: Optional[HttpSettings] = None, client: Optional[httpx.Client] = None
    ):
        self.settings = settings or HttpSettings()
        self._client = client or httpx.Client(
            follow_redirects=self.settings.allow_redirects,
            timeout=self.settings.timeout,
            verify=self.settings.verify_ssl,
        )

    def request(self, request: HttpRequest) -> HttpResponse:
        headers = dict(request.headers or {})
        headers.setdefault("User-Agent", self.settings.user_agent)

        try:
            resp = self._client.request(
                request.method,
                request.url,
                headers=headers,
                content=request.body,
                timeout=request.timeout or self.settings.timeout,
                follow_redirects=request.allow_redirects,
            )
            return HttpResponse(
                ok=True,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                content=resp.content,
                url=str(resp.url),
            )
        except Exception as exc:  # noqa: BLE001
            category = categorize_exception(exc)
            return HttpResponse(
                ok=False,
                error_category=category.value,
                error_message=str(exc),
                error_type=type(exc).__name__,
            )

    def close(self) -> None:
        self._client.close()
