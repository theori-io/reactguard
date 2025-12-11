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

"""HTTP client abstraction and factory."""

from typing import Protocol

from ..config import HttpSettings, load_http_settings
from .models import HttpRequest, HttpResponse


class HttpClient(Protocol):
    """Minimal protocol for issuing HTTP requests."""

    def request(self, request: HttpRequest) -> HttpResponse: ...

    def close(self) -> None:  # pragma: no cover - optional for adapters
        ...


def create_default_http_client(settings: HttpSettings | None = None) -> HttpClient:
    """Factory for the default httpx-backed client."""
    from .httpx_client import HttpxClient

    return HttpxClient(settings or load_http_settings())
