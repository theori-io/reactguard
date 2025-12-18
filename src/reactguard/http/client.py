# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

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
