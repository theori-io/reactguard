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

"""HTTP request/response data models used across ReactGuard."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..config import HttpSettings

Headers = dict[str, str]


@dataclass
class HttpRequest:
    """Normalized request representation consumed by HttpClient implementations."""

    url: str
    method: str = "GET"
    headers: Headers | None = None
    body: bytes | str | None = None
    timeout: float | None = None
    allow_redirects: bool = True


@dataclass
class HttpResponse:
    """Normalized HTTP response with minimal metadata used by detectors and probes."""

    ok: bool
    status_code: int | None = None
    headers: Headers = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    url: str | None = None
    error_category: str | None = None
    error_message: str | None = None
    error_type: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def body_snippet(self) -> str:
        """Return a trimmed text body for lightweight analysis."""
        return self.text or ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> HttpResponse:
        """Helper to normalize dictionary-like responses (e.g., worker scan output)."""
        raw_headers = data.get("headers") or {}
        headers: Headers = {}
        if isinstance(raw_headers, Mapping):
            for key, value in raw_headers.items():
                if key is None:
                    continue
                headers[str(key).lower()] = "" if value is None else str(value)

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
        elif isinstance(raw_snippet, str):
            text = raw_snippet
            content = raw_snippet.encode("utf-8")

        return cls(
            ok=bool(data.get("ok")),
            status_code=data.get("status_code"),
            headers=headers,
            text=text,
            content=content,
            url=data.get("url"),
            error_category=data.get("error_category"),
            error_message=data.get("error_message"),
            error_type=data.get("error_type"),
            meta={k: v for k, v in data.items() if k not in {"ok", "status_code", "headers", "body", "body_snippet", "url", "error_category", "error_message", "error_type"}},
        )


@dataclass
class RetryConfig:
    """Retry policy for HTTP requests derived from HttpSettings."""

    max_attempts: int = 2
    backoff_factor: float = 2.0
    initial_delay: float = 1.0
    retry_on: Iterable[str] = field(default_factory=set)
    retry_never: Iterable[str] = field(default_factory=set)

    @classmethod
    def from_settings(cls, settings: HttpSettings) -> RetryConfig:
        """Build a retry config from the shared HttpSettings."""
        return cls(
            max_attempts=max(1, settings.max_retries),
            backoff_factor=settings.backoff_factor,
            initial_delay=settings.initial_delay,
        )
