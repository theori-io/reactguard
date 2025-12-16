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

"""Crawl-lite helpers (same-origin, GET-only) used for safe discovery."""

from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from ..config import load_http_settings
from ..utils.context import get_scan_context
from .models import HttpRequest, RetryConfig
from .retry import send_with_retries
from .utils import get_http_client


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: str
    depth: int


class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)


def _scan_once(
    url: str,
    *,
    timeout: float | None,
    http_client=None,
) -> dict[str, Any]:
    settings = load_http_settings()
    context = get_scan_context()
    client = http_client or context.http_client or get_http_client()
    effective_timeout = timeout if timeout is not None else (context.timeout if context.timeout is not None else settings.timeout)

    request = HttpRequest(
        url=url,
        method="GET",
        headers={"Accept": "text/html, */*", "User-Agent": settings.user_agent},
        timeout=effective_timeout,
        allow_redirects=True,
    )
    response = send_with_retries(client, request, retry_config=RetryConfig(max_attempts=1))

    return {
        "ok": response.ok,
        "status_code": response.status_code,
        "headers": response.headers,
        "body": response.text,
        "body_snippet": response.body_snippet,
        "url": response.url or url,
        "error_category": response.error_category,
        "error_message": response.error_message,
        "error_type": response.error_type,
    }


def _looks_like_html(resp: dict[str, Any]) -> bool:
    headers = resp.get("headers") or {}
    content_type = str(headers.get("content-type") or "").lower()
    if "text/html" in content_type:
        return True
    body = str(resp.get("body") or resp.get("body_snippet") or "").lstrip()
    lowered = body[:256].lower()
    return lowered.startswith("<!doctype") or lowered.startswith("<html") or "<html" in lowered


def _same_origin(start: str, candidate: str) -> bool:
    a = urlparse(start)
    b = urlparse(candidate)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def crawl_same_origin_html(
    start_url: str,
    *,
    max_pages: int = 6,
    max_depth: int = 2,
    timeout: float | None = 4.0,
    http_client=None,
) -> list[CrawledPage]:
    """
    Crawl same-origin HTML pages with strict limits.

    Safety properties:
    - GET-only requests
    - same-origin only
    - bounded by max_pages/max_depth
    """
    if not start_url:
        return []

    start_norm = str(start_url)
    visited: set[str] = set()
    out: list[CrawledPage] = []

    queue: deque[tuple[str, int]] = deque([(start_norm, 0)])
    while queue and len(out) < max_pages:
        url, depth = queue.popleft()
        if not url or depth > max_depth:
            continue
        if url in visited:
            continue
        visited.add(url)

        resp = _scan_once(url, timeout=timeout, http_client=http_client)
        final_url = str(resp.get("url") or url)
        if final_url and final_url != url:
            if final_url in visited:
                continue
            if not _same_origin(start_norm, final_url):
                continue
            visited.add(final_url)
            url = final_url

        if not resp.get("ok"):
            out.append(CrawledPage(url=url, status_code=resp.get("status_code"), headers=dict(resp.get("headers") or {}), body="", depth=depth))
            continue

        body = str(resp.get("body") or resp.get("body_snippet") or "")
        headers = dict(resp.get("headers") or {})
        out.append(CrawledPage(url=url, status_code=resp.get("status_code"), headers=headers, body=body, depth=depth))

        if depth >= max_depth:
            continue
        if not _looks_like_html(resp):
            continue

        parser = _HrefParser()
        try:
            parser.feed(body)
        except Exception:
            continue

        for href in parser.hrefs:
            raw = str(href or "").strip()
            if not raw:
                continue
            if raw.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            joined = urljoin(url, raw)
            parsed = urlparse(joined)
            if parsed.scheme not in {"http", "https"}:
                continue

            normalized = parsed._replace(fragment="").geturl()
            if not _same_origin(start_norm, normalized):
                continue
            if normalized in visited:
                continue
            queue.append((normalized, depth + 1))

    return out


__all__ = ["CrawledPage", "crawl_same_origin_html"]

