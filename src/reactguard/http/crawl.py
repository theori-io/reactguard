# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Crawl-lite helpers (same-origin, GET-only) used for safe discovery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from ..config import load_http_settings
from .headers import header_value
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
) -> dict[str, Any]:
    settings = load_http_settings()
    client = get_http_client()

    request = HttpRequest(
        url=url,
        method="GET",
        headers={"Accept": "text/html, */*", "User-Agent": settings.user_agent},
        timeout=None,
        allow_redirects=True,
    )
    response = send_with_retries(client, request, retry_config=RetryConfig(max_attempts=1))

    result: dict[str, Any] = {
        "ok": response.ok,
        "status_code": response.status_code,
        "headers": response.headers,
        "body": response.text,
        "body_snippet": response.body_snippet,
        "url": response.url or url,
        "error_message": response.error_message,
        "error_type": response.error_type,
    }
    if result.get("ok") is False and result.get("error_message") and result.get("error") is None:
        result["error"] = result["error_message"]
    return result


def _looks_like_html(resp: dict[str, Any]) -> bool:
    headers = resp.get("headers") or {}
    content_type = header_value(headers, "content-type").lower()
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
    follow_links: bool = False,
) -> list[CrawledPage]:
    """
    Fetch same-origin HTML pages with strict limits.

    Safety properties:
    - GET-only requests
    - same-origin only
    - bounded by max_pages/max_depth
    - does not follow `<a href>` links by default

    Notes:
    - We follow the initial HTTP redirect chain (if any) and then enforce same-origin relative to the
      landing page. This supports common www/https redirects without broadening crawl scope.
    """
    if not start_url:
        return []

    start_norm = str(start_url)
    start_origin_url = start_norm
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

        resp = _scan_once(url)
        final_url = str(resp.get("url") or url)
        if final_url and final_url != url:
            if depth == 0 and url == start_norm:
                start_origin_url = final_url
            if final_url in visited:
                continue
            if not _same_origin(start_origin_url, final_url):
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
        if not follow_links:
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
            if not _same_origin(start_origin_url, normalized):
                continue
            if normalized in visited:
                continue
            queue.append((normalized, depth + 1))

    return out


__all__ = ["CrawledPage", "crawl_same_origin_html"]
