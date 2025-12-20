# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Crawl-lite helpers (same-origin, GET-only) used for safe discovery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .heuristics import looks_like_html
from .models import HttpResponse
from .utils import request_once


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
) -> HttpResponse:
    return request_once(
        url,
        headers={"Accept": "text/html, */*"},
        allow_redirects=True,
    )


def _looks_like_html(resp: HttpResponse) -> bool:
    headers = getattr(resp, "headers", {}) or {}
    body = getattr(resp, "text", "") or getattr(resp, "body_snippet", "")
    return looks_like_html(headers, body)


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
        final_url = str(getattr(resp, "url", None) or url)
        if final_url and final_url != url:
            if depth == 0 and url == start_norm:
                start_origin_url = final_url
            if final_url in visited:
                continue
            if not _same_origin(start_origin_url, final_url):
                continue
            visited.add(final_url)
            url = final_url

        if not getattr(resp, "ok", False):
            out.append(
                CrawledPage(
                    url=url,
                    status_code=getattr(resp, "status_code", None),
                    headers=dict(getattr(resp, "headers", {}) or {}),
                    body="",
                    depth=depth,
                )
            )
            continue

        body = str(getattr(resp, "text", "") or getattr(resp, "body_snippet", "") or "")
        headers = dict(getattr(resp, "headers", {}) or {})
        out.append(
            CrawledPage(
                url=url,
                status_code=getattr(resp, "status_code", None),
                headers=headers,
                body=body,
                depth=depth,
            )
        )

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
