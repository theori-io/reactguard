# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Lightweight JS-module parsing and same-origin crawling helpers."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from .headers import header_value
from .url import build_base_dir_url, build_endpoint_candidates, same_origin

_JS_IMPORT_FROM_PATTERN = re.compile(
    r'\b(?:import|export)\b[^;\n]*?\bfrom\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_SIDE_EFFECT_IMPORT_PATTERN = re.compile(r'\bimport\s*["\']([^"\']+)["\']', re.IGNORECASE)
_JS_DYNAMIC_IMPORT_PATTERN = re.compile(r'\bimport\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)


@dataclass(frozen=True)
class CrawledJsModule:
    """Result for a fetched JS module."""

    url: str
    final_url: str
    headers: dict[str, str]
    body: str


def looks_like_html_response(headers: Mapping[str, object] | None, body: str) -> bool:
    headers = headers or {}
    content_type = header_value(headers, "content-type").lower()
    if "text/html" in content_type:
        return True
    lowered = str(body or "").lstrip().lower()
    return lowered.startswith("<!doctype") or lowered.startswith("<html")


def extract_js_import_specs(text: str) -> list[str]:
    """Extract import specifiers from common JS/TS import syntaxes."""
    if not text:
        return []
    specs: list[str] = []
    specs.extend(_JS_IMPORT_FROM_PATTERN.findall(text))
    specs.extend(_JS_SIDE_EFFECT_IMPORT_PATTERN.findall(text))
    specs.extend(_JS_DYNAMIC_IMPORT_PATTERN.findall(text))
    return list(dict.fromkeys([s for s in specs if s]))


def resolve_js_import_candidates(
    base_url: str,
    current_url: str,
    spec: str,
) -> list[str]:
    """
    Resolve an import specifier into fetchable same-origin URLs.

    Supports:
    - absolute http(s) URLs (filtered to same-origin)
    - root-relative URLs (/assets/app.js)
    - relative URLs (./chunk.js, ../chunk.js)

    Ignores:
    - package imports (react, @scope/pkg)
    - non-http schemes (data:, javascript:)
    """
    raw = str(spec or "").strip()
    if not raw:
        return []

    if raw.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
        return []

    if raw.startswith(("http://", "https://")):
        return [raw] if same_origin(base_url, raw) else []

    if raw.startswith("//"):
        scheme = urlparse(base_url).scheme or "http"
        absolute = f"{scheme}:{raw}"
        return [absolute] if same_origin(base_url, absolute) else []

    if raw.startswith("/"):
        return [u for u in build_endpoint_candidates(base_url, raw) if same_origin(base_url, u)]

    if raw.startswith((".", "..")):
        joined = urljoin(current_url, raw)
        return [joined] if same_origin(base_url, joined) else []

    return []


def crawl_same_origin_js_modules(
    base_url: str,
    seeds: Iterable[str],
    *,
    fetch: Callable[[str], Mapping[str, object]],
    max_modules: int = 20,
    extra_url_patterns: Iterable[re.Pattern[str]] = (),
) -> list[CrawledJsModule]:
    """
    Crawl same-origin JS modules, following import statements with strict limits.

    Safety properties:
    - same-origin only
    - bounded by max_modules
    - skips HTML fallbacks (common for dev servers returning index.html)
    """
    if not base_url:
        return []

    max_modules = max(0, int(max_modules))
    if max_modules <= 0:
        return []

    base_scheme = urlparse(base_url).scheme or "http"
    base_dir = build_base_dir_url(base_url)

    def _seed_candidates(raw: str) -> list[str]:
        text = str(raw or "").strip()
        if not text:
            return []
        if text.startswith(("http://", "https://")):
            return [text] if same_origin(base_url, text) else []
        if text.startswith("//"):
            absolute = f"{base_scheme}:{text}"
            return [absolute] if same_origin(base_url, absolute) else []
        if text.startswith("/"):
            return resolve_js_import_candidates(base_url, base_url, text)
        # page-relative: resolve both as file-relative and dir-relative.
        primary = urljoin(base_url, text)
        secondary = urljoin(base_dir, text)
        out: list[str] = []
        for candidate in (primary, secondary):
            if candidate and same_origin(base_url, candidate):
                out.append(candidate)
        return list(dict.fromkeys(out))

    queue: list[str] = []
    for seed in seeds:
        queue.extend(_seed_candidates(seed))

    visited: set[str] = set()
    out: list[CrawledJsModule] = []

    idx = 0
    while idx < len(queue) and len(visited) < max_modules:
        module_url = queue[idx]
        idx += 1
        if module_url in visited:
            continue
        visited.add(module_url)

        resp = fetch(module_url)
        if not resp or not bool(resp.get("ok")) or resp.get("status_code") != 200:
            continue

        final_url = str(resp.get("url") or module_url)
        if final_url and not same_origin(base_url, final_url):
            continue

        raw_headers = resp.get("headers") or {}
        headers: dict[str, str] = {}
        if isinstance(raw_headers, Mapping):
            for key, value in raw_headers.items():
                if key is None:
                    continue
                headers[str(key).lower()] = "" if value is None else str(value)
        body = str(resp.get("body") or resp.get("body_snippet") or "")
        if not body:
            continue
        if looks_like_html_response(headers, body):
            continue

        out.append(CrawledJsModule(url=module_url, final_url=final_url or module_url, headers=headers, body=body))

        for spec in extract_js_import_specs(body):
            for candidate in resolve_js_import_candidates(base_url, final_url or module_url, spec):
                if candidate and candidate not in visited:
                    queue.append(candidate)

        for pattern in extra_url_patterns:
            try:
                matches = pattern.findall(body)
            except Exception:
                continue
            for match in matches:
                raw_match = match[0] if isinstance(match, tuple) else match
                if not raw_match:
                    continue
                for candidate in resolve_js_import_candidates(base_url, final_url or module_url, str(raw_match)):
                    if candidate and candidate not in visited:
                        queue.append(candidate)

    return out


__all__ = [
    "CrawledJsModule",
    "crawl_same_origin_js_modules",
    "extract_js_import_specs",
    "looks_like_html_response",
    "resolve_js_import_candidates",
]
