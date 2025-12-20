# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Lightweight JS-module parsing and same-origin crawling helpers."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from .heuristics import looks_like_html
from .models import HttpResponse
from .url import build_base_dir_url, build_endpoint_candidates, same_origin

_JS_IMPORT_FROM_PATTERN = re.compile(
    r'\b(?:import|export)\b[^;\n]*?\bfrom\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_SIDE_EFFECT_IMPORT_PATTERN = re.compile(r'\bimport\s*["\']([^"\']+)["\']', re.IGNORECASE)
_JS_DYNAMIC_IMPORT_PATTERN = re.compile(r'\bimport\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)

_JS_ASSET_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.(?:js|mjs|cjs|jsx|tsx)(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)
_JS_ASSET_LINK_RE = re.compile(
    r'<link[^>]+href=["\']([^"\']+\.(?:js|mjs|cjs)(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)
_JS_ASSET_QUOTED_RE = re.compile(r'["\']([^"\']*\.(?:js|mjs|cjs)(?:\?[^"\']*)?)["\']')

DEFAULT_MAX_JS_ASSETS = 20
DEFAULT_MAX_JS_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class CrawledJsModule:
    """Result for a fetched JS module."""

    url: str
    final_url: str
    headers: dict[str, str]
    body: str


def looks_like_html_response(headers: Mapping[str, object] | None, body: str | None) -> bool:
    return looks_like_html(headers, body)


def extract_js_asset_urls(
    html: str,
    base_url: str,
    *,
    max_assets: int = DEFAULT_MAX_JS_ASSETS,
    include_imports: bool = True,
) -> list[str]:
    """
    Extract same-origin JS asset URLs from HTML.

    Combines tag-based extraction (`<script src>`, `<link href>`) with a quoted-string fallback
    to catch inline bootstraps. URLs are normalized to same-origin absolute URLs and sorted by
    a heuristic priority to reduce bandwidth.
    """
    if not html or not base_url:
        return []

    js_urls: set[str] = set()

    for match in _JS_ASSET_SCRIPT_RE.findall(html):
        js_urls.add(match)

    for match in _JS_ASSET_LINK_RE.findall(html):
        js_urls.add(match)

    for match in _JS_ASSET_QUOTED_RE.findall(html):
        if "/" in match:
            js_urls.add(match)

    if include_imports:
        for match in _JS_DYNAMIC_IMPORT_PATTERN.findall(html):
            if match:
                js_urls.add(match)

    normalized: set[str] = set()
    base_scheme = urlparse(base_url).scheme or "http"
    base_dir = build_base_dir_url(base_url)

    for js_url in js_urls:
        if js_url.startswith(("http://", "https://")):
            if same_origin(base_url, js_url):
                normalized.add(js_url)
            continue

        if js_url.startswith("//"):
            absolute = f"{base_scheme}:{js_url}"
            if same_origin(base_url, absolute):
                normalized.add(absolute)
            continue

        if js_url.startswith("/"):
            for candidate in build_endpoint_candidates(base_url, js_url):
                if same_origin(base_url, candidate):
                    normalized.add(candidate)
            continue

        # Page-relative: resolve both as file-relative and dir-relative to handle `/app` vs `/app/`.
        primary = urljoin(base_url, js_url)
        if same_origin(base_url, primary):
            normalized.add(primary)
        secondary = urljoin(base_dir, js_url)
        if same_origin(base_url, secondary):
            normalized.add(secondary)

    def _priority_score(url: str) -> int:
        url_lower = url.lower()
        if any(token in url_lower for token in ("/_next/", "/rsc/", "/action")):
            return 0
        if "main" in url_lower or "index" in url_lower or "app" in url_lower:
            return 1
        if "bundle" in url_lower or "vendor" in url_lower:
            return 2
        if "chunk" in url_lower:
            return 3
        return 4

    sorted_urls = sorted(normalized, key=lambda url: (_priority_score(url), url))
    if max_assets is None:
        return sorted_urls
    safe_max = max(0, int(max_assets))
    return sorted_urls[:safe_max]


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
    fetch: Callable[[str], HttpResponse],
    max_modules: int = 20,
    max_total_bytes: int | None = DEFAULT_MAX_JS_BYTES,
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
    total_bytes = 0
    byte_budget = None
    if max_total_bytes is not None:
        byte_budget = max(0, int(max_total_bytes))

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
        if not resp.ok or resp.status_code != 200:
            continue

        final_url = str(resp.url or module_url)
        if final_url and not same_origin(base_url, final_url):
            continue

        raw_headers = resp.headers or {}
        headers: dict[str, str] = {}
        if isinstance(raw_headers, Mapping):
            for key, value in raw_headers.items():
                if key is None:
                    continue
                headers[str(key).lower()] = "" if value is None else str(value)
        body = str(resp.text or resp.body_snippet or "")
        if not body:
            continue
        if looks_like_html_response(headers, body):
            continue
        if byte_budget is not None:
            total_bytes += len(body)
            if total_bytes > byte_budget:
                break

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


def extract_js_urls(html: str, base_url: str, *, max_assets: int = DEFAULT_MAX_JS_ASSETS) -> list[str]:
    """Backward-compatible alias for extract_js_asset_urls."""
    return extract_js_asset_urls(html, base_url, max_assets=max_assets)


__all__ = [
    "CrawledJsModule",
    "crawl_same_origin_js_modules",
    "DEFAULT_MAX_JS_ASSETS",
    "DEFAULT_MAX_JS_BYTES",
    "extract_js_import_specs",
    "extract_js_asset_urls",
    "extract_js_urls",
    "looks_like_html_response",
    "resolve_js_import_candidates",
]
