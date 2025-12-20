# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Lightweight JS-module parsing and same-origin crawling helpers."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from ..utils.context import get_http_settings
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
# Default JS scan budget; override via HttpSettings / env vars when needed.
DEFAULT_MAX_JS_BYTES: int | None = 16 * 1024 * 1024


def _resolve_js_asset_cap(max_assets: int | None) -> int | None:
    """
    Resolve the JS asset cap, honoring HttpSettings overrides when available.
    """
    if max_assets is None or max_assets == DEFAULT_MAX_JS_ASSETS:
        settings = get_http_settings()
        candidate = getattr(settings, "max_js_assets", None)
        if candidate is not None:
            max_assets = candidate
    if max_assets is None:
        return None
    try:
        return max(0, int(max_assets))
    except (TypeError, ValueError):
        return DEFAULT_MAX_JS_ASSETS


def _resolve_js_byte_budget(max_total_bytes: int | None) -> int | None:
    """
    Resolve the JS byte budget, honoring HttpSettings overrides when available.
    """
    if max_total_bytes is None or max_total_bytes == DEFAULT_MAX_JS_BYTES:
        settings = get_http_settings()
        candidate = getattr(settings, "max_js_bytes", None)
        if candidate is not None:
            max_total_bytes = candidate
    if max_total_bytes is None:
        return None
    try:
        return max(0, int(max_total_bytes))
    except (TypeError, ValueError):
        return DEFAULT_MAX_JS_BYTES

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
    allow_cross_origin_hop: bool = True,
) -> list[str]:
    """
    Extract JS asset URLs from HTML.

    Combines tag-based extraction (`<script src>`, `<link href>`) with a quoted-string fallback
    to catch inline bootstraps. URLs are normalized to absolute URLs and filtered to same-origin
    by default, with optional cross-origin inclusion for single-hop checks, then sorted by a
    heuristic priority to reduce bandwidth.
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

    candidates: dict[str, bool] = {}
    base_scheme = urlparse(base_url).scheme or "http"
    base_dir = build_base_dir_url(base_url)

    def _record_asset(candidate: str) -> None:
        if not candidate:
            return
        is_same_origin = same_origin(base_url, candidate)
        if is_same_origin:
            candidates[candidate] = True
            return
        candidates.setdefault(candidate, False)

    for js_url in js_urls:
        if js_url.startswith(("http://", "https://")):
            _record_asset(js_url)
            continue

        if js_url.startswith("//"):
            absolute = f"{base_scheme}:{js_url}"
            _record_asset(absolute)
            continue

        if js_url.startswith("/"):
            for candidate in build_endpoint_candidates(base_url, js_url):
                _record_asset(candidate)
            continue

        # Page-relative: resolve both as file-relative and dir-relative to handle `/app` vs `/app/`.
        primary = urljoin(base_url, js_url)
        _record_asset(primary)
        secondary = urljoin(base_dir, js_url)
        _record_asset(secondary)

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

    sorted_urls = sorted(
        candidates.items(),
        key=lambda item: (_priority_score(item[0]), 0 if item[1] else 1, item[0]),
    )
    max_assets = _resolve_js_asset_cap(max_assets)
    out: list[str] = []
    for url, is_same_origin in sorted_urls:
        if not is_same_origin:
            if not allow_cross_origin_hop:
                continue
        out.append(url)
        if max_assets is not None and len(out) >= max_assets:
            break
    return out


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
    Resolve an import specifier into fetchable absolute URLs.

    Supports:
    - absolute http(s) URLs
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
        return [raw]

    if raw.startswith("//"):
        scheme = urlparse(base_url).scheme or "http"
        absolute = f"{scheme}:{raw}"
        return [absolute]

    if raw.startswith("/"):
        return build_endpoint_candidates(base_url, raw)

    if raw.startswith((".", "..")):
        joined = urljoin(current_url, raw)
        return [joined]

    return []


def crawl_same_origin_js_modules(
    base_url: str,
    seeds: Iterable[str],
    *,
    fetch: Callable[[str], HttpResponse],
    max_modules: int = 20,
    max_total_bytes: int | None = DEFAULT_MAX_JS_BYTES,
    extra_url_patterns: Iterable[re.Pattern[str]] = (),
    allow_cross_origin_hop: bool = True,
) -> list[CrawledJsModule]:
    """
    Crawl same-origin JS modules, following import statements with strict limits.

    Safety properties:
    - same-origin only, with optional cross-origin seeds (no crawling from them)
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
    byte_budget = _resolve_js_byte_budget(max_total_bytes)

    queue: list[tuple[str, bool]] = []
    queued: set[str] = set()

    def _enqueue(candidate: str, *, allow_children: bool) -> None:
        if not candidate:
            return
        if candidate in queued:
            return
        if not allow_cross_origin_hop and not same_origin(base_url, candidate):
            return
        queue.append((candidate, allow_children))
        queued.add(candidate)

    def _seed_candidates(raw: str) -> None:
        text = str(raw or "").strip()
        if not text:
            return
        if text.startswith(("http://", "https://")):
            _enqueue(text, allow_children=same_origin(base_url, text))
            return
        if text.startswith("//"):
            absolute = f"{base_scheme}:{text}"
            _enqueue(absolute, allow_children=same_origin(base_url, absolute))
            return
        if text.startswith("/"):
            for candidate in resolve_js_import_candidates(base_url, base_url, text):
                _enqueue(candidate, allow_children=True)
            return
        # page-relative: resolve both as file-relative and dir-relative.
        primary = urljoin(base_url, text)
        secondary = urljoin(base_dir, text)
        for candidate in (primary, secondary):
            _enqueue(candidate, allow_children=True)

    for seed in seeds:
        _seed_candidates(seed)

    visited: set[str] = set()
    out: list[CrawledJsModule] = []

    idx = 0
    while idx < len(queue) and len(visited) < max_modules:
        module_url, allow_children = queue[idx]
        idx += 1
        if module_url in visited:
            continue
        visited.add(module_url)

        resp = fetch(module_url)
        if not resp.ok or resp.status_code != 200:
            continue

        final_url = str(resp.url or module_url)
        if final_url and not same_origin(base_url, final_url):
            allow_children = False

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

        if allow_children:
            for spec in extract_js_import_specs(body):
                for candidate in resolve_js_import_candidates(base_url, final_url or module_url, spec):
                    if candidate and same_origin(base_url, candidate) and candidate not in visited:
                        _enqueue(candidate, allow_children=True)

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
                        if candidate and same_origin(base_url, candidate) and candidate not in visited:
                            _enqueue(candidate, allow_children=True)

    return out


def extract_js_urls(
    html: str,
    base_url: str,
    *,
    max_assets: int = DEFAULT_MAX_JS_ASSETS,
    allow_cross_origin_hop: bool = True,
) -> list[str]:
    """Backward-compatible alias for extract_js_asset_urls."""
    return extract_js_asset_urls(html, base_url, max_assets=max_assets, allow_cross_origin_hop=allow_cross_origin_hop)


__all__ = [
    "CrawledJsModule",
    "crawl_same_origin_js_modules",
    "DEFAULT_MAX_JS_ASSETS",
    "DEFAULT_MAX_JS_BYTES",
    "_resolve_js_asset_cap",
    "_resolve_js_byte_budget",
    "extract_js_import_specs",
    "extract_js_asset_urls",
    "extract_js_urls",
    "looks_like_html_response",
    "resolve_js_import_candidates",
]
