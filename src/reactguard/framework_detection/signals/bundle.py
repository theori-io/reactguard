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

"""JS bundle probing for framework detection."""

import re
from urllib.parse import urljoin, urlparse

from ...http import request_with_retries
from ...http.client import HttpClient
from ...http.url import build_base_dir_url, build_endpoint_candidates, same_origin
from ...utils.context import scan_context


def extract_js_urls(body: str, base_url: str) -> list[str]:
    js_urls = set()

    for match in re.findall(
        r'<script[^>]+src=["\']([^"\']+\.(?:js|mjs|cjs|jsx|tsx)(?:\?[^"\']*)?)["\']',
        body,
        re.IGNORECASE,
    ):
        js_urls.add(match)

    for match in re.findall(
        r'<link[^>]+href=["\']([^"\']+\.(?:js|mjs|cjs)(?:\?[^"\']*)?)["\']',
        body,
        re.IGNORECASE,
    ):
        js_urls.add(match)

    for match in re.findall(r'["\']([^"\']*\.(?:js|mjs|cjs)(?:\?[^"\']*)?)["\']', body):
        if "/" in match:
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

    def priority_score(url: str) -> int:
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

    sorted_urls = sorted(normalized, key=lambda url: (priority_score(url), url))
    return sorted_urls[:20]


def _probe_js_bundles_ctx(url: str, body: str) -> dict[str, bool]:
    signals: dict[str, bool] = {}

    all_js_urls = extract_js_urls(body, url)

    for script_src in all_js_urls:
        scan = request_with_retries(
            script_src,
            allow_redirects=True,
        )
        if not scan.get("ok") or scan.get("status_code") != 200:
            continue
        js_content = scan.get("body", "") or scan.get("body_snippet", "")

        # React Router (v5/v6/v7) fingerprints
        has_v7_manifest = "__reactRouterManifest" in js_content or "__reactRouterContext" in js_content
        has_v7_pkg_literal = re.search(r"react-router(?:-dom)?@7", js_content) is not None
        has_v7_version = re.search(r'"7\.\d+\.\d+"', js_content) is not None and "react-router" in js_content.lower()
        has_v7_router = has_v7_manifest or has_v7_pkg_literal or (has_v7_version and "createBrowserRouter" in js_content)
        if has_v7_router:
            signals["react_router_v7_bundle"] = True

        has_react_router_pkg = "react-router-dom" in js_content or "react-router" in js_content.lower()
        has_v6_routes = has_react_router_pkg and "Routes" in js_content and "Route" in js_content and "Switch" not in js_content
        has_v6_data_router = has_react_router_pkg and ("createBrowserRouter" in js_content or "RouterProvider" in js_content)

        if not signals.get("react_router_v7_bundle"):
            if has_v6_data_router:
                signals["react_router_v6_bundle"] = True
            elif has_react_router_pkg and re.search(r'"6\.\d+\.\d+"', js_content) and "Routes" in js_content:
                signals["react_router_v6_bundle"] = True
            elif has_v6_routes:
                signals["react_router_v6_bundle"] = True

        if not signals.get("react_router_v6_bundle"):
            if has_react_router_pkg and ("BrowserRouter" in js_content or "browserRouter" in js_content) and "Switch" in js_content:
                signals["react_router_v5_bundle"] = True

        has_expo_router = "expo-router" in js_content and ("renderRouter" in js_content or "EXPO_ROUTER" in js_content)
        if has_expo_router:
            signals["expo_router"] = True

        js_lower = js_content.lower()
        has_react_dom = "react-dom" in js_lower
        has_rsc_runtime = "react-server-dom" in js_lower
        if has_react_dom:
            signals["react_dom_bundle"] = True
        if has_rsc_runtime:
            signals["react_server_dom_bundle"] = True
        if has_react_dom or has_rsc_runtime:
            signals["react_bundle"] = True

        has_vite_manifest = "vite" in js_content and "import.meta" in js_content
        if has_vite_manifest:
            signals["vite_assets"] = True

        if has_react_router_pkg or has_expo_router:
            break

    return signals


def probe_js_bundles(
    url: str,
    body: str,
    *,
    timeout: float | None = None,
    http_client: HttpClient | None = None,
) -> dict[str, bool]:
    if timeout is not None or http_client is not None:
        with scan_context(timeout=timeout, http_client=http_client):
            return _probe_js_bundles_ctx(url, body)
    return _probe_js_bundles_ctx(url, body)
