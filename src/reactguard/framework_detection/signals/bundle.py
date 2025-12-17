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
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

from ...http import request_with_retries
from ...http.url import build_base_dir_url, build_endpoint_candidates, same_origin
from ...utils import extract_versions, parse_semver
from ...utils.confidence import confidence_score


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


def _semver_rank(value: object) -> tuple[int, int, int, int, str]:
    """
    Rank a semver-ish string for tie-breaking (when confidence scores are equal).

    We bias toward stable releases over canary/rc markers to reduce false positives from
    unrelated bundles that may embed prerelease strings.
    """
    parsed = parse_semver(str(value)) if value is not None else None
    if not parsed:
        return (0, 0, 0, 0, "")

    suffix = str(parsed.suffix or "").lower()
    if not suffix:
        suffix_rank = 3
    elif "canary" in suffix:
        suffix_rank = 2
    elif "rc" in suffix:
        suffix_rank = 0
    else:
        suffix_rank = 1

    return (suffix_rank, parsed.major, parsed.minor, parsed.patch, suffix)


def _prefer_semver(existing: object, candidate: object) -> bool:
    """Return True if candidate should replace existing for equal-confidence version picks."""
    return _semver_rank(candidate) > _semver_rank(existing)


def _probe_js_bundles_ctx(url: str, body: str) -> dict[str, object]:
    signals: dict[str, object] = {}
    bundle_versions: dict[str, object] = {}

    all_js_urls = extract_js_urls(body, url)

    for script_src in all_js_urls:
        scan = request_with_retries(
            script_src,
            allow_redirects=True,
        )
        if not scan.get("ok") or scan.get("status_code") != 200:
            continue
        js_content = scan.get("body", "") or scan.get("body_snippet", "")
        js_headers = {str(k).lower(): str(v) for k, v in (scan.get("headers") or {}).items() if k is not None}

        try:
            extracted = extract_versions(js_headers, js_content)
        except Exception:  # noqa: BLE001
            extracted = {}

        for version_key in ("react_version", "rsc_runtime_version", "next_version", "waku_version", "react_router_version", "react_major"):
            value = extracted.get(version_key)
            if value is None:
                continue
            new_conf = extracted.get(f"{version_key}_confidence")
            current_conf = bundle_versions.get(f"{version_key}_confidence")
            new_score = confidence_score(str(new_conf) if new_conf is not None else None)
            current_score = confidence_score(str(current_conf) if current_conf is not None else None)
            should_set = False
            if version_key not in bundle_versions:
                should_set = True
            elif new_score > current_score:
                should_set = True
            elif new_score == current_score and version_key != "react_major":
                # Prefer better semver candidates when confidence is tied (e.g., stable 19.0.2 over 19.0.0-rc...).
                should_set = _prefer_semver(bundle_versions.get(version_key), value)

            if should_set:
                bundle_versions[version_key] = value
                if extracted.get(f"{version_key}_confidence") is not None:
                    bundle_versions[f"{version_key}_confidence"] = extracted.get(f"{version_key}_confidence")
                if extracted.get(f"{version_key}_source") is not None:
                    bundle_versions[f"{version_key}_source"] = extracted.get(f"{version_key}_source")

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

        # If we already found framework-identifying markers *and* extracted a React/RSC runtime version,
        # stop early to reduce bandwidth. Otherwise keep scanning since version literals may only exist
        # in vendor/runtime chunks.
        has_any_framework_hint = bool(has_react_router_pkg or has_expo_router)
        has_any_version = bool(bundle_versions.get("react_version") or bundle_versions.get("rsc_runtime_version"))
        if has_any_framework_hint and has_any_version:
            break

    for key, value in bundle_versions.items():
        signals[f"bundle_{key}"] = value

    return signals


def promote_bundle_versions(
    signals: dict[str, Any],
    bundle_signals: dict[str, Any],
    *,
    keys: Iterable[str],
) -> None:
    """
    Promote `bundle_*` version markers into the canonical `detected_*` namespace.

    Detectors often rely on HTML heuristics first, then refine/confirm versions from JS bundles.
    This helper keeps the promotion logic consistent across detectors.
    """
    for version_key in keys:
        value = bundle_signals.get(f"bundle_{version_key}")
        if value is None:
            continue
        bundle_conf = str(bundle_signals.get(f"bundle_{version_key}_confidence") or "medium")
        detected_conf = str(signals.get(f"detected_{version_key}_confidence") or "none")
        if signals.get(f"detected_{version_key}") is None or confidence_score(bundle_conf) > confidence_score(detected_conf):
            signals[f"detected_{version_key}"] = value
            signals[f"detected_{version_key}_confidence"] = bundle_conf
            source = bundle_signals.get(f"bundle_{version_key}_source")
            if source:
                signals[f"detected_{version_key}_source"] = f"bundle:{source}"


def probe_js_bundles(
    url: str,
    body: str,
) -> dict[str, object]:
    return _probe_js_bundles_ctx(url, body)
