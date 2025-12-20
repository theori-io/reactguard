# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""JS bundle probing for framework detection."""

import re
from collections.abc import Iterable
from typing import Any
from ...http import request_with_retries
from ...http.headers import normalize_headers
from ...http.js import DEFAULT_MAX_JS_BYTES, extract_js_asset_urls
from ...utils import (
    DetectedVersion,
    derive_react_major,
    extract_versions,
    flatten_version_map,
    merge_version_maps,
    normalize_version_map,
)
from ...utils.context import scan_cache
from ...utils.version import update_version_pick
from ..keys import (
    SIG_BUNDLE_VERSIONS,
    SIG_DETECTED_VERSIONS,
    SIG_EXPO_ROUTER,
    SIG_REACT_BUNDLE,
    SIG_REACT_DOM_BUNDLE,
    SIG_REACT_ROUTER_V5_BUNDLE,
    SIG_REACT_ROUTER_V6_BUNDLE,
    SIG_REACT_ROUTER_V7_BUNDLE,
    SIG_REACT_SERVER_DOM_BUNDLE,
    SIG_VITE_ASSETS,
)

JS_BUNDLE_PROBE_CACHE_KEY = "js_bundle_probe_cache"


def _probe_js_bundles_ctx(url: str, body: str) -> dict[str, object]:
    signals: dict[str, object] = {}
    bundle_versions: dict[str, DetectedVersion] = {}

    all_js_urls = extract_js_asset_urls(body, url)
    total_bytes = 0

    for script_src in all_js_urls:
        scan = request_with_retries(
            script_src,
            allow_redirects=True,
        )
        if not scan.ok or scan.status_code != 200:
            continue
        js_content = scan.text or scan.body_snippet or ""
        total_bytes += len(js_content)
        if DEFAULT_MAX_JS_BYTES and total_bytes > DEFAULT_MAX_JS_BYTES:
            break
        js_headers = normalize_headers(scan.headers)

        try:
            extracted = extract_versions(js_headers, js_content, case_sensitive_body=True)
        except Exception:  # noqa: BLE001
            extracted = {}

        merge_version_maps(bundle_versions, extracted, prefer_semver=True)

        # React Router (v5/v6/v7) fingerprints.
        #
        # NOTE: Treat JS as case-sensitive text. Avoid `.lower()`/IGNORECASE matching so
        # we don't accidentally broaden heuristics beyond what the bundle actually contains.
        #
        # Many production bundles do not contain the literal package name `react-router`, but
        # v6.4+ often retains `@remix-run/router` (internal dependency).
        has_react_router_pkg = (
            "react-router-dom" in js_content
            or "react-router" in js_content
            or "@remix-run/router" in js_content
        )

        has_v7_manifest = "__reactRouterManifest" in js_content or "__reactRouterContext" in js_content
        has_v7_pkg_literal = re.search(r"react-router(?:-dom)?@7", js_content) is not None
        has_v7_version = re.search(r'"7\.\d+\.\d+"', js_content) is not None and has_react_router_pkg
        has_v7_router = has_v7_manifest or has_v7_pkg_literal or (has_v7_version and "createBrowserRouter" in js_content)
        if has_v7_router:
            signals[SIG_REACT_ROUTER_V7_BUNDLE] = True

        has_v6_routes = has_react_router_pkg and "Routes" in js_content and "Route" in js_content and "Switch" not in js_content
        has_v6_data_router = has_react_router_pkg and ("createBrowserRouter" in js_content or "RouterProvider" in js_content)

        if not signals.get(SIG_REACT_ROUTER_V7_BUNDLE):
            if "@remix-run/router" in js_content:
                signals[SIG_REACT_ROUTER_V6_BUNDLE] = True
            if has_v6_data_router:
                signals[SIG_REACT_ROUTER_V6_BUNDLE] = True
            elif has_react_router_pkg and re.search(r'"6\.\d+\.\d+"', js_content) and "Routes" in js_content:
                signals[SIG_REACT_ROUTER_V6_BUNDLE] = True
            elif has_v6_routes:
                signals[SIG_REACT_ROUTER_V6_BUNDLE] = True

        if not signals.get(SIG_REACT_ROUTER_V6_BUNDLE):
            if has_react_router_pkg and ("BrowserRouter" in js_content or "browserRouter" in js_content) and "Switch" in js_content:
                signals[SIG_REACT_ROUTER_V5_BUNDLE] = True

        has_expo_router = "expo-router" in js_content and ("renderRouter" in js_content or "EXPO_ROUTER" in js_content)
        if has_expo_router:
            signals[SIG_EXPO_ROUTER] = True

        has_react_dom = "react-dom" in js_content
        has_rsc_runtime = "react-server-dom" in js_content
        if has_react_dom:
            signals[SIG_REACT_DOM_BUNDLE] = True
        if has_rsc_runtime:
            signals[SIG_REACT_SERVER_DOM_BUNDLE] = True
        if has_react_dom or has_rsc_runtime:
            signals[SIG_REACT_BUNDLE] = True

        has_vite_manifest = "vite" in js_content and "import.meta" in js_content
        if has_vite_manifest:
            signals[SIG_VITE_ASSETS] = True

        # If we already found framework-identifying markers *and* extracted a React/RSC runtime version,
        # stop early to reduce bandwidth. Otherwise keep scanning since version literals may only exist
        # in vendor/runtime chunks.
        has_any_framework_hint = bool(has_react_router_pkg or has_expo_router)
        has_any_version = bool(bundle_versions.get("react_version") or bundle_versions.get("rsc_runtime_version"))
        if has_any_framework_hint and has_any_version:
            break

    # Derive `react_major` from the selected version pick to avoid inconsistent (react_version != react_major)
    # when multiple bundles include different React versions at equal confidence.
    bundle_versions.pop("react_major", None)
    derive_react_major(bundle_versions)

    normalized_versions = normalize_version_map(bundle_versions)
    signals[SIG_BUNDLE_VERSIONS] = {key: pick.to_mapping() for key, pick in normalized_versions.items()}
    signals.update(flatten_version_map(normalized_versions, prefix="bundle_"))

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
    detected_versions = normalize_version_map(signals.get(SIG_DETECTED_VERSIONS))
    bundle_versions = normalize_version_map(bundle_signals.get(SIG_BUNDLE_VERSIONS))

    if not bundle_versions:
        # Backfill from flattened keys when only legacy signals are present.
        for version_key in keys:
            value = bundle_signals.get(f"bundle_{version_key}")
            if value is None:
                continue
            bundle_versions[version_key] = DetectedVersion(
                value=value,
                source=bundle_signals.get(f"bundle_{version_key}_source"),
                confidence=bundle_signals.get(f"bundle_{version_key}_confidence"),
            )

    for version_key in keys:
        pick = bundle_versions.get(version_key)
        if not pick:
            continue
        source = f"bundle:{pick.source}" if pick.source else "bundle"
        update_version_pick(
            detected_versions,
            version_key,
            pick.value,
            source=source,
            confidence=pick.confidence,
            prefer_semver=True,
        )

    signals[SIG_DETECTED_VERSIONS] = {key: pick.to_mapping() for key, pick in detected_versions.items()}
    signals.update(flatten_version_map(detected_versions, prefix="detected_"))


def probe_js_bundles(
    url: str,
    body: str,
) -> dict[str, object]:
    cache = scan_cache("js_bundles", legacy_key=JS_BUNDLE_PROBE_CACHE_KEY)
    cache_key = str(url or "")
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return dict(cached)

    result = _probe_js_bundles_ctx(url, body)
    cache[cache_key] = dict(result)
    return result
