# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Waku-specific probing for framework detection."""

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ...http import request_with_retries
from ...http.headers import header_value
from ...http.js import crawl_same_origin_js_modules
from ...http.url import build_endpoint_candidates, same_origin
from ..constants import (
    SERVER_ACTIONS_FLIGHT_PATTERN,
    WAKU_ACTION_ID_PATTERN_V021,
    WAKU_ACTION_ID_PATTERN_V025,
    WAKU_ACTION_LITERAL_PATTERN,
    WAKU_CREATE_SERVER_REF_PATTERN,
    WAKU_JS_FALLBACK_PATTERN,
    WAKU_MINIMAL_HTML_PATTERN,
    WAKU_RSC_DEV_ENDPOINT_PATTERN,
    WAKU_RSC_ENDPOINT_PATTERN,
    WAKU_RSC_PREFETCH_KEY_PATTERN,
    WAKU_RSC_PREFETCH_ROUTE_KEY_PATTERN,
    WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN,
)


def _candidate_same_origin_urls(base_url: str, raw: str) -> list[str]:
    if not raw:
        return []

    text = str(raw).strip()
    if not text:
        return []

    if text.startswith(("http://", "https://")):
        return [text] if same_origin(base_url, text) else []

    return build_endpoint_candidates(base_url, text)


def _extract_create_server_ref_endpoints(text: str) -> list[tuple[str, str]]:
    endpoints: list[tuple[str, str]] = []
    for match in WAKU_CREATE_SERVER_REF_PATTERN.finditer(text or ""):
        file_path_raw = match.group(1)
        action_name = match.group(2)
        file_path = urlparse(file_path_raw).path or file_path_raw
        action_id = f"ACTION_{file_path}/{action_name}"
        endpoints.append((f"/RSC/{action_id}.txt", action_name))
        file_norm = file_path.lstrip("/")
        endpoints.append((f"/RSC/F/_/{file_norm}/{action_name}.txt", action_name))
    return endpoints


def _discover_waku_action_endpoints_from_js(
    effective_base_url: str,
    html: str,
    *,
    max_modules: int = 20,
) -> list[tuple[str, str]]:
    if not effective_base_url or not html or max_modules <= 0:
        return []

    seed_paths: list[str] = []
    seed_paths.extend([m for m in WAKU_JS_FALLBACK_PATTERN.findall(html) if m])
    seed_paths.extend([m for m in WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN.findall(html) if m])
    seed_paths = list(dict.fromkeys(seed_paths))

    def _fetch(url: str):
        return request_with_retries(url, allow_redirects=True)

    modules = crawl_same_origin_js_modules(
        effective_base_url,
        seed_paths,
        fetch=_fetch,
        max_modules=max_modules,
        extra_url_patterns=(WAKU_JS_FALLBACK_PATTERN, WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN),
    )

    endpoints: list[tuple[str, str]] = []
    seen_endpoints: set[tuple[str, str]] = set()

    def _add(endpoint: str, action_name: str) -> None:
        pair = (endpoint, action_name)
        if pair in seen_endpoints:
            return
        seen_endpoints.add(pair)
        endpoints.append(pair)

    for module in modules:
        body = module.body

        for match in WAKU_RSC_ENDPOINT_PATTERN.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            _add(f"/RSC/F/{hash_id}/{action_name}.txt", action_name)

        for match in WAKU_RSC_DEV_ENDPOINT_PATTERN.finditer(body):
            file_path = match.group(1)
            action_name = match.group(2)
            _add(f"/RSC/F/_/{file_path}/{action_name}.txt", action_name)

        for match in WAKU_ACTION_LITERAL_PATTERN.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if len(hash_id) < 12:
                continue
            _add(f"/RSC/F/{hash_id}/{action_name}.txt", action_name)

        for endpoint, action_name in _extract_create_server_ref_endpoints(body):
            _add(endpoint, action_name)

    return endpoints


def _probe_waku_rsc_surface_ctx(base_url: str | None) -> bool:
    if not base_url:
        return False

    try:
        # Waku sometimes serves Flight at `/RSC/index.rsc` even when the base HTML only references `.txt` routes.
        endpoint_paths: list[str] = ["/RSC/_", "/RSC/index.txt", "/RSC/index.rsc"]
        try:
            base_scan = request_with_retries(base_url, allow_redirects=True)
            if base_scan.get("ok") and (base_scan.get("status_code") or 0) == 200:
                effective_base_url = str(base_scan.get("url") or base_url)
                base_body = base_scan.get("body") or base_scan.get("body_snippet", "")
                for match in WAKU_RSC_PREFETCH_KEY_PATTERN.finditer(base_body):
                    endpoint = match.group(1)
                    if endpoint and endpoint not in endpoint_paths:
                        endpoint_paths.append(endpoint)
                for match in WAKU_RSC_PREFETCH_ROUTE_KEY_PATTERN.finditer(base_body):
                    route_key = match.group(1).lstrip("/")
                    suffix = "" if route_key.endswith((".txt", ".rsc")) else ".txt"
                    endpoint = f"/RSC/{route_key}{suffix}"
                    if endpoint not in endpoint_paths:
                        endpoint_paths.append(endpoint)
            else:
                effective_base_url = str(base_url)
        except Exception:
            effective_base_url = str(base_url)

        for endpoint_path in endpoint_paths[:20]:
            for probe_url in build_endpoint_candidates(effective_base_url, endpoint_path):
                resp = request_with_retries(
                    probe_url,
                    allow_redirects=True,
                )
                if not resp.get("ok"):
                    continue

                final_url = str(resp.get("url") or probe_url)
                if final_url and not same_origin(effective_base_url, final_url):
                    continue

                status = resp.get("status_code", 0) or 0
                if status != 200:
                    continue

                body = resp.get("body") or resp.get("body_snippet", "")
                content_type = header_value(resp.get("headers") or {}, "content-type")

                # Waku Flight responses may start with module rows like `1:I[...]` before the main `0:{...}` row,
                # so detect any Flight-like row on any line.
                looks_flight = bool(re.search(r"^\d+:(?:I\[|\[|\{)", body, re.MULTILINE)) or bool(SERVER_ACTIONS_FLIGHT_PATTERN.search(body))
                content_type_lower = content_type.lower()
                is_rsc_ct = "text/x-component" in content_type_lower
                # Note: Waku may respond with Flight in text/plain, but text/plain alone is too common
                # on non-Waku sites (e.g., 404 bodies), so don't treat it as a positive signal by itself.
                if looks_flight or is_rsc_ct:
                    return True

        return False

    except Exception:
        return False


def probe_waku_rsc_surface(
    base_url: str | None,
) -> bool:
    return _probe_waku_rsc_surface_ctx(base_url)


def probe_waku_minimal_html(
    body: str,
    base_url: str | None,
) -> bool:
    return _probe_waku_minimal_html_ctx(body, base_url)


def _probe_waku_minimal_html_ctx(body: str, base_url: str | None) -> bool:
    minimal_pattern = WAKU_MINIMAL_HTML_PATTERN.search(body.strip())
    if not minimal_pattern:
        return False

    if not base_url:
        return False

    try:
        match = re.search(r'import\(["\']([^"\']+)["\']\)', body)
        if not match:
            return False

        js_path = match.group(1)
        for js_url in _candidate_same_origin_urls(base_url, js_path)[:20]:
            scan = request_with_retries(js_url, allow_redirects=True)
            if not scan.get("ok") or scan.get("status_code") != 200:
                continue
            final_url = str(scan.get("url") or js_url)
            if final_url and not same_origin(base_url, final_url):
                continue

            js_body = scan.get("body") or scan.get("body_snippet", "")
            return "__WAKU_" in js_body or "__waku" in js_body.lower()

        return False
    except Exception:
        return False


def _probe_waku_server_actions_ctx(
    base_url: str | None,
) -> tuple[bool, int] | tuple[bool, int, list[tuple[str, str]]] | tuple[bool, int, list[tuple[str, str]], dict[str, str | int | None]]:
    if not base_url:
        return False, 0

    endpoints: list[tuple[str, str]] = []

    try:
        scan = request_with_retries(
            base_url,
            allow_redirects=True,
        )
        if not scan.get("ok"):
            return (
                False,
                0,
                [],
                {
                    "error_message": scan.get("error_message"),
                    "error_type": scan.get("error_type"),
                    "status_code": scan.get("status_code"),
                },
            )

        effective_base_url = str(scan.get("url") or base_url)
        body = scan.get("body") or scan.get("body_snippet", "")
        action_endpoints: list[tuple[str, str]] = []
        prefetch_endpoints: list[tuple[str, str]] = []

        def _add_endpoint(endpoint: str, action_name: str, *, is_action: bool) -> None:
            pair = (endpoint, action_name)
            if pair not in endpoints:
                endpoints.append(pair)
            if is_action and pair not in action_endpoints:
                action_endpoints.append(pair)

        for match in WAKU_RSC_ENDPOINT_PATTERN.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            _add_endpoint(endpoint, action_name, is_action=True)

        for match in WAKU_RSC_DEV_ENDPOINT_PATTERN.finditer(body):
            file_path = match.group(1)
            action_name = match.group(2)
            endpoint = f"/RSC/F/_/{file_path}/{action_name}.txt"
            _add_endpoint(endpoint, action_name, is_action=True)

        for match in WAKU_ACTION_ID_PATTERN_V021.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if not re.fullmatch(r"[A-Za-z0-9._:-]+", hash_id):
                continue
            endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            _add_endpoint(endpoint, action_name, is_action=True)

        for match in WAKU_ACTION_ID_PATTERN_V025.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if len(hash_id) < 12:
                continue
            endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            _add_endpoint(endpoint, action_name, is_action=True)

        for match in WAKU_RSC_PREFETCH_KEY_PATTERN.finditer(body):
            endpoint = match.group(1)
            leaf = endpoint.rstrip("/").split("/")[-1]
            action_name = leaf.split(".", 1)[0]
            prefetch_endpoints.append((endpoint, action_name))

        for match in WAKU_RSC_PREFETCH_ROUTE_KEY_PATTERN.finditer(body):
            route_key = match.group(1).lstrip("/")
            suffix = "" if route_key.endswith((".txt", ".rsc")) else ".txt"
            endpoint = f"/RSC/{route_key}{suffix}"
            leaf = endpoint.rstrip("/").split("/")[-1]
            action_name = leaf.split(".", 1)[0]
            prefetch_endpoints.append((endpoint, action_name))

        for endpoint, action_name in prefetch_endpoints:
            _add_endpoint(endpoint, action_name, is_action=False)

        for endpoint, action_name in _extract_create_server_ref_endpoints(body):
            _add_endpoint(endpoint, action_name, is_action=True)

        if not action_endpoints:
            for endpoint, action_name in _discover_waku_action_endpoints_from_js(effective_base_url, body, max_modules=20):
                _add_endpoint(endpoint, action_name, is_action=True)

        if action_endpoints:
            endpoints = action_endpoints
        has_actions = bool(action_endpoints)

        count = len(endpoints)
        return (has_actions, count, endpoints)

    except Exception as exc:  # noqa: BLE001
        return (
            False,
            0,
            [],
            {"error_message": str(exc), "error_type": exc.__class__.__name__},
        )


def probe_waku_server_actions(
    base_url: str | None,
) -> tuple[bool, int] | tuple[bool, int, list[tuple[str, str]]] | tuple[bool, int, list[tuple[str, str]], dict[str, str | int | None]]:
    return _probe_waku_server_actions_ctx(base_url)


@dataclass(frozen=True)
class WakuServerActionsProbeResult:
    """Normalized view of `probe_waku_server_actions` output."""

    has_actions: bool
    count: int = 0
    endpoints: list[tuple[str, str]] = field(default_factory=list)
    error_info: dict[str, Any] | None = None


def probe_waku_server_actions_result(
    base_url: str | None,
) -> WakuServerActionsProbeResult:
    """Return a stable-shaped result for Waku Server Actions discovery."""
    raw = probe_waku_server_actions(base_url)
    if not isinstance(raw, tuple):
        return WakuServerActionsProbeResult(has_actions=bool(raw))

    has_actions = bool(raw[0]) if len(raw) > 0 else False

    count = 0
    if len(raw) > 1:
        try:
            count = int(raw[1] or 0)
        except (TypeError, ValueError):
            count = 0

    endpoints: list[tuple[str, str]] = []
    if len(raw) > 2 and isinstance(raw[2], list):
        endpoints = list(raw[2])

    error_info = dict(raw[3]) if len(raw) > 3 and isinstance(raw[3], dict) else None

    return WakuServerActionsProbeResult(
        has_actions=has_actions,
        count=count,
        endpoints=endpoints,
        error_info=error_info,
    )
