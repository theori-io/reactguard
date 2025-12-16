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

"""Waku-specific probing for framework detection."""

import re
from urllib.parse import urljoin

from ...errors import categorize_exception
from ...http import request_with_retries
from ...http.client import HttpClient
from ...http.url import build_endpoint_candidates
from ...utils.context import scan_context
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


def _probe_waku_rsc_surface_ctx(base_url: str | None) -> bool:
    if not base_url:
        return False

    try:
        endpoint_paths: list[str] = ["/RSC/_", "/RSC/index.txt", "/RSC/index.rsc"]
        try:
            base_scan = request_with_retries(base_url, allow_redirects=True)
            if base_scan.get("ok") and (base_scan.get("status_code") or 0) == 200:
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
        except Exception:
            pass

        for endpoint_path in endpoint_paths[:12]:
            for probe_url in build_endpoint_candidates(base_url, endpoint_path):
                resp = request_with_retries(
                    probe_url,
                    allow_redirects=True,
                )
                if not resp.get("ok"):
                    continue

                status = resp.get("status_code", 0) or 0
                if status != 200:
                    continue

                body = resp.get("body") or resp.get("body_snippet", "")
                content_type = (resp.get("headers") or {}).get("content-type", "")

                # Waku Flight responses may start with module rows like `1:I[...]` before the main `0:{...}` row,
                # so detect any Flight-like row on any line.
                looks_flight = bool(re.search(r"^\d+:(?:I\[|\[|\{)", body, re.MULTILINE)) or bool(
                    SERVER_ACTIONS_FLIGHT_PATTERN.search(body)
                )
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
    *,
    http_client: HttpClient | None = None,
) -> bool:
    if http_client is not None:
        with scan_context(http_client=http_client):
            return _probe_waku_rsc_surface_ctx(base_url)
    return _probe_waku_rsc_surface_ctx(base_url)


def probe_waku_minimal_html(
    body: str,
    base_url: str | None,
    *,
    http_client: HttpClient | None = None,
) -> bool:
    if http_client is not None:
        with scan_context(http_client=http_client):
            return _probe_waku_minimal_html_ctx(body, base_url)
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
        js_url = urljoin(base_url, js_path)
        scan = request_with_retries(js_url, allow_redirects=True)
        if not scan.get("ok") or scan.get("status_code") != 200:
            return False

        js_body = scan.get("body") or scan.get("body_snippet", "")
        return "__WAKU_" in js_body or "__waku" in js_body.lower()
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
        )
        if not scan.get("ok"):
            return (
                False,
                0,
                [],
                {
                    "error_category": scan.get("error_category"),
                    "error_message": scan.get("error_message"),
                    "status_code": scan.get("status_code"),
                },
            )

        body = scan.get("body") or scan.get("body_snippet", "")
        has_react_action_forms = bool(re.search(r'action=["\']javascript:throw', body, re.IGNORECASE))
        has_actions = False

        for match in WAKU_RSC_ENDPOINT_PATTERN.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            ext = (match.group(3) or "txt").lower()
            endpoint = f"/RSC/F/{hash_id}/{action_name}.{ext}"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))
                has_actions = True

        for match in WAKU_RSC_DEV_ENDPOINT_PATTERN.finditer(body):
            file_path = match.group(1)
            action_name = match.group(2)
            ext = (match.group(3) or "txt").lower()
            endpoint = f"/RSC/F/_/{file_path}/{action_name}.{ext}"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))
                has_actions = True

        for match in WAKU_ACTION_ID_PATTERN_V021.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if not re.fullmatch(r"[A-Za-z0-9._:-]+", hash_id):
                continue
            endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))
                has_actions = True

        for match in WAKU_ACTION_ID_PATTERN_V025.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if len(hash_id) < 12:
                continue
            endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))
                has_actions = True

        for match in WAKU_RSC_PREFETCH_KEY_PATTERN.finditer(body):
            endpoint = match.group(1)
            leaf = endpoint.rstrip("/").split("/")[-1]
            action_name = leaf.split(".", 1)[0]
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))

        for match in WAKU_RSC_PREFETCH_ROUTE_KEY_PATTERN.finditer(body):
            route_key = match.group(1).lstrip("/")
            suffix = "" if route_key.endswith((".txt", ".rsc")) else ".txt"
            endpoint = f"/RSC/{route_key}{suffix}"
            leaf = endpoint.rstrip("/").split("/")[-1]
            action_name = leaf.split(".", 1)[0]
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))

        def _add_create_server_refs(text: str) -> None:
            nonlocal has_actions
            for match in WAKU_CREATE_SERVER_REF_PATTERN.finditer(text):
                file_path = match.group(1)
                file_norm = file_path.lstrip("/")
                action_name = match.group(2)
                action_id = f"ACTION_{file_path}/{action_name}"
                endpoint = f"/RSC/{action_id}.txt"
                if (endpoint, action_name) not in endpoints:
                    endpoints.append((endpoint, action_name))
                    has_actions = True
                dev_endpoint = f"/RSC/F/_/{file_norm}/{action_name}.txt"
                if (dev_endpoint, action_name) not in endpoints:
                    endpoints.append((dev_endpoint, action_name))
                    has_actions = True

        _add_create_server_refs(body)

        if not has_actions:
            js_files = list(set(WAKU_JS_FALLBACK_PATTERN.findall(body)))[:20]
            vite_virtuals = set(WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN.findall(body))
            for virt in vite_virtuals:
                js_files.append(virt)
            # `/src/actions.ts` is typically dev-only; only probe it when we see strong dev hints.
            if vite_virtuals:
                js_files.append("/src/actions.ts")

            for js_path in js_files:
                js_url = urljoin(base_url, js_path)
                js_scan = request_with_retries(
                    js_url,
                )
                if not js_scan.get("ok"):
                    continue

                js_body = js_scan.get("body") or js_scan.get("body_snippet", "")

                for match in WAKU_ACTION_LITERAL_PATTERN.finditer(js_body):
                    hash_id = match.group(1)
                    action_name = match.group(2)
                    if len(hash_id) < 12:
                        continue
                    endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
                    if (endpoint, action_name) not in endpoints:
                        endpoints.append((endpoint, action_name))
                        has_actions = True

                _add_create_server_refs(js_body)

                if has_actions:
                    break

        # `/RSC/<route>.txt` prefetch keys are an RSC mechanism and may exist even when server actions
        # are not enabled. Only treat those as action endpoints when we see React server action forms.
        if not has_actions and has_react_action_forms and endpoints:
            has_actions = True
        if not has_actions and has_react_action_forms and not endpoints:
            endpoints.append(("/RSC/index.txt", "index"))
            has_actions = True

        # Prefer concrete action endpoints over route-level RSC prefetch endpoints (e.g. `/RSC/R/_root.txt`),
        # since only the former are valid decode surfaces for server-action style probes and patch fingerprinting.
        explicit_action_endpoints = [
            (endpoint, action_name)
            for endpoint, action_name in endpoints
            if "/RSC/F/" in endpoint or "/RSC/ACTION_" in endpoint
        ]
        if explicit_action_endpoints:
            endpoints = explicit_action_endpoints
            has_actions = True
        count = len(endpoints)
        return (has_actions, count, endpoints)

    except Exception as exc:  # noqa: BLE001
        category = categorize_exception(exc).value
        return (
            False,
            0,
            [],
            {"error_category": category, "error_message": str(exc), "error_type": exc.__class__.__name__},
        )


def probe_waku_server_actions(
    base_url: str | None,
    *,
    http_client: HttpClient | None = None,
) -> tuple[bool, int] | tuple[bool, int, list[tuple[str, str]]] | tuple[bool, int, list[tuple[str, str]], dict[str, str | int | None]]:
    if http_client is not None:
        with scan_context(http_client=http_client):
            return _probe_waku_server_actions_ctx(base_url)
    return _probe_waku_server_actions_ctx(base_url)
