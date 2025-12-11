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

from ...config import load_http_settings
from ...http import scan_with_retry
from ...http.client import HttpClient
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
    WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN,
)


def probe_waku_rsc_surface(
    base_url: str | None,
    *,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    http_client: HttpClient | None = None,
) -> bool:
    if not base_url:
        return False

    try:
        timeout = load_http_settings().timeout
        resp = scan_with_retry(
            urljoin(base_url, "/RSC/_"),
            allow_redirects=True,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            timeout=timeout,
            http_client=http_client,
        )
        if not resp.get("ok"):
            return False

        body = resp.get("body") or resp.get("body_snippet", "")
        content_type = (resp.get("headers") or {}).get("content-type", "")

        looks_flight = bool(SERVER_ACTIONS_FLIGHT_PATTERN.search(body))
        is_rsc_ct = "text/x-component" in content_type or "text/plain" in content_type

        return looks_flight or is_rsc_ct

    except Exception:
        return False


def probe_waku_minimal_html(
    body: str,
    base_url: str | None,
    *,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    http_client: HttpClient | None = None,
) -> bool:
    minimal_pattern = WAKU_MINIMAL_HTML_PATTERN.search(body.strip())
    if not minimal_pattern:
        return False

    if not base_url:
        return False

    try:
        timeout = load_http_settings().timeout
        resp = scan_with_retry(
            urljoin(base_url, "/RSC/"),
            allow_redirects=True,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            timeout=timeout,
            http_client=http_client,
        )
        status = resp.get("status_code", 0)
        content_type = (resp.get("headers") or {}).get("content-type", "")
        body_text = resp.get("body") or resp.get("body_snippet", "")
        looks_flight = bool(SERVER_ACTIONS_FLIGHT_PATTERN.search(body_text))
        is_rsc_ct = "text/x-component" in content_type
        return status == 200 and (looks_flight or is_rsc_ct)
    except Exception:
        return False


def probe_waku_server_actions(
    base_url: str | None,
    *,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    http_client: HttpClient | None = None,
) -> tuple[bool, int] | tuple[bool, int, list[tuple[str, str]]]:
    if not base_url:
        return False, 0

    endpoints: list[tuple[str, str]] = []
    timeout = load_http_settings().timeout

    try:
        scan = scan_with_retry(
            base_url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            timeout=timeout,
            http_client=http_client,
        )
        if not scan.get("ok"):
            return False, 0

        body = scan.get("body") or scan.get("body_snippet", "")

        for match in WAKU_RSC_ENDPOINT_PATTERN.finditer(body):
            endpoint = f"/RSC/F/{match.group(1)}/{match.group(2)}.txt"
            action_name = match.group(2)
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))

        for match in WAKU_RSC_DEV_ENDPOINT_PATTERN.finditer(body):
            file_path = match.group(1)
            action_name = match.group(2)
            endpoint = f"/RSC/F/_/{file_path}/{action_name}.txt"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))

        for match in WAKU_ACTION_ID_PATTERN_V021.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if not re.fullmatch(r"[A-Za-z0-9._:-]+", hash_id):
                continue
            endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))

        for match in WAKU_ACTION_ID_PATTERN_V025.finditer(body):
            hash_id = match.group(1)
            action_name = match.group(2)
            if len(hash_id) >= 12:
                endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
            if (endpoint, action_name) not in endpoints:
                endpoints.append((endpoint, action_name))

        def _add_create_server_refs(text: str) -> None:
            for match in WAKU_CREATE_SERVER_REF_PATTERN.finditer(text):
                file_path = match.group(1)
                file_norm = file_path.lstrip("/")
                action_name = match.group(2)
                action_id = f"ACTION_{file_path}/{action_name}"
                endpoint = f"/RSC/{action_id}.txt"
                if (endpoint, action_name) not in endpoints:
                    endpoints.append((endpoint, action_name))
                dev_endpoint = f"/RSC/F/_/{file_norm}/{action_name}.txt"
                if (dev_endpoint, action_name) not in endpoints:
                    endpoints.append((dev_endpoint, action_name))

        _add_create_server_refs(body)

        if not endpoints:
            js_files = list(set(WAKU_JS_FALLBACK_PATTERN.findall(body)))[:20]
            for virt in set(WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN.findall(body)):
                js_files.append(virt)
            js_files.append("/src/actions.ts")

            for js_path in js_files:
                js_url = urljoin(base_url, js_path)
                js_scan = scan_with_retry(
                    js_url,
                    proxy_profile=proxy_profile,
                    correlation_id=correlation_id,
                    timeout=timeout,
                    http_client=http_client,
                )
                if not js_scan.get("ok"):
                    continue

                js_body = js_scan.get("body") or js_scan.get("body_snippet", "")

                for match in WAKU_ACTION_LITERAL_PATTERN.finditer(js_body):
                    hash_id = match.group(1)
                    action_name = match.group(2)
                    endpoint = f"/RSC/F/{hash_id}/{action_name}.txt"
                    if (endpoint, action_name) not in endpoints:
                        endpoints.append((endpoint, action_name))

                _add_create_server_refs(js_body)

                if endpoints:
                    break

        has_actions = len(endpoints) > 0
        count = len(endpoints)
        return (has_actions, count, endpoints)

    except Exception:
        return False, 0
