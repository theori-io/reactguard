from __future__ import annotations

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

"""Expo Router (web) RSC / Server Functions probing helpers."""

import re
from dataclasses import dataclass

from ...http import request_with_retries
from ...http.url import build_endpoint_candidates, same_origin

_FLIGHT_LINE_RE = re.compile(r"^\d+:(?:I\[|\[|\{)", re.MULTILINE)
_BUNDLE_URL_RE = re.compile(r'"(/[^"\s]+?\.bundle\?[^"\s]+)"')
_ACTION_REF_RE = re.compile(r"(\./[^\"']+?\.(?:ts|tsx|js|jsx|mjs|cjs)#[_$A-Za-z0-9]+)")


@dataclass(frozen=True)
class ExpoProbeResult:
    has_rsc_surface: bool
    server_action_endpoints: list[str]
    evidence: dict[str, object]


def _probe_expo_flight_ctx(base_url: str) -> tuple[bool, str | None, str]:
    """
    Try to fetch the canonical Expo Router RSC flight payload for web.

    Returns:
      (ok, final_url, body)
    """
    for flight_url in build_endpoint_candidates(base_url, "/_flight/web/index.txt"):
        resp = request_with_retries(
            flight_url,
            headers={
                "Accept": "text/x-component",
                "expo-platform": "web",
            },
            allow_redirects=True,
        )
        if not resp.get("ok"):
            continue
        if (resp.get("status_code") or 0) != 200:
            continue
        final_url = str(resp.get("url") or flight_url)
        if final_url and not same_origin(base_url, final_url):
            continue
        body = str(resp.get("body") or resp.get("body_snippet") or "")
        if _FLIGHT_LINE_RE.search(body):
            return True, final_url, body
    return False, None, ""


def _extract_bundle_paths_from_flight(body: str, *, max_urls: int = 12) -> list[str]:
    urls: list[str] = []
    if not body:
        return urls
    for line in body.splitlines():
        if ":I[" not in line:
            continue
        for match in _BUNDLE_URL_RE.finditer(line):
            url = match.group(1)
            if url and url not in urls:
                urls.append(url)
                if len(urls) >= max_urls:
                    return urls
    return urls


def _discover_action_refs_from_bundles(base_url: str, bundle_paths: list[str]) -> list[str]:
    refs: list[str] = []
    if not base_url:
        return refs
    for bundle_path in bundle_paths:
        for candidate in build_endpoint_candidates(base_url, bundle_path)[:20]:
            resp = request_with_retries(candidate, allow_redirects=True)
            if not resp.get("ok") or (resp.get("status_code") or 0) != 200:
                continue
            final_url = str(resp.get("url") or candidate)
            if final_url and not same_origin(base_url, final_url):
                continue
            body = str(resp.get("body") or resp.get("body_snippet") or "")
            if not body:
                continue
            for match in _ACTION_REF_RE.finditer(body):
                ref = match.group(1)
                if ref and ref not in refs:
                    refs.append(ref)
            if refs:
                # Prefer the first module that contains action refs to keep this bounded.
                return refs
    return refs


def _action_ref_to_endpoint_path(ref: str) -> str | None:
    if not ref or "#" not in ref:
        return None
    file_path, export_name = ref.split("#", 1)
    file_path = file_path.strip()
    export_name = export_name.strip()
    if not file_path or not export_name:
        return None
    # Expo Router encodes action IDs as: ACTION_<filePath>/<export>.txt
    return f"/_flight/web/ACTION_{file_path}/{export_name}.txt"


def _probe_expo_server_functions_ctx(base_url: str) -> ExpoProbeResult:
    ok, flight_url, flight_body = _probe_expo_flight_ctx(base_url)
    bundle_paths = _extract_bundle_paths_from_flight(flight_body)
    action_refs = _discover_action_refs_from_bundles(base_url, bundle_paths)
    endpoint_paths = []
    for ref in action_refs:
        endpoint = _action_ref_to_endpoint_path(ref)
        if endpoint and endpoint not in endpoint_paths:
            endpoint_paths.append(endpoint)

    endpoints: list[str] = []
    for path in endpoint_paths:
        for candidate in build_endpoint_candidates(base_url, path):
            if candidate not in endpoints:
                endpoints.append(candidate)

    return ExpoProbeResult(
        has_rsc_surface=bool(ok),
        server_action_endpoints=endpoints,
        evidence={
            "flight_url": flight_url,
            "bundle_paths": bundle_paths,
            "action_refs": action_refs,
        },
    )


def probe_expo_server_functions(
    base_url: str | None,
) -> ExpoProbeResult:
    """
    Best-effort discovery of Expo Router (web) Server Functions endpoints.

    Notes:
    - Uses the framework-native Flight endpoint `/_flight/web/index.txt`.
    - Derives action endpoints by scanning RSC module bundles for action refs like `./path.ts#export`.
    """
    if not base_url:
        return ExpoProbeResult(has_rsc_surface=False, server_action_endpoints=[], evidence={})
    return _probe_expo_server_functions_ctx(base_url)


__all__ = ["ExpoProbeResult", "probe_expo_server_functions"]
