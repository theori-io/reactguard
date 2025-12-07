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

"""RSC endpoint and server action probing."""

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from ...config import load_http_settings
from ...http import scan_with_retry
from ...utils import TagSet
from ..constants import RSC_PROBE_FLIGHT_BODY_PATTERN
from .server_actions import probe_server_actions_support


def probe_rsc_endpoint(
    base_url: str,
    *,
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> bool:
    if not base_url:
        return False

    rsc_url = urljoin(base_url, "/rsc")
    timeout = load_http_settings().timeout
    resp = scan_with_retry(
        rsc_url,
        timeout=timeout,
        proxy_profile=proxy_profile,
        correlation_id=correlation_id,
    )
    if not resp.get("ok") or resp.get("status_code") != 200:
        return False

    resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    resp_body = (resp.get("body") or resp.get("body_snippet") or "").strip()

    if resp_headers.get("content-type", "").startswith("text/x-component"):
        return True

    if resp_body and RSC_PROBE_FLIGHT_BODY_PATTERN.match(resp_body):
        return True

    return False


def probe_server_actions(
    base_url: str,
    *,
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> bool:
    if not base_url:
        return False

    try:
        result_plain = probe_server_actions_support(
            base_url,
            action_id="probe",
            payload_style="plain",
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
        )
        if result_plain.get("supported"):
            return True

        result_multipart = probe_server_actions_support(
            base_url,
            action_id="probe",
            payload_style="multipart",
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
        )
        return bool(result_multipart.get("supported"))
    except Exception:
        return False


def probe_rsc_and_actions(
    base_url: str,
    *,
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, bool]:
    return {
        "rsc_endpoint_found": probe_rsc_endpoint(
            base_url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
        ),
        "server_actions_enabled": probe_server_actions(
            base_url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
        ),
    }


def apply_rsc_probe_results(
    base_url: Optional[str],
    *,
    tags: TagSet,
    signals: Dict[str, Any],
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
    rsc_tag: Optional[str] = None,
    server_actions_tag: Optional[str] = None,
    server_actions_imply_rsc: bool = False,
    set_defaults: bool = False,
) -> Dict[str, bool]:
    """
    Run the generic RSC + server action probes and fold the results into tags/signals.

    - Adds ``rsc_tag`` when the RSC endpoint is reachable (or when actions imply RSC).
    - Adds ``server_actions_tag`` when server actions are detected.
    - Optionally sets default False values when nothing is detected.
    """
    probe_result = {"rsc_endpoint_found": False, "server_actions_enabled": False}
    if base_url:
        probe_result = probe_rsc_and_actions(
            base_url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
        )

    rsc_found = bool(probe_result.get("rsc_endpoint_found"))
    actions_found = bool(probe_result.get("server_actions_enabled"))
    promote_rsc = rsc_found or (server_actions_imply_rsc and actions_found)

    if promote_rsc:
        signals["rsc_endpoint_found"] = True
        if rsc_tag:
            tags.add(rsc_tag)
    elif set_defaults:
        signals.setdefault("rsc_endpoint_found", False)

    if actions_found:
        signals["server_actions_enabled"] = True
        if server_actions_tag:
            tags.add(server_actions_tag)
    elif set_defaults:
        signals.setdefault("server_actions_enabled", None)
        signals.setdefault("server_actions_confidence", "none")

    return {"rsc_endpoint_found": rsc_found, "server_actions_enabled": actions_found}
