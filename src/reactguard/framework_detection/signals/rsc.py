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

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from ...http import scan_with_retry
from ...http.client import HttpClient
from ...utils import TagSet
from ...utils.context import scan_context
from ..constants import RSC_PROBE_FLIGHT_BODY_PATTERN
from .server_actions import probe_server_actions_support


@dataclass
class RscSignalApplier:
    """Stateful applier for folding RSC + server action probe results into tags/signals."""

    tags: TagSet
    signals: dict[str, Any]
    base_url: str | None
    rsc_tag: str | None = None
    server_actions_tag: str | None = None
    server_actions_imply_rsc: bool = False
    set_defaults: bool = False

    def apply(
        self,
        *,
        proxy_profile: str | None = None,
        correlation_id: str | None = None,
        http_client: HttpClient | None = None,
    ) -> dict[str, bool]:
        probe_result = {"rsc_endpoint_found": False, "server_actions_enabled": False}
        if self.base_url:
            if proxy_profile is not None or correlation_id is not None or http_client is not None:
                with scan_context(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client):
                    probe_result = probe_rsc_and_actions(self.base_url)
            else:
                probe_result = probe_rsc_and_actions(self.base_url)

        rsc_found = bool(probe_result.get("rsc_endpoint_found"))
        actions_found = bool(probe_result.get("server_actions_enabled"))
        promote_rsc = rsc_found or (self.server_actions_imply_rsc and actions_found)

        if promote_rsc:
            self.signals["rsc_endpoint_found"] = True
            if self.rsc_tag:
                self.tags.add(self.rsc_tag)
        elif self.set_defaults:
            self.signals.setdefault("rsc_endpoint_found", False)

        if actions_found:
            self.signals["server_actions_enabled"] = True
            if self.server_actions_tag:
                self.tags.add(self.server_actions_tag)
        elif self.set_defaults:
            self.signals.setdefault("server_actions_enabled", None)
            self.signals.setdefault("server_actions_confidence", "none")

        return {"rsc_endpoint_found": rsc_found, "server_actions_enabled": actions_found}


def _probe_rsc_endpoint_ctx(base_url: str) -> bool:
    if not base_url:
        return False

    rsc_url = urljoin(base_url, "/rsc")
    resp = scan_with_retry(
        rsc_url,
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


def probe_rsc_endpoint(
    base_url: str,
    *,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    http_client: HttpClient | None = None,
) -> bool:
    if proxy_profile is not None or correlation_id is not None or http_client is not None:
        with scan_context(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client):
            return _probe_rsc_endpoint_ctx(base_url)
    return _probe_rsc_endpoint_ctx(base_url)


def _probe_server_actions_ctx(base_url: str) -> bool:
    if not base_url:
        return False

    try:
        result_plain = probe_server_actions_support(
            base_url,
            action_id="probe",
            payload_style="plain",
        )
        if result_plain.get("supported"):
            return True

        result_multipart = probe_server_actions_support(
            base_url,
            action_id="probe",
            payload_style="multipart",
        )
        return bool(result_multipart.get("supported"))
    except Exception:
        return False


def probe_server_actions(
    base_url: str,
    *,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    http_client: HttpClient | None = None,
) -> bool:
    if proxy_profile is not None or correlation_id is not None or http_client is not None:
        with scan_context(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client):
            return _probe_server_actions_ctx(base_url)
    return _probe_server_actions_ctx(base_url)


def _probe_rsc_and_actions_ctx(base_url: str) -> dict[str, bool]:
    return {
        "rsc_endpoint_found": _probe_rsc_endpoint_ctx(base_url),
        "server_actions_enabled": _probe_server_actions_ctx(base_url),
    }


def probe_rsc_and_actions(
    base_url: str,
    *,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    http_client: HttpClient | None = None,
) -> dict[str, bool]:
    if proxy_profile is not None or correlation_id is not None or http_client is not None:
        with scan_context(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client):
            return _probe_rsc_and_actions_ctx(base_url)
    return _probe_rsc_and_actions_ctx(base_url)


def apply_rsc_probe_results(
    base_url: str | None,
    *,
    tags: TagSet,
    signals: dict[str, Any],
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    rsc_tag: str | None = None,
    server_actions_tag: str | None = None,
    server_actions_imply_rsc: bool = False,
    set_defaults: bool = False,
    http_client: HttpClient | None = None,
) -> dict[str, bool]:
    """
    Run the generic RSC + server action probes and fold the results into tags/signals.

    - Adds ``rsc_tag`` when the RSC endpoint is reachable (or when actions imply RSC).
    - Adds ``server_actions_tag`` when server actions are detected.
    - Optionally sets default False values when nothing is detected.
    """
    applier = RscSignalApplier(
        tags=tags,
        signals=signals,
        base_url=base_url,
        rsc_tag=rsc_tag,
        server_actions_tag=server_actions_tag,
        server_actions_imply_rsc=server_actions_imply_rsc,
        set_defaults=set_defaults,
    )
    return applier.apply(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client)
