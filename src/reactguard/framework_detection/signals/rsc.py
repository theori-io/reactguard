# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RSC endpoint and server action probing."""

from dataclasses import dataclass
from typing import Any

from ...http import request_with_retries
from ...http.headers import normalize_headers
from ...utils import TagSet
from ..constants import RSC_PROBE_FLIGHT_BODY_PATTERN
from ..keys import SIG_INVOCATION_CONFIDENCE, SIG_INVOCATION_ENABLED, SIG_RSC_ENDPOINT_FOUND
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
    ) -> dict[str, bool]:
        probe_result = {"rsc_endpoint_found": False, "invocation_enabled": False}
        if self.base_url:
            probe_result = probe_rsc_and_actions(self.base_url)

        rsc_found = bool(probe_result.get("rsc_endpoint_found"))
        actions_found = bool(probe_result.get("invocation_enabled"))
        promote_rsc = rsc_found or (self.server_actions_imply_rsc and actions_found)

        if promote_rsc:
            self.signals[SIG_RSC_ENDPOINT_FOUND] = True
            if self.rsc_tag:
                self.tags.add(self.rsc_tag)
        elif self.set_defaults:
            self.signals.setdefault(SIG_RSC_ENDPOINT_FOUND, False)

        if actions_found:
            self.signals[SIG_INVOCATION_ENABLED] = True
            if self.server_actions_tag:
                self.tags.add(self.server_actions_tag)
        elif self.set_defaults:
            self.signals.setdefault(SIG_INVOCATION_ENABLED, None)
            self.signals.setdefault(SIG_INVOCATION_CONFIDENCE, "none")

        return {"rsc_endpoint_found": rsc_found, "invocation_enabled": actions_found}


def _probe_rsc_endpoint_ctx(endpoint_url: str) -> bool:
    """
    Probe a specific URL and return True if it appears to serve RSC Flight responses.

    Note: This intentionally does not guess framework endpoints (e.g. `/rsc`). Callers should
    provide a concrete endpoint URL discovered via framework-native signals.
    """
    if not endpoint_url:
        return False

    resp = request_with_retries(endpoint_url)
    if not resp.get("ok") or resp.get("status_code") != 200:
        return False

    resp_headers = normalize_headers(resp.get("headers"))
    resp_body = (resp.get("body") or resp.get("body_snippet") or "").strip()

    if resp_headers.get("content-type", "").startswith("text/x-component"):
        return True

    if resp_body and RSC_PROBE_FLIGHT_BODY_PATTERN.match(resp_body):
        return True

    return False


def probe_rsc_endpoint(
    endpoint_url: str,
) -> bool:
    return _probe_rsc_endpoint_ctx(endpoint_url)


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
) -> bool:
    return _probe_server_actions_ctx(base_url)


def _probe_rsc_and_actions_ctx(base_url: str) -> dict[str, bool]:
    return {
        "rsc_endpoint_found": _probe_rsc_endpoint_ctx(base_url),
        "invocation_enabled": _probe_server_actions_ctx(base_url),
    }


def probe_rsc_and_actions(
    base_url: str,
) -> dict[str, bool]:
    return _probe_rsc_and_actions_ctx(base_url)


def apply_rsc_probe_results(
    base_url: str | None,
    *,
    tags: TagSet,
    signals: dict[str, Any],
    rsc_tag: str | None = None,
    server_actions_tag: str | None = None,
    server_actions_imply_rsc: bool = False,
    set_defaults: bool = False,
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
    return applier.apply()
