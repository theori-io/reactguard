# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared orchestration helpers for running multi-action RSC probes."""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any, cast

from ..utils.context import get_http_settings, get_scan_context, scan_context
from .heuristics import RSC_CONTENT_TYPE
from .payloads import build_decode_payload_factories, build_safe_args_payload_factories
from .send import send_rsc_request
from .types import PayloadFactory, RscEndpointSpec, RscProbePayloads, RscProbePlan, RscRequestConfig, RscResponse


def _run_rsc_probe_plan_ctx(plan: RscProbePlan) -> tuple[list[RscResponse], RscResponse]:
    """
    Inner probe runner that relies on ambient ScanContext.

    Note: this runner relies on the ambient ScanContext (http client, etc.) set at scan boundaries.
    """
    if not plan.endpoints:
        raise ValueError("RscProbePlan.endpoints must be non-empty")

    endpoints = list(plan.endpoints)
    proto_results: list[RscResponse] = []

    for idx, action_id in enumerate(list(plan.action_ids)):
        endpoint = endpoints[idx % len(endpoints)]
        payload = plan.payloads.proto(action_id)
        result = send_rsc_request(
            endpoint.url,
            endpoint.request_config,
            payload,
            action_id=action_id,
        )
        proto_results.append(result)

    control_action_id = plan.control_action_id or plan.default_control_action_id
    control_endpoint = plan.control_endpoint or endpoints[plan.control_endpoint_index % len(endpoints)]
    control_payload = plan.payloads.control(control_action_id)
    control_result = send_rsc_request(
        control_endpoint.url,
        control_endpoint.request_config,
        control_payload,
        action_id=control_action_id,
    )

    return proto_results, control_result


def _is_transport_failure(result: RscResponse | None) -> bool:
    if result is None:
        return True
    if result.status_code is not None:
        return False
    return result.ok is False


def _all_transport_failures(proto_results: list[RscResponse], control_result: RscResponse | None) -> bool:
    if not proto_results:
        return False
    results = list(proto_results)
    if control_result is not None:
        results.append(control_result)
    return all(_is_transport_failure(r) for r in results)


def run_rsc_probe_plan(
    plan: RscProbePlan,
) -> tuple[list[RscResponse], RscResponse]:
    """
    Run a unified RSC probe plan.

    - Executes proto probes across `plan.action_ids`, round-robin across `plan.endpoints`.
    - Executes a single control probe against `plan.control_endpoint` (or the indexed endpoint).
    """
    proto_results, control_result = _run_rsc_probe_plan_ctx(plan)

    # Live targets (notably dev servers) can intermittently drop connections under load. When every
    # request fails at the transport layer, do a single bounded retry with a larger per-request timeout.
    if _all_transport_failures(cast(list[RscResponse], proto_results), cast(RscResponse, control_result)):
        settings = get_http_settings()
        context_timeout = get_scan_context().timeout
        base_timeout = context_timeout if context_timeout is not None else settings.timeout
        if base_timeout is None or base_timeout <= 0:
            base_timeout = 10.0
        retry_timeout = min(max(float(base_timeout), 10.0) * 2.0, 30.0)

        time.sleep(0.2)
        with scan_context(timeout=retry_timeout):
            return _run_rsc_probe_plan_ctx(plan)

    return proto_results, control_result


def run_rsc_action_probes(
    base_url: str,
    action_ids: Iterable[str],
    *,
    request_config: RscRequestConfig,
    proto_payload: PayloadFactory,
    control_payload: PayloadFactory,
    control_action_id: str | None = None,
    default_control_action_id: str = "control_probe",
    action_urls: list[str] | None = None,
    control_url: str | None = None,
) -> tuple[list[RscResponse], RscResponse]:
    """
    Run proto probes for a set of action IDs plus a single control probe.

    This is a framework-agnostic replacement for the older ActionProbeRunner:
    - per-framework differences live in `request_config` + payload factories.
    - per-action URL selection is supported via `action_urls`.
    """
    action_targets = list(action_urls or [])
    endpoint_urls = action_targets or [base_url]
    endpoints = [RscEndpointSpec(url=url, request_config=request_config) for url in endpoint_urls]
    control_endpoint = None
    if control_url:
        control_endpoint = RscEndpointSpec(url=control_url, request_config=request_config)

    plan = RscProbePlan(
        endpoints=endpoints,
        action_ids=list(action_ids),
        payloads=RscProbePayloads(proto=proto_payload, control=control_payload),
        control_action_id=control_action_id,
        default_control_action_id=default_control_action_id,
        control_endpoint=control_endpoint,
    )
    proto_results, control_result = run_rsc_probe_plan(plan)
    return cast(list[RscResponse], proto_results), cast(RscResponse, control_result)


def build_request_config(
    *,
    action_id_header: str | None,
    base_headers: dict[str, str] | None = None,
    method: str = "POST",
    allow_redirects: bool = True,
) -> RscRequestConfig:
    """
    Build a standard RSC probe request config with consistent Accept headers.
    """
    headers = {"Accept": RSC_CONTENT_TYPE}
    if base_headers:
        headers.update(base_headers)
    return RscRequestConfig(
        method=method,
        base_headers=headers,
        action_id_header=action_id_header,
        allow_redirects=allow_redirects,
    )


def run_decode_action_probes(
    base_url: str,
    action_ids: Iterable[str],
    *,
    request_config: RscRequestConfig,
    marker: str = "F",
    proto_prop: str = "__proto__",
    safe_prop_prefix: str = "z",
    proto_meta: dict[str, Any] | None = None,
    control_meta: dict[str, Any] | None = None,
    control_action_id: str | None = None,
    default_control_action_id: str = "control_probe",
    action_urls: list[str] | None = None,
    control_url: str | None = None,
) -> tuple[list[RscResponse], RscResponse]:
    """
    Run standard decodeReply probes using shared payload factories (proto/control).
    """
    proto_payload, control_payload = build_decode_payload_factories(
        marker=marker,
        proto_prop=proto_prop,
        safe_prop_prefix=safe_prop_prefix,
        proto_meta=proto_meta,
        control_meta=control_meta,
    )
    return run_rsc_action_probes(
        base_url,
        action_ids,
        request_config=request_config,
        proto_payload=proto_payload,
        control_payload=control_payload,
        control_action_id=control_action_id,
        default_control_action_id=default_control_action_id,
        action_urls=action_urls,
        control_url=control_url,
    )


def run_safe_args_action_probes(
    base_url: str,
    action_ids: Iterable[str],
    *,
    request_config: RscRequestConfig,
    wire_action_id: str,
    probe_targets: dict[str, str],
    safe_prop_prefix: str = "z",
    proto_meta: dict[str, Any] | None = None,
    control_meta: dict[str, Any] | None = None,
    control_action_id: str | None = None,
    default_control_action_id: str = "control_probe",
    action_urls: list[str] | None = None,
    control_url: str | None = None,
) -> tuple[list[RscResponse], RscResponse]:
    """
    Run safe-args multipart probes (React Router style) using shared payload factories.
    """
    proto_payload, control_payload = build_safe_args_payload_factories(
        wire_action_id=wire_action_id,
        probe_targets=probe_targets,
        safe_prop_prefix=safe_prop_prefix,
        proto_meta=proto_meta,
        control_meta=control_meta,
    )
    return run_rsc_action_probes(
        base_url,
        action_ids,
        request_config=request_config,
        proto_payload=proto_payload,
        control_payload=control_payload,
        control_action_id=control_action_id,
        default_control_action_id=default_control_action_id,
        action_urls=action_urls,
        control_url=control_url,
    )


__all__ = [
    "build_request_config",
    "run_decode_action_probes",
    "run_rsc_action_probes",
    "run_rsc_probe_plan",
    "run_safe_args_action_probes",
]
