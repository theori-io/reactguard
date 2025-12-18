# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared orchestration helpers for running multi-action RSC probes."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

from .send import send_rsc_request
from .types import PayloadFactory, RscEndpointSpec, RscHttpResult, RscProbePayloads, RscProbePlan, RscRequestConfig


def _run_rsc_probe_plan_ctx(plan: RscProbePlan) -> tuple[list[RscHttpResult], RscHttpResult]:
    """
    Inner probe runner that relies on ambient ScanContext.

    Note: this runner relies on the ambient ScanContext (http client, etc.) set at scan boundaries.
    """
    if not plan.endpoints:
        raise ValueError("RscProbePlan.endpoints must be non-empty")

    endpoints = list(plan.endpoints)
    proto_results: list[RscHttpResult] = []

    for idx, action_id in enumerate(list(plan.action_ids)):
        endpoint = endpoints[idx % len(endpoints)]
        payload = plan.payloads.proto(action_id)
        result = send_rsc_request(
            endpoint.url,
            endpoint.request_config,
            payload,
            action_id=action_id,
        )
        result.setdefault("action_id", action_id)
        result.setdefault("endpoint", endpoint.url)
        result.setdefault("request_wire_format", str(payload.wire_format.value))
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
    control_result.setdefault("action_id", control_action_id)
    control_result.setdefault("endpoint", control_endpoint.url)
    control_result.setdefault("request_wire_format", str(control_payload.wire_format.value))

    return proto_results, control_result


def run_rsc_probe_plan(
    plan: RscProbePlan,
) -> tuple[list[RscHttpResult], RscHttpResult]:
    """
    Run a unified RSC probe plan.

    - Executes proto probes across `plan.action_ids`, round-robin across `plan.endpoints`.
    - Executes a single control probe against `plan.control_endpoint` (or the indexed endpoint).
    """
    return _run_rsc_probe_plan_ctx(plan)


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
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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
    return cast(list[dict[str, Any]], proto_results), cast(dict[str, Any], control_result)


__all__ = ["run_rsc_action_probes", "run_rsc_probe_plan"]
