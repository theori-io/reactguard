# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared RSC probe send helpers."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from ..utils.context import scan_context
from .payloads import (
    RscReference,
    build_dec2025_marker_root_payload,
    build_dec2025_missing_chunk_payload,
    build_dec2025_nextjs_promise_chain_payload,
    build_dec2025_promise_chain_payload,
    build_dec2025_safe_control_payload,
    build_multipart_decode_payload,
    build_random_safe_prop,
)
from .send import send_rsc_request
from .types import RscRequestConfig, RscResponse


@contextmanager
def _optional_timeout(timeout: float | None):
    if timeout is None:
        yield
    else:
        with scan_context(timeout=timeout):
            yield


def probe_server_reference_markers(
    endpoint: str,
    *,
    request_config: RscRequestConfig,
    markers: Iterable[str] = ("h", "F"),
    safe_prop_prefix: str = "z",
    timeout: float | None = 3.0,
) -> dict[str, RscResponse]:
    """
    Probe multiple server-reference markers using a safe decodeReply payload.

    Returns a mapping of marker -> RscResponse.
    """
    safe_prop = build_random_safe_prop(prefix=safe_prop_prefix)
    results: dict[str, RscResponse] = {}
    for marker in markers:
        payload = build_multipart_decode_payload(
            RscReference(slot=1, root="x", prop=safe_prop, marker=marker)
        )
        with _optional_timeout(timeout):
            results[str(marker)] = send_rsc_request(endpoint, request_config, payload)
    return results


def send_dec2025_safe_control_probe(
    url: str,
    *,
    request_config: RscRequestConfig,
    action_id: str | None,
    prefix_parts: list[tuple[str, str]] | None = None,
) -> RscResponse:
    payload = build_dec2025_safe_control_payload(prefix_parts=prefix_parts)
    return send_rsc_request(url, request_config, payload, action_id=action_id)


def send_dec2025_missing_chunk_probe(
    url: str,
    *,
    request_config: RscRequestConfig,
    action_id: str | None,
    missing_chunk_id_hex: str = "ffff",
    prefix_parts: list[tuple[str, str]] | None = None,
) -> RscResponse:
    payload = build_dec2025_missing_chunk_payload(
        missing_chunk_id_hex=missing_chunk_id_hex,
        prefix_parts=prefix_parts,
    )
    return send_rsc_request(url, request_config, payload, action_id=action_id)


def send_dec2025_server_reference_marker_root_probe(
    url: str,
    *,
    request_config: RscRequestConfig,
    action_id: str | None,
    server_ref_marker: str,
    prefix_parts: list[tuple[str, str]] | None = None,
) -> RscResponse:
    payload = build_dec2025_marker_root_payload(
        server_ref_marker=server_ref_marker,
        prefix_parts=prefix_parts,
    )
    return send_rsc_request(url, request_config, payload, action_id=action_id)


def send_dec2025_nextjs_promise_chain_root_probe(
    url: str,
    *,
    request_config: RscRequestConfig,
    action_id: str,
    chain_depth: int,
    start_promise_id: int = 10,
    missing_chunk_id_hex: str = "ffff",
    prefix_parts: list[tuple[str, str]] | None = None,
) -> RscResponse:
    """
    Next.js-friendly PR#35351 fingerprint probe that forces the decoded root value to be a thenable chain.

    The chain resolves to a missing-chunk thenable so decode always terminates in a deterministic error
    before any Server Action invocation ("no-invoke").
    """
    if not action_id:
        raise ValueError("action_id is required for Next.js Server Action probes")
    payload = build_dec2025_nextjs_promise_chain_payload(
        chain_depth=chain_depth,
        start_promise_id=start_promise_id,
        missing_chunk_id_hex=missing_chunk_id_hex,
        prefix_parts=prefix_parts,
    )
    return send_rsc_request(url, request_config, payload, action_id=action_id)


def send_dec2025_promise_chain_probe(
    url: str,
    *,
    request_config: RscRequestConfig,
    action_id: str | None,
    chain_depth: int,
    prefix_parts: list[tuple[str, str]] | None = None,
) -> RscResponse:
    """
    Generic PR#35351 finite thenable-chain probe.

    Builds a finite ReactPromise chain and returns `$@1` via an outlined reference. This exercises
    the PR#35351 cycleProtection traversal without constructing true cycles (DoS-safe).
    """
    payload = build_dec2025_promise_chain_payload(
        chain_depth=chain_depth,
        prefix_parts=prefix_parts,
    )
    return send_rsc_request(url, request_config, payload, action_id=action_id)


__all__ = [
    "probe_server_reference_markers",
    "send_dec2025_missing_chunk_probe",
    "send_dec2025_nextjs_promise_chain_root_probe",
    "send_dec2025_promise_chain_probe",
    "send_dec2025_safe_control_probe",
    "send_dec2025_server_reference_marker_root_probe",
]
