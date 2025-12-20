# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared RSC wire-format helpers (payload generation + sending)."""

from .payloads import (
    RscReference,
    build_decode_payload_factories,
    build_dec2025_marker_root_payload,
    build_dec2025_missing_chunk_payload,
    build_dec2025_nextjs_promise_chain_payload,
    build_dec2025_promise_chain_payload,
    build_dec2025_safe_control_payload,
    build_json_decode_payload,
    build_multipart_decode_payload,
    build_nextjs_action_multipart_payload,
    build_nextjs_action_payload_factories,
    build_no_invoke_temp_ref_payload,
    build_plaintext_decode_payload,
    build_plaintext_payload,
    build_safe_args_payload_factories,
)
from .runner import (
    build_request_config,
    run_decode_action_probes,
    run_rsc_action_probes,
    run_rsc_probe_plan,
    run_safe_args_action_probes,
)
from .send import send_rsc_request
from .types import RscEndpointSpec, RscPayload, RscProbePayloads, RscProbePlan, RscRequestConfig, RscResponse, RscWireFormat

__all__ = [
    "RscPayload",
    "RscReference",
    "RscRequestConfig",
    "RscResponse",
    "RscEndpointSpec",
    "RscProbePlan",
    "RscProbePayloads",
    "RscWireFormat",
    "build_decode_payload_factories",
    "build_dec2025_marker_root_payload",
    "build_dec2025_missing_chunk_payload",
    "build_dec2025_nextjs_promise_chain_payload",
    "build_dec2025_promise_chain_payload",
    "build_dec2025_safe_control_payload",
    "build_json_decode_payload",
    "build_multipart_decode_payload",
    "build_nextjs_action_multipart_payload",
    "build_nextjs_action_payload_factories",
    "build_no_invoke_temp_ref_payload",
    "build_plaintext_decode_payload",
    "build_plaintext_payload",
    "build_safe_args_payload_factories",
    "build_request_config",
    "run_decode_action_probes",
    "run_rsc_action_probes",
    "run_rsc_probe_plan",
    "run_safe_args_action_probes",
    "send_rsc_request",
]
