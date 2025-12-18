# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared RSC wire-format helpers (payload generation + sending)."""

from .payloads import (
    RscReference,
    build_json_decode_payload,
    build_multipart_decode_payload,
    build_nextjs_action_multipart_payload,
    build_plaintext_decode_payload,
    build_plaintext_payload,
)
from .runner import run_rsc_action_probes, run_rsc_probe_plan
from .send import send_rsc_request
from .types import RscEndpointSpec, RscHttpResult, RscPayload, RscProbePayloads, RscProbePlan, RscRequestConfig, RscWireFormat

__all__ = [
    "RscPayload",
    "RscReference",
    "RscRequestConfig",
    "RscHttpResult",
    "RscEndpointSpec",
    "RscProbePlan",
    "RscProbePayloads",
    "RscWireFormat",
    "build_json_decode_payload",
    "build_multipart_decode_payload",
    "build_nextjs_action_multipart_payload",
    "build_plaintext_decode_payload",
    "build_plaintext_payload",
    "run_rsc_action_probes",
    "run_rsc_probe_plan",
    "send_rsc_request",
]
