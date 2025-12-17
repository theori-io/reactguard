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
