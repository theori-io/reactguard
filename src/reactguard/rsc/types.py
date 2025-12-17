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

"""Types for framework-agnostic RSC request construction."""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypedDict

from typing_extensions import NotRequired


class RscWireFormat(str, Enum):
    """High-level request body encoding used for RSC/Server Functions probes."""

    MULTIPART_FORM = "multipart-form"
    JSON = "json"
    TEXT = "text"


@dataclass(frozen=True)
class RscPayload:
    """A request body with the minimal headers required to transmit it."""

    wire_format: RscWireFormat
    headers: dict[str, str]
    body: str | bytes
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RscRequestConfig:
    """Per-framework request configuration (endpoint-independent)."""

    method: str = "POST"
    base_headers: dict[str, str] = field(default_factory=dict)
    action_id_header: str | None = None
    allow_redirects: bool = True


class RscHttpResult(TypedDict):
    """
    Normalized HTTP result produced by `send_rsc_request`.

    This is a request_with_retries-compatible mapping with additional RSC metadata.
    """

    ok: bool
    status_code: int | None
    headers: dict[str, Any]
    body: str
    body_snippet: str
    url: str
    error_message: NotRequired[str | None]
    error_type: NotRequired[str | None]
    error: NotRequired[str | None]
    endpoint: str
    action_id: NotRequired[str | None]
    request_wire_format: str
    payload_meta: NotRequired[dict[str, Any]]


PayloadFactory = Callable[[str], RscPayload]


@dataclass(frozen=True)
class RscEndpointSpec:
    """Concrete endpoint + request configuration for an RSC probe."""

    url: str
    request_config: RscRequestConfig
    name: str | None = None


@dataclass(frozen=True)
class RscProbePayloads:
    """Payload factories for proto/control (and optional confirm) probes."""

    proto: PayloadFactory
    control: PayloadFactory
    confirm: PayloadFactory | None = None


@dataclass(frozen=True)
class RscProbePlan:
    """A unified, framework-agnostic plan for running RSC action probes."""

    endpoints: list[RscEndpointSpec]
    action_ids: list[str]
    payloads: RscProbePayloads
    control_action_id: str | None = None
    default_control_action_id: str = "control_probe"
    control_endpoint: RscEndpointSpec | None = None
    control_endpoint_index: int = 0
