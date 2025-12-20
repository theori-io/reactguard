# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Types for framework-agnostic RSC request construction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..http.models import HttpResponse


class RscWireFormat(str, Enum):
    """High-level request body encoding used for RSC Flight protocol probes."""

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


@dataclass
class RscResponse(HttpResponse):
    """HTTP response plus RSC request metadata."""

    endpoint: str = ""
    action_id: str | None = None
    request_wire_format: str = ""
    payload_meta: dict[str, Any] = field(default_factory=dict)

    def to_mapping(self) -> dict[str, Any]:
        base = super().to_mapping()
        base.update(
            {
                "endpoint": self.endpoint,
                "action_id": self.action_id,
                "request_wire_format": self.request_wire_format,
                "payload_meta": dict(self.payload_meta or {}),
            }
        )
        return base


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
