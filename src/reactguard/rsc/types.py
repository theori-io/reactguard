# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Types for framework-agnostic RSC request construction."""

from __future__ import annotations

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
