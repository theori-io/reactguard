# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe request/response models."""

from dataclasses import dataclass, field
from typing import Any

from ..http.models import HttpResponse


@dataclass
class ProbeRequest:
    url: str
    method: str = "GET"
    body: str | bytes | None = None
    headers: dict[str, str] | None = None
    proxy_profile: str | None = None
    correlation_id: str | None = None


@dataclass
class ProbeResult:
    ok: bool
    response: HttpResponse | None = None
    error_message: str | None = None
    error_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
