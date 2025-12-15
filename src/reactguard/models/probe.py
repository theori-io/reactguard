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
