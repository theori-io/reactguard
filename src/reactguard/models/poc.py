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

"""PoC domain models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .detection import FrameworkDetectionResult


class PocStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    LIKELY_NOT_VULNERABLE = "LIKELY_NOT_VULNERABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class PocRequest:
    url: str
    proxy_profile: str | None = None
    correlation_id: str | None = None
    detection: FrameworkDetectionResult | None = None


@dataclass
class PocResult:
    status: PocStatus
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)
