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

"""Scan request/result models."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .http import HttpResponse


@dataclass
class ScanRequest:
    """
    Represents a scan request spanning framework detection plus vulnerability detection.

    Either `url` or a pre-fetched `response` must be supplied. Proxy and correlation
    metadata propagate through to all probes.
    """

    url: Optional[str] = None
    response: Optional[HttpResponse] = None
    proxy_profile: Optional[str] = None
    correlation_id: Optional[str] = None
    body: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


@dataclass
class FrameworkDetectionResult:
    """Normalized framework detection result."""

    tags: list[str]
    signals: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        return float(self.signals.get("detection_confidence", 0.0))

    @property
    def confidence_level(self) -> str:
        return str(self.signals.get("detection_confidence_level", "unknown"))
