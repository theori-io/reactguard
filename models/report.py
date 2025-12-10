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

"""Dataclasses for vulnerability and scan reports."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .poc import PocStatus
from .scan import FrameworkDetectionResult


@dataclass
class VulnerabilityReport:
    """Normalized PoC result wrapper."""

    status: PocStatus
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "details": self.details,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "VulnerabilityReport":
        status_val = data.get("status")
        try:
            status = PocStatus(status_val) if status_val is not None else PocStatus.INCONCLUSIVE
        except Exception:
            status = PocStatus.INCONCLUSIVE
        return cls(
            status=status,
            details=dict(data.get("details") or {}),
            raw_data=dict(data.get("raw_data") or {}),
        )


@dataclass
class ScanReport:
    """Combined framework + vulnerability report."""

    status: PocStatus
    framework_detection: FrameworkDetectionResult
    vulnerability_detection: VulnerabilityReport

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "framework_detection": {
                "tags": self.framework_detection.tags,
                "signals": self.framework_detection.signals,
            },
            "vulnerability_detection": self.vulnerability_detection.to_dict(),
        }

    @classmethod
    def from_parts(
        cls,
        detection: FrameworkDetectionResult,
        vulnerability: VulnerabilityReport | Dict[str, Any],
    ) -> "ScanReport":
        vuln_report = (
            vulnerability
            if isinstance(vulnerability, VulnerabilityReport)
            else VulnerabilityReport.from_mapping(vulnerability)
        )
        return cls(status=vuln_report.status, framework_detection=detection, vulnerability_detection=vuln_report)


__all__ = ["VulnerabilityReport", "ScanReport"]
