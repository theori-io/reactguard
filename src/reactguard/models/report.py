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
from typing import Any

from .poc import PocStatus
from .scan import FrameworkDetectionResult


@dataclass
class VulnerabilityReport:
    """Normalized PoC result wrapper."""

    status: PocStatus
    details: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like access for backwards compatibility."""
        if key == "status":
            return self.status
        if key == "details":
            return self.details
        if key == "raw_data":
            return self.raw_data
        return default

    def __getitem__(self, key: str) -> Any:
        value = self.get(key, default=None)
        if value is None and key not in {"status", "details", "raw_data"}:
            raise KeyError(key)
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "status":
            self.status = value
            return
        if key == "details":
            self.details = value
            return
        if key == "raw_data":
            self.raw_data = value
            return
        raise KeyError(key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "details": dict(self.details or {}),
            "raw_data": dict(self.raw_data or {}),
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> VulnerabilityReport:
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
    vulnerability_detections: list[VulnerabilityReport] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Keep the "primary" field consistent when callers provide an explicit list.
        if self.vulnerability_detections:
            self.vulnerability_detection = self.vulnerability_detections[0]

    @property
    def findings(self) -> list[VulnerabilityReport]:
        """Return all vulnerability findings, falling back to the primary finding."""
        return self.vulnerability_detections or [self.vulnerability_detection]

    @staticmethod
    def _aggregate_status(reports: list[VulnerabilityReport]) -> PocStatus:
        """
        Compute an overall scan status across multiple CVE results.

        Ordering is intentionally conservative: any confirmed vulnerability dominates; otherwise any inconclusive
        result dominates; otherwise fall back to the strongest "not vulnerable" style result available.
        """
        if any(r.status == PocStatus.VULNERABLE for r in reports):
            return PocStatus.VULNERABLE
        if any(r.status == PocStatus.LIKELY_VULNERABLE for r in reports):
            return PocStatus.LIKELY_VULNERABLE
        if any(r.status == PocStatus.INCONCLUSIVE for r in reports):
            return PocStatus.INCONCLUSIVE
        if any(r.status == PocStatus.LIKELY_NOT_VULNERABLE for r in reports):
            return PocStatus.LIKELY_NOT_VULNERABLE
        if any(r.status == PocStatus.NOT_VULNERABLE for r in reports):
            return PocStatus.NOT_VULNERABLE
        return PocStatus.NOT_APPLICABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "framework_detection": {
                "tags": self.framework_detection.tags,
                "signals": self.framework_detection.signals,
            },
            "vulnerability_detection": self.vulnerability_detection.to_dict(),
            "vulnerability_detections": [v.to_dict() for v in self.vulnerability_detections],
        }

    def __contains__(self, item: str) -> bool:
        return item in self.to_dict()

    @classmethod
    def from_parts(
        cls,
        detection: FrameworkDetectionResult,
        vulnerability: VulnerabilityReport | dict[str, Any] | list[VulnerabilityReport] | list[dict[str, Any]],
    ) -> ScanReport:
        if isinstance(vulnerability, list):
            vuln_reports: list[VulnerabilityReport] = [v if isinstance(v, VulnerabilityReport) else VulnerabilityReport.from_mapping(v) for v in vulnerability]
        else:
            vuln_reports = [vulnerability if isinstance(vulnerability, VulnerabilityReport) else VulnerabilityReport.from_mapping(vulnerability)]

        if not vuln_reports:
            tags = detection.tags or []
            reason = "No applicable CVE detectors for the detected framework tags"
            if tags:
                reason = f"{reason}: {', '.join(tags)}"
            primary = VulnerabilityReport(status=PocStatus.NOT_APPLICABLE, details={"reason": reason})
            return cls(
                status=PocStatus.NOT_APPLICABLE,
                framework_detection=detection,
                vulnerability_detection=primary,
                vulnerability_detections=[],
            )

        primary = vuln_reports[0]
        overall = cls._aggregate_status(vuln_reports)
        return cls(
            status=overall,
            framework_detection=detection,
            vulnerability_detection=primary,
            vulnerability_detections=vuln_reports,
        )


__all__ = ["VulnerabilityReport", "ScanReport"]
