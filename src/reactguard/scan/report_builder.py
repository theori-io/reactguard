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

"""Reporting helpers for scan orchestration."""

from typing import Any

from ..models import FrameworkDetectionResult, ScanReport, VulnerabilityReport


def build_scan_report(
    detection_result: FrameworkDetectionResult,
    vulnerability_result: VulnerabilityReport | dict[str, Any] | list[VulnerabilityReport] | list[dict[str, Any]],
) -> ScanReport:
    """Combine detection + vulnerability results into a single report."""
    if isinstance(vulnerability_result, list):
        vuln_reports = [v if isinstance(v, VulnerabilityReport) else VulnerabilityReport.from_mapping(v) for v in vulnerability_result]
        return ScanReport.from_parts(detection_result, vuln_reports)

    vuln_report = vulnerability_result if isinstance(vulnerability_result, VulnerabilityReport) else VulnerabilityReport.from_mapping(vulnerability_result)
    return ScanReport.from_parts(detection_result, vuln_report)


__all__ = ["build_scan_report"]
