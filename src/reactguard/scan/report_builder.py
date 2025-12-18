# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reporting helpers for scan orchestration."""

from __future__ import annotations

from typing import Any

from ..models import FrameworkDetectionResult, ScanReport, VulnerabilityReport


def build_scan_report(
    detection_result: FrameworkDetectionResult,
    vulnerability_result: VulnerabilityReport | dict[str, Any] | list[VulnerabilityReport] | list[dict[str, Any]],
) -> ScanReport:
    """Combine detection + vulnerability results into a single report."""
    return ScanReport.from_parts(detection_result, vulnerability_result)


__all__ = ["build_scan_report"]
