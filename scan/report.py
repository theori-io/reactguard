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

from typing import Any, Dict

from ..models import FrameworkDetectionResult


def build_scan_report(
    detection_result: FrameworkDetectionResult,
    vulnerability_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Combine detection + vulnerability results into a single mapping."""
    return {
        "status": vulnerability_result.get("status"),
        "framework_detection": {
            "tags": detection_result.tags,
            "signals": detection_result.signals,
        },
        "vulnerability_detection": vulnerability_result,
    }
