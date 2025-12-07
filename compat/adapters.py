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

"""Thin adapters to preserve legacy call patterns."""

from typing import Any, Dict, Optional

from ..models import FrameworkDetectionResult
from ..runtime import ReactGuard


def legacy_detect(
    url: str,
    *,
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
    http_client=None,
) -> FrameworkDetectionResult:
    """
    Legacy-compatible detection helper.

    Mirrors the old `detect_frameworks.detect(url)` signature and is intended
    for callers in `src/`, `src_legacy/`, or external integrations.
    """
    with ReactGuard(http_client=http_client) as guard:
        return guard.detect(url, proxy_profile=proxy_profile, correlation_id=correlation_id)


def legacy_vuln(
    url: str,
    *,
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
    detection_result: Optional[FrameworkDetectionResult] = None,
    http_client=None,
) -> Dict[str, Any]:
    """Legacy-compatible vulnerability helper (PoC only)."""
    with ReactGuard(http_client=http_client) as guard:
        return guard.vuln(
            url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            detection_result=detection_result,
        )


def legacy_scan(
    url: str,
    *,
    proxy_profile: Optional[str] = None,
    correlation_id: Optional[str] = None,
    http_client=None,
) -> Dict[str, Any]:
    """Legacy-compatible full scan helper."""
    with ReactGuard(http_client=http_client) as guard:
        return guard.scan(url, proxy_profile=proxy_profile, correlation_id=correlation_id)
