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

"""High-level ReactGuard facade for detection and vulnerability workflows."""

from contextlib import suppress
from typing import Any, Dict, Optional

from .framework_detection.engine import FrameworkDetectionEngine
from .http.client import HttpClient, create_default_http_client
from .models import FrameworkDetectionResult, ScanRequest
from .scan.runner import ScanRunner
from .vulnerability_detection.runner import VulnerabilityDetectionRunner


class ReactGuard:
    """
    Convenience wrapper that wires a shared HTTP client across detection and PoC runs.

    This reduces churn in CLI/consumers and ensures the same client configuration is
    reused for framework detection and vulnerability probing.
    """

    def __init__(self, http_client: Optional[HttpClient] = None):
        self.http_client = http_client or create_default_http_client()
        self.detection_engine = FrameworkDetectionEngine(self.http_client)
        self.vulnerability_runner = VulnerabilityDetectionRunner(self.detection_engine)
        self.scan_runner = ScanRunner(self.detection_engine, self.vulnerability_runner)

    def detect(
        self,
        url: str,
        *,
        proxy_profile: Optional[str] = None,
        correlation_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> FrameworkDetectionResult:
        request = ScanRequest(
            url=url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            headers=headers,
            body=body,
        )
        return self.detection_engine.detect(request)

    def vuln(
        self,
        url: str,
        *,
        proxy_profile: Optional[str] = None,
        correlation_id: Optional[str] = None,
        detection_result: Optional[FrameworkDetectionResult] = None,
    ) -> Dict[str, Any]:
        return self.vulnerability_runner.run(
            url,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            detection_result=detection_result,
        )

    def scan(
        self,
        url: str,
        *,
        proxy_profile: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        request = ScanRequest(url=url, proxy_profile=proxy_profile, correlation_id=correlation_id)
        return self.scan_runner.run(request)

    def close(self) -> None:
        with suppress(Exception):
            if hasattr(self.http_client, "close"):
                self.http_client.close()

    def __enter__(self) -> "ReactGuard":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()
