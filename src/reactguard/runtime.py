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

from .framework_detection.engine import FrameworkDetectionEngine
from .http.client import HttpClient, create_default_http_client
from .models import (
    FrameworkDetectionResult,
    ScanReport,
    ScanRequest,
    VulnerabilityReport,
)
from .scan.engine import ScanEngine
from .utils.context import scan_context
from .vulnerability_detection.engine import VulnerabilityDetectionEngine


class ReactGuard:
    """
    Convenience wrapper that wires a shared HTTP client across detection and PoC runs.

    This reduces churn in CLI/consumers and ensures the same client configuration is
    reused for framework detection and vulnerability probing.
    """

    def __init__(self, http_client: HttpClient | None = None):
        self.http_client = http_client or create_default_http_client()
        self.detection_engine = FrameworkDetectionEngine(self.http_client)
        self.vulnerability_engine = VulnerabilityDetectionEngine(self.detection_engine)
        self.scan_engine = ScanEngine(self.detection_engine, self.vulnerability_engine)

    def detect(
        self,
        url: str,
        *,
        request_headers: dict[str, str] | None = None,
        response_headers: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        proxy_profile: str | None = None,
        correlation_id: str | None = None,
    ) -> FrameworkDetectionResult:
        if response_headers is None and headers is not None:
            response_headers = headers
        request = ScanRequest(
            url=url,
            request_headers=request_headers,
            response_headers=response_headers,
            body=body,
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
        )
        with scan_context(http_client=self.http_client, proxy_profile=proxy_profile, correlation_id=correlation_id):
            return self.detection_engine.detect(request)

    def scan_vulnerabilities(
        self,
        url: str,
        *,
        detection_result: FrameworkDetectionResult | None = None,
        proxy_profile: str | None = None,
        correlation_id: str | None = None,
    ) -> list[VulnerabilityReport]:
        with scan_context(http_client=self.http_client, proxy_profile=proxy_profile, correlation_id=correlation_id):
            result = self.vulnerability_engine.run(
                url,
                detection_result=detection_result,
                proxy_profile=proxy_profile,
                correlation_id=correlation_id,
            )
        if isinstance(result, list):
            return [r if isinstance(r, VulnerabilityReport) else VulnerabilityReport.from_mapping(r) for r in result]
        if isinstance(result, VulnerabilityReport):
            return [result]
        return [VulnerabilityReport.from_mapping(result)]

    def scan(
        self,
        url: str,
        *,
        proxy_profile: str | None = None,
        correlation_id: str | None = None,
    ) -> ScanReport:
        request = ScanRequest(url=url, proxy_profile=proxy_profile, correlation_id=correlation_id)
        with scan_context(http_client=self.http_client, proxy_profile=proxy_profile, correlation_id=correlation_id):
            return self.scan_engine.run(request)

    def close(self) -> None:
        with suppress(Exception):
            if hasattr(self.http_client, "close"):
                self.http_client.close()

    def __enter__(self) -> ReactGuard:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:  # noqa: ANN001
        self.close()
