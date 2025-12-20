# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Scan engine: framework detection followed by vulnerability detection."""

from ..framework_detection.engine import FrameworkDetectionEngine
from ..framework_detection.keys import SIG_FINAL_URL
from ..models import FrameworkDetectionResult, ScanReport, ScanRequest
from ..vulnerability_detection.engine import VulnerabilityDetectionEngine


class ScanEngine:
    """Coordinates framework detection and vulnerability detection for a single target."""

    def __init__(
        self,
        detection_engine: FrameworkDetectionEngine | None = None,
        vulnerability_engine: VulnerabilityDetectionEngine | None = None,
    ):
        self.detection_engine = detection_engine or FrameworkDetectionEngine()
        self.vulnerability_engine = vulnerability_engine or VulnerabilityDetectionEngine(self.detection_engine)

    def run(self, request: ScanRequest) -> ScanReport:
        detection_result: FrameworkDetectionResult = self.detection_engine.detect(request)
        target_url = str(detection_result.signals.get(SIG_FINAL_URL) or request.url or "")

        vulnerability_result = self.vulnerability_engine.run(
            target_url,
            detection_result=detection_result,
            proxy_profile=request.proxy_profile,
            correlation_id=request.correlation_id,
        )

        return ScanReport.from_parts(detection_result, vulnerability_result)
