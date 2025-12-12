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

"""Run a full scan: framework detection followed by vulnerability detection."""


from ..framework_detection.engine import FrameworkDetectionEngine
from ..models import FrameworkDetectionResult, ScanReport, ScanRequest
from ..vulnerability_detection.runner import VulnerabilityDetectionRunner
from .report import build_scan_report


class ScanRunner:
    """Coordinates framework detection and vulnerability detection for a single target."""

    def __init__(
        self,
        detection_engine: FrameworkDetectionEngine | None = None,
        vulnerability_runner: VulnerabilityDetectionRunner | None = None,
    ):
        self.detection_engine = detection_engine or FrameworkDetectionEngine()
        self.vulnerability_runner = vulnerability_runner or VulnerabilityDetectionRunner(self.detection_engine)

    def run(self, request: ScanRequest) -> ScanReport:
        detection_result: FrameworkDetectionResult = self.detection_engine.detect(request)
        target_url = str(detection_result.signals.get("final_url") or request.url or "")

        vulnerability_result = self.vulnerability_runner.run(
            target_url,
            detection_result=detection_result,
        )

        return build_scan_report(detection_result, vulnerability_result)
