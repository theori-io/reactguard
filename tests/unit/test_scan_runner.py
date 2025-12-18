# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.models import FrameworkDetectionResult, ScanRequest
from reactguard.models.poc import PocStatus
from reactguard.scan.engine import ScanEngine
from reactguard.scan.report_builder import build_scan_report


class FakeDetectionEngine:
    def __init__(self, result):
        self.result = result
        self.called = 0

    def detect(self, request):
        self.called += 1
        return self.result


class FakeVulnEngine:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        return self.result


def test_scan_engine_passes_final_url():
    detection_result = FrameworkDetectionResult(tags=["nextjs"], signals={"final_url": "http://final"})
    vuln_result = {"status": PocStatus.NOT_VULNERABLE, "details": {}}
    engine = ScanEngine(detection_engine=FakeDetectionEngine(detection_result), vulnerability_engine=FakeVulnEngine(vuln_result))
    request = ScanRequest(url="http://origin")
    report = engine.run(request)
    assert report.status == PocStatus.NOT_VULNERABLE


def test_build_scan_report_accepts_mapping():
    detection = FrameworkDetectionResult(tags=[], signals={})
    vuln_mapping = {"status": PocStatus.INCONCLUSIVE, "details": {"reason": "x"}}
    report = build_scan_report(detection, vuln_mapping)
    assert report.vulnerability_detection.status == PocStatus.INCONCLUSIVE
