from reactguard.compat import adapters
from reactguard.models import FrameworkDetectionResult, ScanReport, VulnerabilityReport
from reactguard.models.poc import PocStatus


class StubGuard:
    def __init__(self, http_client=None):  # noqa: ARG002
        self.called = {"detect": 0, "vuln": 0, "scan": 0}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ARG002
        return None

    def detect(self, url, **kwargs):  # noqa: ARG002
        self.called["detect"] += 1
        return FrameworkDetectionResult(tags=["nextjs"], signals={"url": url})

    def vuln(self, url, **kwargs):  # noqa: ARG002
        self.called["vuln"] += 1
        return VulnerabilityReport(status=PocStatus.VULNERABLE, details={"url": url})

    def scan(self, url, **kwargs):  # noqa: ARG002
        self.called["scan"] += 1
        det = FrameworkDetectionResult(tags=["nextjs"], signals={"url": url})
        vuln = VulnerabilityReport(status=PocStatus.INCONCLUSIVE, details={"url": url})
        return ScanReport(status=PocStatus.INCONCLUSIVE, framework_detection=det, vulnerability_detection=vuln)


def test_legacy_adapters(monkeypatch):
    stub_guard = StubGuard()
    monkeypatch.setattr(adapters, "ReactGuard", lambda http_client=None: stub_guard)

    detection = adapters.legacy_detect("http://example")
    assert detection["tags"] == ["nextjs"]

    vuln = adapters.legacy_vuln("http://example")
    assert vuln["status"] == PocStatus.VULNERABLE

    scan = adapters.legacy_scan("http://example")
    assert scan["vulnerability_detection"]["status"] == PocStatus.INCONCLUSIVE
    assert stub_guard.called["scan"] == 1
