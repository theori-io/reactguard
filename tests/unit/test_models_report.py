from reactguard.models import FrameworkDetectionResult, ScanReport, VulnerabilityReport
from reactguard.models.poc import PocStatus


def test_vulnerability_report_from_mapping_and_to_dict():
    report = VulnerabilityReport.from_mapping({"status": "UNKNOWN", "details": {"foo": "bar"}, "raw_data": {"k": "v"}})
    assert report.status == PocStatus.INCONCLUSIVE
    data = report.to_dict()
    assert data["details"]["foo"] == "bar"
    assert data["raw_data"]["k"] == "v"


def test_scan_report_to_dict_and_from_parts():
    detection = FrameworkDetectionResult(tags=["nextjs"], signals={"signal": True})
    vuln = VulnerabilityReport(status=PocStatus.NOT_VULNERABLE, details={"reason": "ok"})
    scan = ScanReport.from_parts(detection, vuln)
    payload = scan.to_dict()
    assert payload["framework_detection"]["tags"] == ["nextjs"]
    assert payload["vulnerability_detection"]["status"] == PocStatus.NOT_VULNERABLE
    reconstructed = ScanReport.from_parts(detection, {"status": PocStatus.LIKELY_NOT_VULNERABLE, "details": {}})
    assert reconstructed.status == PocStatus.LIKELY_NOT_VULNERABLE
