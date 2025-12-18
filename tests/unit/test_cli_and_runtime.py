# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.cli.main import _cve_sort_key, _pretty_print, build_parser
from reactguard.models import FrameworkDetectionResult, ScanReport, VulnerabilityReport
from reactguard.models.poc import PocStatus
from reactguard.runtime import ReactGuard
from reactguard.vulnerability_detection.engine import VulnerabilityDetectionEngine
from reactguard.vulnerability_detection.registry import CVE202555182VulnerabilityDetector


def test_build_parser_and_pretty_print(capsys):
    parser = build_parser()
    args = parser.parse_args(["http://example.com", "--json"])
    assert args.url == "http://example.com"
    assert args.json is True

    report = {
        "status": PocStatus.VULNERABLE,
        "framework_detection": {
            "tags": ["nextjs", "rsc"],
            "signals": {"nextjs_app_router": True, "server_actions_enabled": True},
        },
        "vulnerability_detection": {
            "status": PocStatus.VULNERABLE,
            "details": {"reason": "test", "confidence": "high", "detected_versions": {"react_version": "19.1.0"}},
        },
    }
    _pretty_print(report)
    output = capsys.readouterr().out
    assert "Status" in output
    assert "nextjs" in output
    assert "Signals" in output
    assert "Confidence" in output
    _pretty_print("plain output")
    assert "plain output" in capsys.readouterr().out


class DummyClient:
    def __init__(self):
        self.closed = False

    def close(self):  # pragma: no cover - exercised via ReactGuard
        self.closed = True


class DummyDetectionEngine:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def detect(self, request):  # noqa: ARG002
        self.calls += 1
        return self.result


class DummyVulnEngine:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def run(self, *_, **__):
        self.calls += 1
        return self.result


class DummyScanEngine:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def run(self, request):  # noqa: ARG002
        self.calls += 1
        return self.result


def test_reactguard_facade_methods():
    client = DummyClient()
    detection_result = FrameworkDetectionResult(tags=["nextjs"], signals={"detection_confidence": 80})
    vuln_dict = {"status": PocStatus.LIKELY_VULNERABLE, "details": {}, "raw_data": {}}
    scan_report = ScanReport(
        status=PocStatus.VULNERABLE,
        framework_detection=detection_result,
        vulnerability_detection=VulnerabilityReport(status=PocStatus.VULNERABLE),
    )

    guard = ReactGuard(http_client=client)
    guard.detection_engine = DummyDetectionEngine(detection_result)
    guard.vulnerability_engine = DummyVulnEngine(vuln_dict)
    guard.scan_engine = DummyScanEngine(scan_report)

    detect_out = guard.detect("http://example.com", proxy_profile="legacy-proxy", correlation_id="legacy-correlation")
    assert detect_out.tags == ["nextjs"]
    vuln_out = guard.scan_vulnerabilities("http://example.com", proxy_profile="legacy-proxy", correlation_id="legacy-correlation")
    assert isinstance(vuln_out, list)
    assert isinstance(vuln_out[0], VulnerabilityReport)
    scan_out = guard.scan("http://example.com", proxy_profile="legacy-proxy", correlation_id="legacy-correlation")
    assert isinstance(scan_out, ScanReport)
    guard.close()
    assert client.closed is True


def test_reactguard_exit_closes_client():
    client = DummyClient()
    guard = ReactGuard(http_client=client)
    guard.__exit__(None, None, None)
    assert client.closed is True


def test_cli_main_executes(monkeypatch, capsys):
    from reactguard.cli import main as cli_main

    fake_report = ScanReport(
        status=PocStatus.NOT_VULNERABLE,
        framework_detection=FrameworkDetectionResult(tags=["nextjs"], signals={}),
        vulnerability_detection=VulnerabilityReport(status=PocStatus.NOT_VULNERABLE, details={"reason": "ok"}),
    )

    class FakeGuard:
        def __init__(self, http_client=None):  # noqa: ARG002
            self.calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):  # noqa: ARG002
            return None

        def scan(self, url, **kwargs):  # noqa: ARG002
            self.calls += 1
            return fake_report

    monkeypatch.setattr(cli_main, "ReactGuard", lambda http_client=None: FakeGuard(http_client))
    monkeypatch.setattr(cli_main, "create_default_http_client", lambda settings=None: object())
    monkeypatch.setattr(cli_main, "load_http_settings", lambda: cli_main.HttpSettings())

    exit_code = cli_main.main(["http://example", "--json", "--ignore-ssl-errors"])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "status" in output.lower()


def test_cli_json_truncates_large_strings(capsys):
    from reactguard.cli.main import _print_json

    _print_json({"body": "x" * 5000})
    output = capsys.readouterr().out
    assert "[truncated]" in output


def test_cve_sort_key_parses_ids():
    assert _cve_sort_key("CVE-2025-55182") == (2025, 55182, "CVE-2025-55182")
    assert _cve_sort_key("not-a-cve")[0] == 9999


def test_ignored_proxy_and_correlation_are_accepted():
    detection_result = FrameworkDetectionResult(tags=[], signals={"fetch_error_message": "TIMEOUT"})

    detector = CVE202555182VulnerabilityDetector()
    result = detector.evaluate(
        "http://example.com",
        detection_result=detection_result,
        proxy_profile="legacy-proxy",
        correlation_id="legacy-correlation",
    )
    assert result.status == PocStatus.INCONCLUSIVE

    engine = VulnerabilityDetectionEngine()
    out = engine.run(
        "http://example.com",
        detection_result=detection_result,
        proxy_profile="legacy-proxy",
        correlation_id="legacy-correlation",
    )
    assert isinstance(out, list)
    assert all(isinstance(item, VulnerabilityReport) for item in out)
    assert any(item.status == PocStatus.INCONCLUSIVE for item in out)
