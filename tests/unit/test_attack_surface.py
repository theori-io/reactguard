from reactguard.framework_detection.keys import (
    SIG_DETECTION_CONFIDENCE_LEVEL,
    SIG_REACT_BUNDLE_ONLY,
    SIG_SERVER_ACTIONS_CONFIDENCE,
    SIG_SERVER_ACTIONS_ENABLED,
    TAG_NEXTJS,
    TAG_NEXTJS_PAGES_ROUTER,
    TAG_REACT_ROUTER_V7,
    TAG_REACT_STREAMING,
    TAG_RSC,
    TAG_WAKU,
)
from reactguard.framework_detection.signals.waku import WakuServerActionsProbeResult
from reactguard.models import FrameworkDetectionResult
from reactguard.models.poc import PocStatus
from reactguard.utils.context import scan_context
from reactguard.vulnerability_detection.cves import (
    CVE202555182VulnerabilityDetector,
    CVE202555184VulnerabilityDetector,
)
from reactguard.vulnerability_detection.snapshots import DetectionSnapshot
from reactguard.vulnerability_detection.surface import (
    MISSING_SURFACE_REASON_CODE,
    build_missing_surface_report,
    compute_rsc_server_functions_surface,
)


def test_surface_compute_pages_router_requires_confidence():
    snap_low = DetectionSnapshot(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        server_actions_enabled=None,
        server_actions_confidence=None,
        server_action_endpoints=[],
    )
    surface_low = compute_rsc_server_functions_surface(snap_low)
    assert surface_low.server_functions_surface is None

    snap_med = DetectionSnapshot(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "medium"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        server_actions_enabled=None,
        server_actions_confidence=None,
        server_action_endpoints=[],
    )
    surface_med = compute_rsc_server_functions_surface(snap_med)
    assert surface_med.server_functions_surface is False
    assert surface_med.confidence == "high"


def test_surface_compute_server_actions_absent_high_confidence_is_closed():
    snap = DetectionSnapshot(
        tags=[],
        signals={SIG_SERVER_ACTIONS_ENABLED: False, SIG_SERVER_ACTIONS_CONFIDENCE: "high"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        server_actions_enabled=False,
        server_actions_confidence="high",
        server_action_endpoints=[],
    )
    surface = compute_rsc_server_functions_surface(snap)
    assert surface.server_functions_surface is False
    assert surface.confidence == "high"


def test_surface_compute_waku_requires_entrypoint_when_waku_evidence_present():
    snap = DetectionSnapshot(
        tags=[TAG_WAKU, TAG_RSC],
        signals={"waku_meta_generator": True, SIG_DETECTION_CONFIDENCE_LEVEL: "high"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        server_actions_enabled=None,
        server_actions_confidence=None,
        server_action_endpoints=[],
    )
    surface = compute_rsc_server_functions_surface(snap)
    assert surface.entrypoint_required is True
    # Waku action endpoints may not be discoverable from the landing page without crawling/auth;
    # treat this as unknown rather than a definitive negative.
    assert surface.entrypoint_available is None
    assert surface.server_functions_surface is None
    assert surface.confidence in {"medium", "low"}


def test_build_missing_surface_report_has_reason_code_and_attack_surface():
    snap = DetectionSnapshot(
        tags=[],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "high"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        server_actions_enabled=None,
        server_actions_confidence=None,
        server_action_endpoints=[],
    )
    surface = compute_rsc_server_functions_surface(snap)
    report = build_missing_surface_report(
        cve_id="CVE-2025-55182",
        snapshot=snap,
        surface=surface,
        status=PocStatus.NOT_APPLICABLE,
        reason="No surface",
    )
    assert report.details["reason_code"] == MISSING_SURFACE_REASON_CODE
    assert "attack_surface" in report.details


def test_cve_55182_detector_returns_not_vulnerable_when_surface_closed():
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "high"},
    )
    result = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_VULNERABLE
    assert result.details["reason_code"] == MISSING_SURFACE_REASON_CODE


def test_dec2025_detector_returns_not_vulnerable_when_surface_closed():
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "high"},
    )
    result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_VULNERABLE
    assert result.details["reason_code"] == MISSING_SURFACE_REASON_CODE


def test_rsc_dependency_only_short_circuits_dec2025_family():
    detection = FrameworkDetectionResult(
        tags=[TAG_REACT_ROUTER_V7, TAG_REACT_STREAMING],
        signals={SIG_REACT_BUNDLE_ONLY: True, SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
    )
    with scan_context(extra={}):
        result_55182 = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55182.status == PocStatus.NOT_VULNERABLE
        assert result_55182.details["reason_code"] == MISSING_SURFACE_REASON_CODE

        result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result.status == PocStatus.NOT_VULNERABLE
        assert result.details["reason_code"] == MISSING_SURFACE_REASON_CODE


def test_55182_default_rule_marks_missing_surface_and_skips_dec2025(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_REACT_STREAMING],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves.cve_2025_55182.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.NOT_APPLICABLE,
            "details": {
                "cve_id": "CVE-2025-55182",
                "confidence": "high",
                "reason": "No RSC processing detected",
                "decision_rule": "_default_rule",
                "surface_detected": False,
            },
            "raw_data": {},
        },
    )
    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Dec 2025 assessor should be skipped when surface is marked missing")),
    )

    with scan_context(extra={}):
        result_55182 = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55182.status == PocStatus.NOT_VULNERABLE
        assert result_55182.details["reason_code"] == MISSING_SURFACE_REASON_CODE

        result_55184 = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55184.status == PocStatus.NOT_VULNERABLE
        assert result_55184.details["reason_code"] == MISSING_SURFACE_REASON_CODE


def test_waku_entrypoint_missing_is_likely_not_vulnerable(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_WAKU, TAG_RSC],
        signals={"waku_meta_generator": True, SIG_DETECTION_CONFIDENCE_LEVEL: "high"},
    )

    monkeypatch.setattr("reactguard.vulnerability_detection.assessors.waku.crawl_same_origin_html", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "reactguard.vulnerability_detection.assessors.waku.probe_waku_server_actions_result",
        lambda *_args, **_kwargs: WakuServerActionsProbeResult(has_actions=False, count=0, endpoints=[]),
    )

    result = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_APPLICABLE
    assert "endpoints" in str(result.details.get("reason") or "").lower()


def test_waku_entrypoint_missing_but_expected_is_inconclusive(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_WAKU, TAG_RSC],
        signals={
            "waku_meta_generator": True,
            SIG_DETECTION_CONFIDENCE_LEVEL: "high",
            SIG_SERVER_ACTIONS_ENABLED: True,
        },
    )

    monkeypatch.setattr("reactguard.vulnerability_detection.assessors.waku.crawl_same_origin_html", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "reactguard.vulnerability_detection.assessors.waku.probe_waku_server_actions_result",
        lambda *_args, **_kwargs: WakuServerActionsProbeResult(has_actions=False, count=0, endpoints=[]),
    )

    result = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_APPLICABLE
    assert "endpoints" in str(result.details.get("reason") or "").lower()
