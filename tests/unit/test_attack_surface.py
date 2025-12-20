# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.framework_detection.keys import (
    SIG_DETECTION_CONFIDENCE_LEVEL,
    SIG_INVOCATION_CONFIDENCE,
    SIG_INVOCATION_ENABLED,
    SIG_REACT_BUNDLE_ONLY,
    TAG_NEXTJS,
    TAG_NEXTJS_PAGES_ROUTER,
    TAG_REACT_ROUTER_V7,
    TAG_REACT_STREAMING,
    TAG_RSC,
    TAG_WAKU,
)
from reactguard.models import FrameworkDetectionResult
from reactguard.models.poc import PocStatus
from reactguard.utils.context import scan_context
from reactguard.vulnerability_detection.cves import (
    CVE202555182VulnerabilityDetector,
    CVE202555184VulnerabilityDetector,
)
from reactguard.vulnerability_detection.cves._rsc_common import RSC_SERVER_FUNCTIONS_SURFACE_CACHE_KEY
from reactguard.vulnerability_detection.snapshots import DetectionSnapshot
from reactguard.vulnerability_detection.surface import (
    MISSING_SURFACE_REASON_CODE,
    build_missing_surface_report,
    compute_rsc_server_functions_surface,
    missing_surface_status,
)
from reactguard.vulnerability_detection.resolvers.types import ActionResolution


def test_surface_compute_pages_router_requires_confidence():
    snap_low = DetectionSnapshot(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        invocation_enabled=None,
        invocation_confidence=None,
        invocation_endpoints=[],
    )
    surface_low = compute_rsc_server_functions_surface(snap_low)
    assert surface_low.server_functions_surface is None

    snap_med = DetectionSnapshot(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "medium"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        invocation_enabled=None,
        invocation_confidence=None,
        invocation_endpoints=[],
    )
    surface_med = compute_rsc_server_functions_surface(snap_med)
    assert surface_med.server_functions_surface is False
    assert surface_med.confidence == "high"


def test_missing_surface_status_tiers():
    assert missing_surface_status("high") == PocStatus.NOT_VULNERABLE
    assert missing_surface_status("medium") == PocStatus.LIKELY_NOT_VULNERABLE
    assert missing_surface_status("low") == PocStatus.INCONCLUSIVE


def test_surface_compute_invocation_absent_high_confidence_is_closed():
    snap = DetectionSnapshot(
        tags=[],
        signals={SIG_INVOCATION_ENABLED: False, SIG_INVOCATION_CONFIDENCE: "high"},
        detected_versions={},
        react_major=None,
        react_major_confidence=None,
        invocation_enabled=False,
        invocation_confidence="high",
        invocation_endpoints=[],
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
        invocation_enabled=None,
        invocation_confidence=None,
        invocation_endpoints=[],
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
        invocation_enabled=None,
        invocation_confidence=None,
        invocation_endpoints=[],
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


def test_dec2025_detector_marks_missing_surface_when_fingerprint_missing(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_REACT_ROUTER_V7, TAG_REACT_STREAMING],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "medium"},
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.INCONCLUSIVE,
            "details": {"cve_id": "CVE-2025-55184", "confidence": "low", "reason": "stub"},
            "raw_data": {"evidence": {"reason": "No candidate Flight protocol endpoints discovered"}},
        },
    )

    result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.LIKELY_NOT_VULNERABLE
    assert result.details["reason_code"] == MISSING_SURFACE_REASON_CODE
    assert result.details["reason"] == "No reachable Flight protocol payload deserialization surface detected"


def test_dec2025_detector_marks_missing_surface_when_action_id_required(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_REACT_STREAMING],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "medium"},
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.INCONCLUSIVE,
            "details": {"cve_id": "CVE-2025-55184", "confidence": "low", "reason": "stub"},
            "raw_data": {
                "evidence": {
                    "reason": "No reachable Flight protocol payload deserialization surface found (HTML/timeouts)",
                    "needs_valid_action_id": True,
                }
            },
        },
    )

    result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.LIKELY_NOT_VULNERABLE
    assert result.details["reason_code"] == MISSING_SURFACE_REASON_CODE
    assert result.details["reason"] == "No reachable Flight protocol payload deserialization surface detected"


def test_dec2025_detector_short_circuits_on_react18():
    detection = FrameworkDetectionResult(
        tags=[TAG_RSC],
        signals={
            SIG_DETECTION_CONFIDENCE_LEVEL: "high",
            "detected_react_version": "18.2.0",
            "detected_react_version_confidence": "high",
        },
    )
    result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_APPLICABLE
    assert result.details["not_affected"] is True
    assert "React 18.x" in str(result.details.get("reason") or "")


def test_dec2025_detector_does_not_short_circuit_when_react_major_conflicts():
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_NEXTJS_PAGES_ROUTER],
        signals={
            SIG_DETECTION_CONFIDENCE_LEVEL: "high",
            "detected_react_version": "18.2.0",
            "detected_react_version_confidence": "high",
            "react_major_conflict": True,
            "react_major_conflict_confidence": "high",
            "react_major_conflict_majors": [18, 19],
        },
    )
    result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_VULNERABLE
    assert result.details["reason_code"] == MISSING_SURFACE_REASON_CODE


def test_dec2025_detector_short_circuits_when_react_major_conflict_excludes_react19():
    detection = FrameworkDetectionResult(
        tags=[TAG_RSC],
        signals={
            SIG_DETECTION_CONFIDENCE_LEVEL: "high",
            "detected_react_version": "18.2.0",
            "detected_react_version_confidence": "high",
            "react_major_conflict": True,
            "react_major_conflict_confidence": "high",
            "react_major_conflict_majors": [17, 18],
        },
    )
    result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_APPLICABLE
    assert result.details["not_affected"] is True


def test_rsc_dependency_only_short_circuits_dec2025_family(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_REACT_ROUTER_V7, TAG_REACT_STREAMING],
        signals={SIG_REACT_BUNDLE_ONLY: True, SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
    )
    # The 55182 missing-surface cache is now conservative; low-confidence missing-surface outcomes
    # should not short-circuit Dec 2025 detectors (they may be FN-prone).
    with scan_context(extra={}):
        result_55182 = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55182.status == PocStatus.LIKELY_NOT_VULNERABLE

        # Avoid network by stubbing the Dec 2025 assessor runner and assert it is invoked.
        calls = {"dec2025": 0}

        def _stub_dec2025(*_args, **_kwargs):
            calls["dec2025"] += 1
            return {
                "status": PocStatus.INCONCLUSIVE,
                "details": {"cve_id": "CVE-2025-55184", "confidence": "low", "reason": "stub"},
                "raw_data": {},
            }

        monkeypatch.setattr(
            "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
            _stub_dec2025,
        )

        result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert calls["dec2025"] == 1
        assert result.status == PocStatus.INCONCLUSIVE


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
                "reason": "No RSC Flight or Flight protocol payload deserialization observed on tested endpoints",
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


def test_dec2025_detector_does_not_honor_missing_surface_cache_when_endpoints_do_not_match(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_REACT_STREAMING],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
    )

    calls = {"dec2025": 0}

    def _stub_dec2025(*_args, **_kwargs):
        calls["dec2025"] += 1
        return {
            "status": PocStatus.INCONCLUSIVE,
            "details": {"cve_id": "CVE-2025-55184", "confidence": "low", "reason": "stub"},
            "raw_data": {},
        }

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
        _stub_dec2025,
    )

    with scan_context(
        extra={
            RSC_SERVER_FUNCTIONS_SURFACE_CACHE_KEY: {
                "cve_id": "CVE-2025-55182",
                "decision_rule": "_default_rule",
                "confidence": "high",
                "endpoints": ["http://other.invalid"],
            }
        }
    ):
        result = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert calls["dec2025"] == 1
    assert result.status == PocStatus.INCONCLUSIVE


def test_55182_server_actions_missing_marks_missing_surface_and_skips_dec2025(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_REACT_STREAMING],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves.cve_2025_55182.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.NOT_VULNERABLE,
            "details": {
                "cve_id": "CVE-2025-55182",
                "confidence": "high",
                "reason": "Server Actions not detected; Flight protocol payload deserialization not reachable on tested endpoints",
                "decision_rule": "_rule_server_actions_missing",
                "surface_detected": True,
                "invocation_expected": False,
                "decode_surface_reached": False,
            },
            "raw_data": {},
        },
    )
    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.INCONCLUSIVE,
            "details": {"cve_id": "CVE-2025-55184", "confidence": "low", "reason": "stub"},
            "raw_data": {},
        },
    )

    with scan_context(extra={}):
        result_55182 = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55182.status == PocStatus.NOT_VULNERABLE
        assert result_55182.details["decision_rule"] == "_rule_server_actions_missing"

        result_55184 = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55184.status == PocStatus.INCONCLUSIVE


def test_55182_html_only_rsc_marks_missing_surface_and_skips_dec2025(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_NEXTJS, TAG_REACT_STREAMING],
        signals={SIG_DETECTION_CONFIDENCE_LEVEL: "low"},
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves.cve_2025_55182.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.NOT_VULNERABLE,
                "details": {
                    "cve_id": "CVE-2025-55182",
                    "confidence": "high",
                    "reason": (
                        "Expected Flight protocol payload deserialization (based on RSC and Server Actions hints), "
                        "but probes returned only HTML; endpoint may be blocked or incorrect"
                    ),
                    "decision_rule": "_rule_html_only_responses",
                    "surface_detected": True,
                    "invocation_expected": None,
                    "decode_surface_reached": False,
            },
            "raw_data": {},
        },
    )
    monkeypatch.setattr(
        "reactguard.vulnerability_detection.cves._rsc_dec2025_base.run_assessor_with_context",
        lambda *_args, **_kwargs: {
            "status": PocStatus.INCONCLUSIVE,
            "details": {"cve_id": "CVE-2025-55184", "confidence": "low", "reason": "stub"},
            "raw_data": {},
        },
    )

    with scan_context(extra={}):
        result_55182 = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55182.status == PocStatus.NOT_VULNERABLE
        assert result_55182.details["decision_rule"] == "_rule_html_only_responses"

        result_55184 = CVE202555184VulnerabilityDetector().evaluate("http://example", detection_result=detection)
        assert result_55184.status == PocStatus.INCONCLUSIVE


def test_waku_entrypoint_missing_is_likely_not_vulnerable(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_WAKU, TAG_RSC],
        signals={"waku_meta_generator": True, SIG_DETECTION_CONFIDENCE_LEVEL: "high"},
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.assessors.waku.resolve_waku_action_endpoints",
        lambda *_args, **_kwargs: ActionResolution(endpoints=[], has_actions=False, discovery_method="none"),
    )

    result = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.NOT_VULNERABLE
    assert "endpoints" in str(result.details.get("reason") or "").lower()


def test_waku_entrypoint_missing_but_expected_is_inconclusive(monkeypatch):
    detection = FrameworkDetectionResult(
        tags=[TAG_WAKU, TAG_RSC],
        signals={
            "waku_meta_generator": True,
            SIG_DETECTION_CONFIDENCE_LEVEL: "high",
            SIG_INVOCATION_ENABLED: True,
        },
    )

    monkeypatch.setattr(
        "reactguard.vulnerability_detection.assessors.waku.resolve_waku_action_endpoints",
        lambda *_args, **_kwargs: ActionResolution(endpoints=[], has_actions=False, discovery_method="none"),
    )

    result = CVE202555182VulnerabilityDetector().evaluate("http://example", detection_result=detection)
    assert result.status == PocStatus.INCONCLUSIVE
    assert "endpoints" in str(result.details.get("reason") or "").lower()
