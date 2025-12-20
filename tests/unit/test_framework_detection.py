# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.framework_detection.base import DetectionContext, DetectionState
from reactguard.framework_detection.detectors.generic_rsc import GenericRSCDetector
from reactguard.framework_detection.detectors.nextjs import NextJSDetector
from reactguard.framework_detection.detectors.react_router import ReactRouterDetector
from reactguard.framework_detection.detectors.spa import SPADetector
from reactguard.framework_detection.detectors.waku import WakuDetector
from reactguard.framework_detection.engine import FrameworkDetectionEngine
from reactguard.framework_detection.nextjs_flight import infer_nextjs_rsc_signals_from_html
from reactguard.framework_detection.scoring import score_confidence
from reactguard.framework_detection.signals.waku import WakuServerActionsProbeResult
from reactguard.http.models import HttpResponse
from reactguard.models import ScanRequest
from reactguard.utils.tag_manager import TagSet


def test_score_confidence_with_strong_and_supporting_signals():
    signals = {
        "nextjs_hydration_array": True,
        "vite_assets": True,
        "invocation_enabled": True,
        "react_router_confidence": "medium",
    }
    score, level, breakdown = score_confidence(signals)
    assert score >= 40
    assert level in {"medium", "high"}
    assert "nextjs_hydration_array" in breakdown["strong_hits"]


def test_score_confidence_penalizes_mutable_only():
    signals = {"header_powered_by_nextjs": True, "vite_assets": True}
    score, level, breakdown = score_confidence(signals)
    assert "mutable_signals_only" in breakdown["penalties"]
    assert level == "low"
    assert score < 10


def test_framework_detection_engine_runs_detectors(monkeypatch):
    response = HttpResponse(
        ok=True,
        status_code=200,
        headers={"x-nextjs-version": "15.0.0"},
        text='__next_f.push("/_next/static/chunks/app.js");',
        url=None,
    )
    monkeypatch.setattr(
        "reactguard.framework_detection.detectors.nextjs.probe_server_actions_support",
        lambda *_, **__: {"supported": False, "status_code": 404, "has_framework_html_marker": True},
    )
    result = FrameworkDetectionEngine().detect(ScanRequest(url=None, response=response))
    assert "nextjs" in result.tags
    assert result.signals["detection_confidence"] > 0
    assert result.signals["detection_confidence_level"] in {"medium", "high"}
    assert result.signals["detected_next_version"] == "15.0.0"


def test_framework_detection_engine_detects_nextjs_without_version_headers(monkeypatch):
    response = HttpResponse(
        ok=True,
        status_code=200,
        headers={},
        text='__next_f.push("/_next/static/chunks/app.js");',
        url="http://example",
    )
    monkeypatch.setattr(
        "reactguard.framework_detection.detectors.nextjs.probe_server_actions_support",
        lambda *_, **__: {"supported": False, "status_code": 404, "has_framework_html_marker": True},
    )
    result = FrameworkDetectionEngine().detect(ScanRequest(url="http://example", response=response))
    assert "nextjs" in result.tags
    assert result.signals["detection_confidence_level"] in {"medium", "high"}


def test_framework_detection_engine_fetch_error(monkeypatch):
    monkeypatch.setattr(
        "reactguard.framework_detection.engine.send_with_retries",
        lambda *_, **__: HttpResponse(ok=False, error_message="fail", error_type="TimeoutException", url="http://example"),
    )
    result = FrameworkDetectionEngine().detect(ScanRequest(url="http://example"))
    assert result.signals["fetch_error_message"] == "fail"


def test_normalize_headers_merges_response_headers():
    request = ScanRequest(url="http://example", response_headers={"X-Test": "client", "X-Only-Offline": "1"})
    response = HttpResponse(
        ok=True,
        status_code=200,
        headers={"X-Test": "server", "X-Nextjs-Version": "15.0.0"},
        text="",
        url="http://example",
    )
    normalized = FrameworkDetectionEngine._normalize_headers(request, response)
    assert normalized["x-nextjs-version"] == "15.0.0"
    assert normalized["x-test"] == "server"
    assert normalized["x-only-offline"] == "1"


def test_apply_rsc_flags_marks_dependency_only():
    tags = TagSet()
    signals = {"react_bundle": True, "rsc_endpoint_found": False}
    FrameworkDetectionEngine._apply_rsc_flags(DetectionState(tags=tags, signals=signals))
    assert signals["react_bundle_only"] is True


def test_apply_rsc_flags_marks_rsc_runtime_dependency_only():
    tags = TagSet()
    signals = {"react_bundle": True, "react_server_dom_bundle": True, "rsc_endpoint_found": False}
    FrameworkDetectionEngine._apply_rsc_flags(DetectionState(tags=tags, signals=signals))
    assert signals["rsc_dependency_only"] is True


def test_nextjs_detector_infers_react_major_from_flight():
    assert NextJSDetector._react_major_from_flight('0:[null,["$"') == 18
    assert NextJSDetector._react_major_from_flight('__next_f.push([]);0:{\\"P\\":null') == 19
    assert NextJSDetector._react_major_from_flight('0:"$L') == 18
    assert NextJSDetector._react_major_from_flight("") is None


def test_infer_nextjs_rsc_signals_from_html():
    assert infer_nextjs_rsc_signals_from_html("") == (False, None)
    assert infer_nextjs_rsc_signals_from_html("__next_f.push([])")[0] is True

    is_rsc, major = infer_nextjs_rsc_signals_from_html('__next_f.push([]);0:{\\"P\\":null')
    assert is_rsc is True
    assert major == 19

    is_rsc, major = infer_nextjs_rsc_signals_from_html('0:"$L1"')
    assert is_rsc is True
    assert major == 18


def test_nextjs_detector_does_not_infer_react_major_from_non_nextjs_html():
    """
    Guard against false positives from HTML containing JS object literals with numeric keys like `0:{...}`.
    """
    detector = NextJSDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body=r'<html><body><script>var s="0:{\"P\":null}";var x={0:{a:1}};</script></body></html>',
        headers={},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url=None, http_client=None),
    )
    assert "nextjs" not in tags
    assert signals.get("detected_react_major") is None


def test_spa_detector_tags_react_spa(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.detectors.spa.probe_js_bundles", lambda *_, **__: {"react_bundle": True})
    detector = SPADetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='<div id="root"></div><script type="module" src="/assets/main.js"></script><div data-reactroot="1"></div>',
        headers={},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url="http://example", http_client=None),
    )
    assert "react-spa" in tags
    assert signals["react_spa_structure"] is True


def test_waku_detector_collects_signals(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.detectors.waku.probe_waku_minimal_html", lambda *_, **__: True)
    monkeypatch.setattr("reactguard.framework_detection.detectors.waku.probe_waku_rsc_surface", lambda *_, **__: False)
    monkeypatch.setattr(
        "reactguard.framework_detection.detectors.waku.probe_waku_server_actions_result",
        lambda *_, **__: WakuServerActionsProbeResult(has_actions=True, count=2, endpoints=[("/RSC/F/abc/action.txt", "runAction")]),
    )
    detector = WakuDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='<meta name="generator" content="Waku"><script>var __waku_root=true;globalThis.wakuRoot=true</script>',
        headers={"x-waku-version": "0.19.0"},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url="http://example", http_client=None),
    )
    assert "waku" in tags and "rsc" in tags
    assert signals["invocation_enabled"] is True
    assert signals["rsc_endpoint_found"] is True
    assert signals["invocation_endpoints"]


def test_expo_detector_tags_framework(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.detectors.expo.probe_js_bundles", lambda *_, **__: {"expo_router": True, "react_bundle": True})
    monkeypatch.setattr(
        "reactguard.framework_detection.detectors.expo.probe_expo_server_functions",
        lambda *_args, **_kwargs: type(
            "ExpoProbe",
            (),
            {"has_rsc_surface": False, "invocation_endpoints": [], "evidence": {}},
        )(),
    )
    detector = __import__("reactguard.framework_detection.detectors.expo", fromlist=["ExpoDetector"]).ExpoDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='__EXPO_ROUTER_HYDRATE__<div id="root"></div><style id="expo-reset"></style>',
        headers={},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url="http://example", http_client=None),
    )
    assert "expo" in tags
    assert signals["expo_router"] is True


def test_react_router_detector_does_not_probe_rsc(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.detectors.react_router.probe_js_bundles", lambda *_, **__: {"react_router_v7_bundle": True})

    detector = ReactRouterDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='__reactRouterManifest {"__reactRouterVersion":"7.0.0"}',
        headers={},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url="http://example", http_client=None),
    )
    assert "react-router-v7" in tags
    assert signals["react_router_confidence"] == "high"
    assert signals.get("invocation_enabled") is None


def test_generic_rsc_detector_sets_signals():
    detector = GenericRSCDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='0:["$","$L"]\n<!--$-->',
        headers={"content-type": "text/x-component"},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url=None, http_client=None),
    )
    assert "rsc" in tags
    assert "react-streaming" in tags
    assert signals["rsc_content_type"] is True
    assert signals["react_streaming_markers"] is True


def test_generic_rsc_detector_does_not_flag_html_with_embedded_flight():
    detector = GenericRSCDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body="<html><body><script>\n0:[null,[\"$\",\"$L1\",null]]\n</script></body></html>",
        headers={"content-type": "text/html"},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url=None, http_client=None),
    )
    assert "rsc" not in tags
    assert signals.get("rsc_content_type") is None
    assert signals.get("rsc_flight_payload") is None


def test_react_major_evidence_conflict_is_annotated():
    signals = {
        "detected_react_major": 18,
        "detected_react_major_confidence": "high",
        "detected_react_major_source": "flight:nextjs_html",
        "detected_rsc_runtime_version": "19.0.0",
        "detected_rsc_runtime_version_confidence": "high",
        "detected_rsc_runtime_version_source": "header",
    }
    FrameworkDetectionEngine._annotate_react_major_evidence(signals)
    assert signals["react_major_conflict"] is True
    assert signals["react_major_conflict_confidence"] == "high"
    assert signals["react_major_conflict_majors"] == [18, 19]
    assert {entry.get("major") for entry in signals.get("react_major_evidence") or []} == {18, 19}


def test_react_router_detector_sets_server_functions_when_action_id_present():
    detector = ReactRouterDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='<form action="/submit" method="POST"><input type="hidden" name="$ACTION_ID_abcd#run" /></form>',
        headers={},
        state=DetectionState(tags=tags, signals=signals),
        context=DetectionContext(url="http://example/app", http_client=None),
    )
    assert "react-router-v7" in tags
    assert "react-router-v7-rsc" in tags
    assert "react-router-v7-server-actions" in tags
    assert signals["react_router_confidence"] == "high"
    assert signals["react_router_server_action_ids"] == ["abcd#run"]
    assert signals["rsc_endpoint_found"] is True
    assert signals["invocation_enabled"] is True
    assert signals["invocation_confidence"] == "high"
    assert any("submit" in ep for ep in signals.get("invocation_endpoints") or [])
