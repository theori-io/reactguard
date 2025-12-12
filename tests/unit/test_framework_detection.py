from reactguard.framework_detection.engine import FrameworkDetectionEngine
from reactguard.framework_detection.frameworks.generic_rsc import GenericRSCDetector
from reactguard.framework_detection.frameworks.nextjs import NextJSDetector
from reactguard.framework_detection.frameworks.react_router import ReactRouterDetector
from reactguard.framework_detection.frameworks.spa import SPADetector
from reactguard.framework_detection.frameworks.waku import WakuDetector
from reactguard.framework_detection.scoring import score_confidence
from reactguard.http.models import HttpResponse
from reactguard.models import ScanRequest
from reactguard.utils.tag_manager import TagSet


def test_score_confidence_with_strong_and_supporting_signals():
    signals = {
        "nextjs_hydration_array": True,
        "vite_assets": True,
        "server_actions_enabled": True,
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
        "reactguard.framework_detection.frameworks.nextjs.probe_server_actions_support",
        lambda *_, **__: {"supported": False, "status_code": 404, "has_framework_html_marker": True},
    )
    result = FrameworkDetectionEngine().detect(ScanRequest(url=None, response=response))
    assert "nextjs" in result.tags
    assert result.signals["detection_confidence"] > 0
    assert result.signals["detection_confidence_level"] in {"medium", "high"}
    assert result.signals["detected_next_version"] == "15.0.0"


def test_framework_detection_engine_fetch_error(monkeypatch):
    monkeypatch.setattr(
        "reactguard.framework_detection.engine.send_with_retries",
        lambda *_, **__: HttpResponse(ok=False, error_category="TIMEOUT", error_message="fail", url="http://example"),
    )
    result = FrameworkDetectionEngine().detect(ScanRequest(url="http://example"))
    assert result.signals["fetch_error_category"] == "TIMEOUT"


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
    FrameworkDetectionEngine._apply_rsc_flags(tags, signals)
    assert signals["rsc_dependency_only"] is True


def test_nextjs_detector_infers_react_major_from_flight():
    assert NextJSDetector._react_major_from_flight('0:[null,["$"') == 19
    assert NextJSDetector._react_major_from_flight('0:"$L') == 18
    assert NextJSDetector._react_major_from_flight("") is None


def test_spa_detector_tags_react_spa(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.frameworks.spa.probe_js_bundles", lambda *_, **__: {"react_bundle": True})
    detector = SPADetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='<div id="root"></div><script type="module" src="/assets/main.js"></script><div data-reactroot="1"></div>',
        headers={},
        tags=tags,
        signals=signals,
        context=type("Ctx", (), {"url": "http://example", "proxy_profile": None, "correlation_id": None, "http_client": None})(),
    )
    assert "react-spa" in tags
    assert signals["react_spa_structure"] is True


def test_waku_detector_collects_signals(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.frameworks.waku.probe_waku_minimal_html", lambda *_, **__: True)
    monkeypatch.setattr("reactguard.framework_detection.frameworks.waku.probe_waku_rsc_surface", lambda *_, **__: False)
    monkeypatch.setattr(
        "reactguard.framework_detection.frameworks.waku.probe_waku_server_actions",
        lambda *_, **__: (True, 2, [("/RSC/F/abc/action.txt", "runAction")]),
    )
    detector = WakuDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='<meta name="generator" content="Waku"><script>var __waku_root=true;globalThis.wakuRoot=true</script>',
        headers={"x-waku-version": "0.19.0"},
        tags=tags,
        signals=signals,
        context=type("Ctx", (), {"url": "http://example", "proxy_profile": None, "correlation_id": None, "http_client": None})(),
    )
    assert "waku" in tags and "rsc" in tags
    assert signals["server_actions_enabled"] is True
    assert signals["rsc_endpoint_found"] is True
    assert signals["server_action_endpoints"]


def test_expo_detector_sets_experimental_flags(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.frameworks.expo.probe_js_bundles", lambda *_, **__: {"expo_router": True, "react_bundle": True})
    monkeypatch.setattr(
        "reactguard.framework_detection.frameworks.expo.apply_rsc_probe_results",
        lambda *_, **__: {"rsc_endpoint_found": True, "server_actions_enabled": True},
    )
    detector = __import__("reactguard.framework_detection.frameworks.expo", fromlist=["ExpoDetector"]).ExpoDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='__EXPO_ROUTER_HYDRATE__<div id="root"></div><style id="expo-reset"></style>',
        headers={},
        tags=tags,
        signals=signals,
        context=type("Ctx", (), {"url": "http://example", "proxy_profile": None, "correlation_id": None, "http_client": None})(),
    )
    assert "expo" in tags
    assert signals["expo_rsc_experimental"] is True
    assert signals["expo_router"] is True


def test_react_router_detector_rsc_tag(monkeypatch):
    monkeypatch.setattr("reactguard.framework_detection.frameworks.react_router.probe_js_bundles", lambda *_, **__: {"react_router_v7_bundle": True})

    def fake_apply_rsc_probe_results(*_, **kwargs):
        tags = kwargs.get("tags")
        signals = kwargs.get("signals")
        if signals is not None:
            signals["server_actions_enabled"] = True
            signals["rsc_endpoint_found"] = True
        if tags is not None:
            tags.add("react-router-v7-rsc")
        return {"rsc_endpoint_found": True, "server_actions_enabled": True}

    monkeypatch.setattr("reactguard.framework_detection.frameworks.react_router.apply_rsc_probe_results", fake_apply_rsc_probe_results)

    detector = ReactRouterDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='__reactRouterManifest {"__reactRouterVersion":"7.0.0"}',
        headers={},
        tags=tags,
        signals=signals,
        context=type("Ctx", (), {"url": "http://example", "proxy_profile": None, "correlation_id": None, "http_client": None})(),
    )
    assert "react-router-v7" in tags
    assert signals["react_router_confidence"] == "high"
    assert signals["server_actions_enabled"] is True


def test_generic_rsc_detector_sets_signals():
    detector = GenericRSCDetector()
    tags = TagSet()
    signals = {}
    detector.detect(
        body='0:["$","$L"]\n<!--$-->',
        headers={"content-type": "text/x-component"},
        tags=tags,
        signals=signals,
        context=None,
    )
    assert "rsc" in tags
    assert "react-streaming" in tags
    assert signals["rsc_content_type"] is True
    assert signals["react_streaming_markers"] is True
