from reactguard.framework_detection.signals import bundle, rsc, server_actions, waku
from reactguard.utils.tag_manager import TagSet


def test_extract_js_urls_normalizes_and_prioritizes():
    base_url = "http://example/app/"
    body = """
    <script src="/_next/static/chunk.js"></script>
    <script src="main.js"></script>
    <script src="//cdn.example.com/lib.js"></script>
    """
    urls = bundle.extract_js_urls(body, base_url)
    assert urls[0].startswith("http://example/_next/static")
    assert any(u.startswith("http://example/app/main.js") for u in urls)
    assert any(u.startswith("http://cdn.example.com") for u in urls)


def test_probe_js_bundles_detects_router(monkeypatch):
    calls = []

    def fake_scan(url, **kwargs):  # noqa: ARG001
        calls.append(url)
        return {"ok": True, "status_code": 200, "body": '__reactRouterManifest "react-router@7.0.0"', "headers": {}}

    monkeypatch.setattr(bundle, "scan_with_retry", fake_scan)
    signals = bundle.probe_js_bundles("http://example", '<script src="/_next/static/chunk.js"></script>')
    assert signals["react_router_v7_bundle"] is True
    assert calls


def test_probe_rsc_endpoint_and_actions(monkeypatch):
    monkeypatch.setattr(
        rsc,
        "scan_with_retry",
        lambda *_, **__: {"ok": True, "status_code": 200, "headers": {"content-type": "text/x-component"}, "body": "0:[", "body_snippet": "0:["},
    )
    assert rsc.probe_rsc_endpoint("http://example") is True

    calls = []

    def fake_probe(url, **kwargs):
        calls.append((url, kwargs.get("payload_style")))
        return {"supported": kwargs.get("payload_style") == "multipart"}

    monkeypatch.setattr(rsc, "probe_server_actions_support", fake_probe)
    assert rsc.probe_server_actions("http://example") is True
    assert ("http://example", "plain") in calls and ("http://example", "multipart") in calls


def test_apply_rsc_probe_results_promotes_signals(monkeypatch):
    tags = TagSet()
    signals = {}
    monkeypatch.setattr(rsc, "probe_rsc_and_actions", lambda *_, **__: {"rsc_endpoint_found": False, "server_actions_enabled": True})
    result = rsc.apply_rsc_probe_results(
        "http://example",
        tags=tags,
        signals=signals,
        rsc_tag="rsc-tag",
        server_actions_tag="actions",
        server_actions_imply_rsc=True,
        set_defaults=True,
    )
    assert result["server_actions_enabled"] is True
    assert "actions" in tags
    assert "rsc-tag" in tags
    assert signals["rsc_endpoint_found"] is True


def test_probe_server_actions_support_reads_rsc(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "scan_with_retry",
        lambda *_, **__: {
            "ok": True,
            "status_code": 200,
            "headers": {"content-type": "text/x-component", "vary": "RSC", "x-nextjs-action-not-found": "1"},
            "body": '0:{"a":"$@"}',
            "body_snippet": '0:{"a":"$@"}',
        },
    )
    result = server_actions.probe_server_actions_support("http://example")
    assert result["supported"] is True
    assert result["has_action_content_type"] is True
    assert result["action_not_found_header"] is True
    assert result["has_flight_marker"] is True


def test_apply_server_actions_probe_results_sets_tags():
    tags = TagSet()
    signals = {}
    probe_result = {
        "status_code": 404,
        "has_framework_html_marker": True,
        "has_action_keywords": True,
        "has_action_content_type": True,
        "has_flight_marker": True,
        "has_digest": False,
        "is_html": False,
        "action_not_found_header": False,
        "action_not_found_body": True,
        "vary_has_rsc": True,
        "flight_format": "object",
        "react_major_from_flight": 19,
    }
    outcome = server_actions.apply_server_actions_probe_results(
        base_url="http://example",
        probe_result=probe_result,
        tags=tags,
        signals=signals,
        server_actions_tag="actions",
        not_found_signal_key="not_found",
        vary_signal_key="vary_rsc",
        react_major_signal_key="detected_react_major",
        rsc_flight_signal_key="rsc_flight_payload",
        fallback_html_signal_key="fallback_html",
    )
    assert outcome["supported"] is True
    assert signals["server_actions_enabled"] is True
    assert signals["not_found"] is True
    assert signals["vary_rsc"] is True
    assert signals["detected_react_major"] == 19
    assert signals["rsc_flight_payload"] is True
    assert "actions" in tags


def test_probe_waku_rsc_surface_and_minimal_html(monkeypatch):
    monkeypatch.setattr(
        waku,
        "scan_with_retry",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {"content-type": "text/x-component"},
            "body": "0:[",
            "body_snippet": "0:[",
        },
    )
    assert waku.probe_waku_rsc_surface("http://example")
    minimal_body = '<html><body><script>import("x")</script></body></html>'
    assert waku.probe_waku_minimal_html(minimal_body, "http://example")


def test_probe_waku_server_actions_extracts_endpoints(monkeypatch):
    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith(".js"):
            return {
                "ok": True,
                "status_code": 200,
                "headers": {},
                "body": '"abcdef123456#actionOne"',
                "body_snippet": '"abcdef123456#actionOne"',
            }
        return {
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": "/RSC/F/123456789abc/actionTwo.txt",
            "body_snippet": "/RSC/F/123456789abc/actionTwo.txt",
        }

    monkeypatch.setattr(waku, "scan_with_retry", fake_scan)
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert count == len(endpoints) >= 1
    assert any(ep.endswith(".txt") for ep, _ in endpoints)


def test_probe_waku_server_actions_create_server_refs(monkeypatch):
    bodies = {
        "http://example": {
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": 'createServerReference("src/app/actions#run")',
            "body_snippet": 'createServerReference("src/app/actions#run")',
        },
        "http://example/src/app/actions.ts": {
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": '"123456789abc#foo"',
            "body_snippet": '"123456789abc#foo"',
        },
    }

    def fake_scan(url, **kwargs):  # noqa: ARG001
        return bodies.get(url, {"ok": False, "status_code": 404, "headers": {}, "body": "", "body_snippet": ""})

    monkeypatch.setattr(waku, "scan_with_retry", fake_scan)
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert any("createServerReference" in ep for ep, _ in endpoints) or endpoints
