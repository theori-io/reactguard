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

    monkeypatch.setattr(bundle, "request_with_retries", fake_scan)
    signals = bundle.probe_js_bundles("http://example", '<script src="/_next/static/chunk.js"></script>')
    assert signals["react_router_v7_bundle"] is True
    assert calls


def test_probe_rsc_endpoint_and_actions(monkeypatch):
    monkeypatch.setattr(
        rsc,
        "request_with_retries",
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
        "request_with_retries",
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
    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith("/RSC/_"):
            return {"ok": True, "status_code": 200, "headers": {"content-type": "text/x-component"}, "body": "0:[", "body_snippet": "0:["}
        if url.endswith("/assets/index.js"):
            return {"ok": True, "status_code": 200, "headers": {"content-type": "application/javascript"}, "body": "globalThis.__WAKU_HYDRATE__=true;", "body_snippet": ""}
        return {"ok": False, "status_code": 404, "headers": {}, "body": "", "body_snippet": ""}

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
    assert waku.probe_waku_rsc_surface("http://example")
    minimal_body = '<html><body><script>import("/assets/index.js")</script></body></html>'
    assert waku.probe_waku_minimal_html(minimal_body, "http://example")


def test_probe_waku_rsc_surface_rejects_plaintext_404(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 404,
            "headers": {"content-type": "text/plain"},
            "body": "Not Found",
            "body_snippet": "Not Found",
        },
    )
    assert waku.probe_waku_rsc_surface("http://example") is False


def test_probe_waku_rsc_surface_requires_flight_for_text_plain(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {"content-type": "text/plain"},
            "body": "Not Found",
            "body_snippet": "Not Found",
        },
    )
    assert waku.probe_waku_rsc_surface("http://example") is False

    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {"content-type": "text/plain"},
            "body": '0:[null,["$","$L1",null,{"foo":"bar"}]]',
            "body_snippet": "0:[",
        },
    )
    assert waku.probe_waku_rsc_surface("http://example") is True


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

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
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

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert any("createServerReference" in ep for ep, _ in endpoints) or endpoints


def test_probe_waku_server_actions_extracts_rsc_extension_and_uppercase_hash(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": "/RSC/F/ABCDEF1234567890/act$ion-Name.rsc",
            "body_snippet": "/RSC/F/ABCDEF1234567890/act$ion-Name.rsc",
        },
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert count == len(endpoints) >= 1
    assert any(ep.endswith(".rsc") for ep, _ in endpoints)
    assert any("act$ion-Name" in ep for ep, _ in endpoints)


def test_probe_waku_server_actions_extracts_prefetched_rsc_route_endpoints(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": "globalThis.__WAKU_PREFETCHED__ = {'/RSC/index.txt': Promise.resolve(1)};",
            "body_snippet": "globalThis.__WAKU_PREFETCHED__ = {'/RSC/index.txt': Promise.resolve(1)};",
        },
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is False
    assert count == len(endpoints) >= 1
    assert any(ep == "/RSC/index.txt" for ep, _ in endpoints)


def test_probe_waku_server_actions_prefetch_requires_react_action_form(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": "<form action=\"javascript:throw new Error('React form unexpectedly submitted.')\"></form>"
            "globalThis.__WAKU_PREFETCHED__ = {'/RSC/index.txt': Promise.resolve(1)};",
            "body_snippet": "<form action=\"javascript:throw new Error('React form unexpectedly submitted.')\"></form>"
            "globalThis.__WAKU_PREFETCHED__ = {'/RSC/index.txt': Promise.resolve(1)};",
        },
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert count == len(endpoints) >= 1
    assert any(ep == "/RSC/index.txt" for ep, _ in endpoints)


def test_probe_waku_server_actions_extracts_prefetched_route_keys(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: {  # noqa: ARG001
            "ok": True,
            "status_code": 200,
            "headers": {},
            "body": 'globalThis.__WAKU_PREFETCHED__ = {\"R/_root\": Promise.resolve(1)};',
            "body_snippet": 'globalThis.__WAKU_PREFETCHED__ = {\"R/_root\": Promise.resolve(1)};',
        },
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is False
    assert count == len(endpoints) >= 1
    assert any(ep == "/RSC/R/_root.txt" for ep, _ in endpoints)
