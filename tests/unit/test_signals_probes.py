# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.framework_detection.signals import bundle, expo_server_functions, react_router_server_functions, rsc, server_actions, waku
from reactguard.http.js import extract_js_asset_urls
from reactguard.http.models import HttpResponse
from reactguard.utils.context import scan_context
from reactguard.utils.tag_manager import TagSet


def http_response(*, ok=True, status_code=200, body="", headers=None, url=None, error_message=None, error_type=None):
    text = str(body or "")
    return HttpResponse(
        ok=ok,
        status_code=status_code,
        headers=headers or {},
        text=text,
        content=text.encode(),
        url=url,
        error_message=error_message,
        error_type=error_type,
    )


def test_extract_js_urls_normalizes_and_prioritizes():
    base_url = "http://example/app/"
    body = """
    <script src="/_next/static/chunk.js"></script>
    <script src="main.js"></script>
    <script src="//cdn.example.com/lib.js"></script>
    """
    urls = extract_js_asset_urls(body, base_url)
    assert urls[0].startswith("http://example/_next/static")
    assert any(u.startswith("http://example/app/main.js") for u in urls)
    assert not any(u.startswith("http://cdn.example.com") for u in urls)


def test_extract_js_urls_allows_same_site_subdomains():
    base_url = "https://app.example.com"
    body = """
    <script src="https://static.example.com/assets/app.js"></script>
    <script src="https://cdn.other.com/assets/other.js"></script>
    """
    urls = extract_js_asset_urls(body, base_url, allow_same_site=True)
    assert any("static.example.com" in u for u in urls)
    assert not any("cdn.other.com" in u for u in urls)


def test_probe_js_bundles_detects_router(monkeypatch):
    calls = []

    def fake_scan(url, **kwargs):  # noqa: ARG001
        calls.append(url)
        return http_response(status_code=200, body='__reactRouterManifest "react-router@7.0.0"')

    monkeypatch.setattr(bundle, "request_with_retries", fake_scan)
    signals = bundle.probe_js_bundles("http://example", '<script src="/_next/static/chunk.js"></script>')
    assert signals["react_router_v7_bundle"] is True
    assert calls


def test_probe_js_bundles_derives_react_major_from_selected_version(monkeypatch):
    """
    When multiple bundles embed different `react@x.y.z` literals at equal confidence,
    `probe_js_bundles()` should keep `bundle_react_major` consistent with the chosen
    `bundle_react_version` (avoid flakiness across bundle ordering/failures).
    """

    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith("a.js"):
            return http_response(status_code=200, body="react@18.2.0")
        if url.endswith("b.js"):
            return http_response(status_code=200, body="react@19.2.0")
        return http_response(ok=False, status_code=404, body="")

    monkeypatch.setattr(bundle, "request_with_retries", fake_scan)
    html = '<script src="/a.js"></script><script src="/b.js"></script>'
    signals = bundle.probe_js_bundles("http://example", html)
    assert signals["bundle_react_version"] == "19.2.0"
    assert signals["bundle_react_major"] == 19


def test_probe_js_bundles_caches_within_scan(monkeypatch):
    calls = []

    def fake_scan(url, **kwargs):  # noqa: ARG001
        calls.append(url)
        return http_response(status_code=200, body="react@19.0.0")

    monkeypatch.setattr(bundle, "request_with_retries", fake_scan)
    html = '<script src="/a.js"></script>'
    with scan_context(extra={}):
        first = bundle.probe_js_bundles("http://example", html)
        second = bundle.probe_js_bundles("http://example", html)
    assert first == second
    assert len(calls) == 1


def test_discover_react_router_server_functions_extracts_ids_and_endpoints():
    html = """
    <html>
      <body>
        <form action="/submit" method="POST">
          <input type="hidden" name="$ACTION_ID_abcd#run" />
          <input type="text" name="x" value="1" />
        </form>
      </body>
    </html>
    """
    discovery = react_router_server_functions.discover_react_router_server_functions(html, "http://example/app")
    assert discovery.action_ids == ["abcd#run"]
    assert "http://example/submit" in discovery.action_endpoints
    assert "http://example/app/submit" in discovery.action_endpoints


def test_discover_react_router_server_functions_falls_back_to_bundle_scan(monkeypatch):
    html = '<html><head><script src="/assets/app.js"></script></head><body></body></html>'

    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith("/assets/app.js"):
            body = 'const x = "$ACTION_ID_abcd#run";'
            return http_response(status_code=200, body=body, headers={"content-type": "application/javascript"}, url=url)
        return http_response(ok=False, status_code=404, body="", url=url)

    monkeypatch.setattr(react_router_server_functions, "request_with_retries", fake_scan)
    discovery = react_router_server_functions.discover_react_router_server_functions(html, "http://example/app")
    assert discovery.action_ids == ["abcd#run"]
    assert discovery.action_endpoints == ["http://example/app"]


def test_probe_expo_server_functions_discovers_action_endpoint(monkeypatch):
    flight_body = "\n".join(
        [
            '1:I["components/CallServerFunction.tsx",["/components/CallServerFunction.tsx.bundle?xRSC=1"],"CallServerFunction",1]',
            '0:{"page":["$","$L1",null,{}]}',
        ]
    )
    bundle_body = "const x = './actions/call-action.ts#echo';"

    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith("/_flight/web/index.txt"):
            return http_response(status_code=200, body=flight_body, headers={"content-type": "text/plain"}, url=url)
        if "CallServerFunction.tsx.bundle" in url:
            return http_response(status_code=200, body=bundle_body, headers={"content-type": "application/javascript"}, url=url)
        return http_response(ok=False, status_code=404, body="", url=url)

    monkeypatch.setattr(expo_server_functions, "request_with_retries", fake_scan)
    result = expo_server_functions.probe_expo_server_functions("http://example/app")
    assert result.has_rsc_surface is True
    assert any("/_flight/web/ACTION_./actions/call-action.ts/echo.txt" in ep for ep in result.invocation_endpoints)


def test_probe_rsc_endpoint_and_actions(monkeypatch):
    calls = []

    def fake_scan(url, **kwargs):  # noqa: ARG001
        calls.append(url)
        return http_response(status_code=200, body="0:[", headers={"content-type": "text/x-component"})

    monkeypatch.setattr(rsc, "request_with_retries", fake_scan)
    assert rsc.probe_rsc_endpoint("http://example") is True
    assert calls == ["http://example"]

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
    monkeypatch.setattr(rsc, "probe_rsc_and_actions", lambda *_, **__: {"rsc_endpoint_found": False, "invocation_enabled": True})
    result = rsc.apply_rsc_probe_results(
        "http://example",
        tags=tags,
        signals=signals,
        rsc_tag="rsc-tag",
        server_actions_tag="actions",
        server_actions_imply_rsc=True,
        set_defaults=True,
    )
    assert result["invocation_enabled"] is True
    assert "actions" in tags
    assert "rsc-tag" in tags
    assert signals["rsc_endpoint_found"] is True


def test_probe_server_actions_support_reads_rsc(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: http_response(
            status_code=200,
            body='0:{"a":"$@"}',
            headers={"content-type": "text/x-component", "vary": "RSC", "x-nextjs-action-not-found": "1"},
        ),
    )
    result = server_actions.probe_server_actions_support("http://example")
    assert result["supported"] is True
    assert result["has_action_content_type"] is True
    assert result["action_not_found_header"] is True
    assert result["has_flight_marker"] is True


def test_probe_server_actions_support_uses_vary_rsc_when_body_is_empty(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: http_response(status_code=200, body="", headers={"vary": "RSC"}),
    )
    result = server_actions.probe_server_actions_support("http://example")
    assert result["supported"] is True
    assert result["confidence"] in {"medium", "high"}
    assert result["vary_has_rsc"] is True


def test_probe_server_actions_support_does_not_use_vary_rsc_on_404(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: http_response(status_code=404, body="Not Found", headers={"vary": "RSC", "content-type": "text/plain"}),
    )
    result = server_actions.probe_server_actions_support("http://example")
    assert result["supported"] is False
    assert result["vary_has_rsc"] is True


def test_probe_server_actions_support_does_not_treat_plain_json_as_strong_signal(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: http_response(status_code=200, body='{"error":"nope"}', headers={"content-type": "application/json"}),
    )
    result = server_actions.probe_server_actions_support("http://example")
    assert result["supported"] is False
    assert result["has_action_content_type"] is False
    assert result["has_digest"] is False


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
    assert signals["invocation_enabled"] is True
    assert signals["not_found"] is True
    assert signals["vary_rsc"] is True
    assert signals["detected_react_major"] == 19
    assert signals["rsc_flight_payload"] is True
    assert "actions" in tags


def test_probe_waku_rsc_surface_and_minimal_html(monkeypatch):
    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith("/RSC/_"):
            return http_response(status_code=200, body="0:[", headers={"content-type": "text/x-component"})
        if url.endswith("/assets/index.js"):
            return http_response(status_code=200, body="globalThis.__WAKU_HYDRATE__=true;", headers={"content-type": "application/javascript"})
        return http_response(ok=False, status_code=404, body="")

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
    assert waku.probe_waku_rsc_surface("http://example")
    minimal_body = """
    <html>
      <head></head>
      <body>
        <script type="module">
          import("/assets/index.js")
        </script>
      </body>
    </html>
    """
    assert waku.probe_waku_minimal_html(minimal_body, "http://example")


def test_probe_waku_rsc_surface_rejects_plaintext_404(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=404,
            body="Not Found",
            headers={"content-type": "text/plain"},
        ),
    )
    assert waku.probe_waku_rsc_surface("http://example") is False


def test_probe_waku_rsc_surface_requires_flight_for_text_plain(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=200,
            body="Not Found",
            headers={"content-type": "text/plain"},
        ),
    )
    assert waku.probe_waku_rsc_surface("http://example") is False

    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=200,
            body='0:[null,["$","$L1",null,{"foo":"bar"}]]',
            headers={"content-type": "text/plain"},
        ),
    )
    assert waku.probe_waku_rsc_surface("http://example") is True


def test_probe_waku_server_actions_extracts_endpoints(monkeypatch):
    def fake_scan(url, **kwargs):  # noqa: ARG001
        if url.endswith(".js"):
            return http_response(status_code=200, body='"abcdef123456#actionOne"')
        return http_response(status_code=200, body="/RSC/F/123456789abc/actionTwo.txt")

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert count == len(endpoints) >= 1
    assert any(ep.endswith(".txt") for ep, _ in endpoints)


def test_probe_waku_server_actions_create_server_refs(monkeypatch):
    bodies = {
        "http://example": http_response(status_code=200, body='createServerReference("src/app/actions#run")'),
        "http://example/src/app/actions.ts": http_response(status_code=200, body='"123456789abc#foo"'),
    }

    def fake_scan(url, **kwargs):  # noqa: ARG001
        return bodies.get(url, http_response(ok=False, status_code=404, body=""))

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert any("createServerReference" in ep for ep, _ in endpoints) or endpoints


def test_probe_waku_server_actions_extracts_txt_extension_and_uppercase_hash(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=200,
            body="/RSC/F/ABCDEF1234567890/act$ion-Name.txt",
        ),
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert count == len(endpoints) >= 1
    assert any(ep.endswith(".txt") for ep, _ in endpoints)
    assert any("act$ion-Name" in ep for ep, _ in endpoints)


def test_probe_waku_server_actions_extracts_prefetched_rsc_route_endpoints(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=200,
            body="globalThis.__WAKU_PREFETCHED__ = {'/RSC/index.txt': Promise.resolve(1)};",
        ),
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is False
    assert count == len(endpoints) >= 1
    assert any(ep == "/RSC/index.txt" for ep, _ in endpoints)


def test_probe_waku_server_actions_prefetch_does_not_imply_actions(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=200,
            body=(
                '<form action="javascript:throw new Error(\'React form unexpectedly submitted.\')"></form>'
                "globalThis.__WAKU_PREFETCHED__ = {'/RSC/index.txt': Promise.resolve(1)};"
            ),
        ),
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is False
    assert count == len(endpoints) >= 1
    assert any(ep == "/RSC/index.txt" for ep, _ in endpoints)


def test_probe_waku_server_actions_follows_imports(monkeypatch):
    bodies = {
        "http://example": http_response(
            status_code=200,
            body='<html><body><script type="module" src="/src/components/ActionForm.tsx"></script></body></html>',
        ),
        "http://example/src/components/ActionForm.tsx": http_response(
            status_code=200,
            body='import {logFieldUpdate} from "/src/actions.ts";',
            headers={"content-type": "text/javascript"},
        ),
        "http://example/src/actions.ts": http_response(
            status_code=200,
            body='createServerReference("/app/src/actions.ts#logFieldUpdate")',
            headers={"content-type": "text/javascript"},
        ),
    }

    def fake_scan(url, **kwargs):  # noqa: ARG001
        return bodies.get(
            url,
            http_response(ok=True, status_code=404, body="Not Found", headers={"content-type": "text/plain"}),
        )

    monkeypatch.setattr(waku, "request_with_retries", fake_scan)
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is True
    assert count == len(endpoints) >= 1
    assert any("/RSC/ACTION_" in ep for ep, _ in endpoints)


def test_probe_waku_server_actions_extracts_prefetched_route_keys(monkeypatch):
    monkeypatch.setattr(
        waku,
        "request_with_retries",
        lambda url, **kwargs: http_response(  # noqa: ARG001
            ok=True,
            status_code=200,
            body='globalThis.__WAKU_PREFETCHED__ = {"R/_root": Promise.resolve(1)};',
        ),
    )
    has_actions, count, endpoints = waku.probe_waku_server_actions("http://example")
    assert has_actions is False
    assert count == len(endpoints) >= 1
    assert any(ep == "/RSC/R/_root.txt" for ep, _ in endpoints)
