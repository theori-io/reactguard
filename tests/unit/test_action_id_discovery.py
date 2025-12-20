# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.http.crawl import CrawledPage
from reactguard.http.models import HttpResponse
from reactguard.vulnerability_detection.probes import rsc_patch_fingerprint_probe as probe


def test_discover_next_action_ids_scrapes_inline_and_assets(monkeypatch):
    pages = [
        CrawledPage(
            url="http://example/app",
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html><script>const h={'Next-Action':'40submit'}</script><script src='/static/app.js'></script></html>",
            depth=0,
        ),
    ]
    monkeypatch.setattr(probe, "crawl_same_origin_html", lambda *_args, **_kwargs: pages)

    def fake_scan_once(url, **kwargs):  # noqa: ARG001
        if url.endswith("/static/app.js") or url.endswith("/app/static/app.js"):
            body = 'headers.set("Next-Action","40echo")'
            return HttpResponse(ok=True, status_code=200, headers={"content-type": "application/javascript"}, text=body)
        return HttpResponse(ok=False, status_code=404, headers={}, text="")

    monkeypatch.setattr(probe, "_scan_once", fake_scan_once)
    assert probe.discover_next_action_ids("http://example/app") == ["40submit", "40echo"]


def test_discover_next_action_ids_scans_hex_tokens_in_bundles(monkeypatch):
    token = "60" + ("a" * 40)
    pages = [
        CrawledPage(
            url="http://example/app",
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html><script src='/static/app.js'></script></html>",
            depth=0,
        ),
    ]
    monkeypatch.setattr(probe, "crawl_same_origin_html", lambda *_args, **_kwargs: pages)

    def fake_scan_once(url, **kwargs):  # noqa: ARG001
        if url.endswith("/static/app.js") or url.endswith("/app/static/app.js"):
            body = f'const action="{token}";'
            return HttpResponse(ok=True, status_code=200, headers={"content-type": "application/javascript"}, text=body)
        return HttpResponse(ok=False, status_code=404, headers={}, text="")

    monkeypatch.setattr(probe, "_scan_once", fake_scan_once)
    assert probe.discover_next_action_ids("http://example/app") == [token]


def test_extract_nextjs_action_id_from_html_unescaped_value():
    html = '<input type="hidden" name="$ACTION_ID_abc" value=\'{"id":"40echo"}\'>'
    assert probe._extract_nextjs_action_id_from_html(html) == "40echo"


def test_extract_nextjs_action_id_from_html_escaped_value():
    html = '<input type="hidden" name="$ACTION_ID_abc" value="{&quot;id&quot;:&quot;40echo&quot;}">'
    assert probe._extract_nextjs_action_id_from_html(html) == "40echo"


def test_discover_nextjs_action_entrypoint_prefers_hidden_action_id_over_hex_tokens(monkeypatch):
    token = "60" + ("a" * 40)
    pages = [
        CrawledPage(
            url="http://example/app",
            status_code=200,
            headers={"content-type": "text/html"},
            body=f'<html><body><input type="hidden" name="$ACTION_ID_abc" value=\'{{"id":"40echo"}}\'><script>const t="{token}"</script></body></html>',
            depth=0,
        ),
    ]
    monkeypatch.setattr(probe, "crawl_same_origin_html", lambda *_args, **_kwargs: pages)

    def fake_scan_once(url, **kwargs):  # noqa: ARG001
        if kwargs.get("method") == "POST":
            action_id = (kwargs.get("headers") or {}).get("Next-Action")
            if action_id == "40echo":
                return HttpResponse(ok=True, status_code=200, headers={"content-type": "text/x-component"}, text='0:{"a":"$@"}')
            return HttpResponse(ok=True, status_code=200, headers={"content-type": "text/html"}, text="<html>no</html>")
        return HttpResponse(ok=False, status_code=404, headers={}, text="")

    monkeypatch.setattr(probe, "_scan_once", fake_scan_once)
    assert probe.discover_nextjs_action_entrypoint("http://example/app") == ("http://example/app", "40echo")


def test_discover_nextjs_action_entrypoint_validates_candidates_and_tries_next(monkeypatch):
    pages = [
        CrawledPage(
            url="http://example/app",
            status_code=200,
            headers={"content-type": "text/html"},
            body='<html><script>headers.set("Next-Action","40bad");headers.set("Next-Action","40good")</script></html>',
            depth=0,
        ),
    ]
    monkeypatch.setattr(probe, "crawl_same_origin_html", lambda *_args, **_kwargs: pages)

    def fake_scan_once(url, **kwargs):  # noqa: ARG001
        if kwargs.get("method") == "POST":
            action_id = (kwargs.get("headers") or {}).get("Next-Action")
            if action_id == "40good":
                return HttpResponse(ok=True, status_code=200, headers={"content-type": "text/x-component"}, text='0:{"a":"$@"}')
            return HttpResponse(ok=True, status_code=200, headers={"content-type": "text/html"}, text="<html>no</html>")
        return HttpResponse(ok=False, status_code=404, headers={}, text="")

    monkeypatch.setattr(probe, "_scan_once", fake_scan_once)
    assert probe.discover_nextjs_action_entrypoint("http://example/app") == ("http://example/app", "40good")
