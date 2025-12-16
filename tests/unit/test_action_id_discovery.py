from reactguard.http.crawl import CrawledPage
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
            return {"ok": True, "status_code": 200, "headers": {"content-type": "application/javascript"}, "body": body, "body_snippet": body}
        return {"ok": False, "status_code": 404, "headers": {}, "body": "", "body_snippet": ""}

    monkeypatch.setattr(probe, "_scan_once", fake_scan_once)
    assert probe.discover_next_action_ids("http://example/app", timeout=0.1) == ["40submit", "40echo"]

