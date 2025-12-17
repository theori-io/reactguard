from reactguard.http.adapters import StubHttpClient, WorkerHttpClientAdapter
from reactguard.http.models import HttpRequest, HttpResponse


def test_worker_http_client_adapter_success_and_error():
    class Scanner:
        def __init__(self):
            self.calls = 0

        def scan(self, url, **kwargs):  # noqa: ARG002
            self.calls += 1
            if "fail" in url:
                raise RuntimeError("boom")
            return {"ok": True, "status_code": 201, "headers": {"X": "1"}, "body": "data", "url": url}

    adapter = WorkerHttpClientAdapter(Scanner())
    ok_resp = adapter.request(HttpRequest(url="http://example/success"))
    assert ok_resp.ok is True
    assert ok_resp.status_code == 201
    assert ok_resp.text == "data"
    assert ok_resp.meta["status_code"] == 201

    err_resp = adapter.request(HttpRequest(url="http://example/fail"))
    assert err_resp.ok is False
    assert err_resp.error_message == "boom"
    assert err_resp.error_type == "RuntimeError"


def test_stub_http_client_returns_registered_responses():
    stub = StubHttpClient()
    custom_resp = HttpResponse(ok=True, status_code=200, text="hello")
    stub.add("http://example", custom_resp)
    result = stub.request(HttpRequest(url="http://example"))
    assert result.text == "hello"
    missing = stub.request(HttpRequest(url="http://missing"))
    assert missing.ok is False
    assert stub.requests[0].url == "http://example"
