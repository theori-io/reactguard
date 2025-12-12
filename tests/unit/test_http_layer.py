import time

import httpx

from reactguard.config import HttpSettings
from reactguard.errors import ErrorCategory
from reactguard.http.httpx_client import HttpxClient
from reactguard.http.models import HttpRequest, HttpResponse, RetryConfig
from reactguard.http.retry import build_default_retry_config, send_with_retries
from reactguard.http.utils import get_http_client, scan_with_retry, set_shared_http_client
from reactguard.utils.context import scan_context


class SequenceHttpClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def request(self, request: HttpRequest) -> HttpResponse:  # noqa: ARG002
        self.calls += 1
        return self._responses[min(self.calls - 1, len(self._responses) - 1)]

    def close(self) -> None:  # pragma: no cover - exercised via ReactGuard tests
        self.closed = True


def test_http_response_from_mapping_keeps_meta():
    mapping = {
        "ok": True,
        "status_code": 201,
        "headers": {"X-Test": "1"},
        "body": "hello",
        "url": "http://x",
        "extra": "value",
        "retry_count": 2,
    }
    resp = HttpResponse.from_mapping(mapping)
    assert resp.ok is True
    assert resp.status_code == 201
    assert resp.headers["X-Test"] == "1"
    assert resp.text == "hello"
    assert resp.content == b"hello"
    assert resp.meta["extra"] == "value"
    assert resp.meta["retry_count"] == 2


def test_retry_config_from_settings_clamps_minimum():
    settings = HttpSettings(max_retries=0)
    retry = RetryConfig.from_settings(settings)
    assert retry.max_attempts == 1
    assert retry.backoff_factor == settings.backoff_factor


def test_send_with_retries_success_after_retry(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    resp_retry = HttpResponse(ok=False, error_category=ErrorCategory.TIMEOUT.value, error_message="timeout")
    resp_ok = HttpResponse(ok=True, status_code=200, text="done")
    client = SequenceHttpClient([resp_retry, resp_ok])
    result = send_with_retries(client, HttpRequest(url="http://example"))
    assert result.ok is True
    assert result.meta["retry_count"] == 1
    assert client.calls == 2


def test_send_with_retries_non_retriable_stops(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    resp = HttpResponse(ok=False, error_category=ErrorCategory.WAF_SUSPECTED.value, error_message="blocked")
    client = SequenceHttpClient([resp, HttpResponse(ok=True)])
    result = send_with_retries(client, HttpRequest(url="http://example"))
    assert result.ok is False
    assert client.calls == 1


def test_send_with_retries_converts_exceptions(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _: None)

    class ExceptionThenSuccess:
        def __init__(self):
            self.calls = 0

        def request(self, request: HttpRequest) -> HttpResponse:  # noqa: ARG002
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("boom")
            return HttpResponse(ok=True, status_code=200, text="ok")

    client = ExceptionThenSuccess()
    result = send_with_retries(client, HttpRequest(url="http://example"))
    assert result.ok is True
    assert result.meta["retry_count"] == 1
    assert client.calls == 2


def test_send_with_retries_returns_last_response(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    resp = HttpResponse(ok=False, error_category=ErrorCategory.TIMEOUT.value, error_message="timeout")
    client = SequenceHttpClient([resp])
    retry_cfg = RetryConfig(max_attempts=1, retry_on={ErrorCategory.TIMEOUT.value}, backoff_factor=1.0, initial_delay=0.01)
    result = send_with_retries(client, HttpRequest(url="http://example", timeout=0.01), retry_config=retry_cfg)
    assert result.ok is False
    assert result.error_category == ErrorCategory.TIMEOUT.value
    assert client.calls == 1


def test_build_default_retry_config_sets_expected_categories():
    cfg = build_default_retry_config()
    assert ErrorCategory.TIMEOUT.value in cfg.retry_on
    assert ErrorCategory.WAF_SUSPECTED.value in cfg.retry_never
    assert cfg.max_attempts >= 1


def test_scan_with_retry_sets_defaults(monkeypatch):
    settings = HttpSettings(timeout=0.5, user_agent="UA/1.0", max_retries=1)
    monkeypatch.setattr("reactguard.http.utils.load_http_settings", lambda: settings)
    captured = {}

    class Client:
        def request(self, request: HttpRequest) -> HttpResponse:
            captured["request"] = request
            return HttpResponse(ok=True, status_code=200, headers={"X": "1"}, text="body", url=request.url)

    result = scan_with_retry("http://example", headers={"X-Test": "1"}, body=b"", http_client=Client())
    assert result["ok"] is True
    assert result["status_code"] == 200
    assert result["headers"]["X"] == "1"
    assert result["body_snippet"] == "body"
    assert result["error_category"] == ErrorCategory.NONE.value
    assert captured["request"].headers["User-Agent"] == "UA/1.0"
    assert captured["request"].allow_redirects is True


def test_shared_http_client_refresh(monkeypatch):
    first = SequenceHttpClient([HttpResponse(ok=True)])
    second = SequenceHttpClient([HttpResponse(ok=True)])
    set_shared_http_client(first)
    assert get_http_client() is first
    monkeypatch.setattr("reactguard.http.utils.create_default_http_client", lambda _=None: second)
    assert get_http_client(refresh=True) is second


def test_get_http_client_prefers_context_over_global(monkeypatch):
    import reactguard.http.utils as http_utils

    global_client = SequenceHttpClient([HttpResponse(ok=True)])
    ctx_client = SequenceHttpClient([HttpResponse(ok=True)])
    monkeypatch.setattr(http_utils, "_shared_http_client", global_client)
    with scan_context(http_client=ctx_client):
        assert get_http_client() is ctx_client
    assert get_http_client() is global_client


def test_scan_with_retry_uses_nested_context_clients(monkeypatch):
    seen_clients: list[object] = []

    def fake_send_with_retries(client, request, *, retry_config=None):  # noqa: ANN001,ARG001
        seen_clients.append(client)
        return HttpResponse(ok=True, status_code=200, headers={}, text="", url=request.url)

    monkeypatch.setattr("reactguard.http.utils.send_with_retries", fake_send_with_retries)

    client_a = object()
    client_b = object()
    with scan_context(http_client=client_a):
        scan_with_retry("http://example/a")
        with scan_context(http_client=client_b):
            scan_with_retry("http://example/b")
        scan_with_retry("http://example/c")

    assert seen_clients == [client_a, client_b, client_a]


def test_httpx_client_success_and_error(monkeypatch):
    requests = []

    class FakeHttpxClient:
        def __init__(self, follow_redirects, timeout, verify):  # noqa: ARG002
            self.follow_redirects = follow_redirects
            self.timeout = timeout
            self.verify = verify

        def request(self, method, url, headers=None, content=None, timeout=None, follow_redirects=None):  # noqa: ARG002
            requests.append({"method": method, "url": url, "headers": headers, "content": content, "timeout": timeout, "follow_redirects": follow_redirects})
            return type(
                "Resp",
                (),
                {
                    "status_code": 204,
                    "headers": {"Content-Type": "text/plain"},
                    "text": "",
                    "content": b"",
                    "url": httpx.URL(url),
                },
            )()

        def close(self):  # pragma: no cover - sanity check
            requests.append({"closed": True})

    monkeypatch.setattr(httpx, "Client", FakeHttpxClient)
    client = HttpxClient(HttpSettings(user_agent="UA/1.0"))
    resp = client.request(HttpRequest(url="http://example/path", method="POST", headers={"X": "1"}, body="payload", allow_redirects=False, timeout=1.2))
    assert resp.ok is True
    assert resp.status_code == 204
    assert requests[0]["headers"]["User-Agent"] == "UA/1.0"
    assert requests[0]["timeout"] == 1.2
    assert requests[0]["follow_redirects"] is False

    class ErrorClient(FakeHttpxClient):
        def request(self, *_, **__):
            raise httpx.TimeoutException("boom")

    monkeypatch.setattr(httpx, "Client", ErrorClient)
    err_client = HttpxClient(HttpSettings())
    err_resp = err_client.request(HttpRequest(url="http://example"))
    assert err_resp.ok is False
    assert err_resp.error_category == ErrorCategory.TIMEOUT.value
