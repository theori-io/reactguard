from reactguard.framework_detection.signals import server_actions
from reactguard.utils.tag_manager import TagSet


def test_detect_server_actions_handles_404(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: {"ok": True, "status_code": 404, "headers": {}, "body": "not found", "body_snippet": "not found"},
    )
    result = server_actions.detect_server_actions("http://example")
    assert result["supported"] is False
    assert result["confidence"] == "medium"
    assert "not observed" in result["reason"].lower()


def test_detect_server_actions_html_and_rsc_paths(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: {
            "ok": True,
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "body": "<html>__next_data__</html>",
            "body_snippet": "<html>__next_data__</html>",
        },
    )
    html_result = server_actions.detect_server_actions("http://example")
    assert html_result["supported"] is True
    assert html_result["confidence"] == "low"

    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: {
            "ok": True,
            "status_code": 500,
            "headers": {"content-type": server_actions.SERVER_ACTIONS_RSC_CONTENT_TYPE},
            "body": '0:{"a":"$@"}',
            "body_snippet": '0:{"a":"$@"}',
        },
    )
    rsc_result = server_actions.detect_server_actions("http://example")
    assert rsc_result["supported"] is True
    assert rsc_result["confidence"] in {"high", "medium"}


def test_detect_server_actions_redirect(monkeypatch):
    monkeypatch.setattr(
        server_actions,
        "send_rsc_request",
        lambda *_, **__: {"ok": True, "status_code": 302, "headers": {}, "body": "", "body_snippet": ""},
    )
    result = server_actions.detect_server_actions("http://example")
    assert result["supported"] is False
    assert "Redirect" in result["reason"]


def test_apply_server_actions_probe_results_fallback(monkeypatch):
    tags = TagSet()
    signals = {}
    probe_result = {
        "status_code": 200,
        "has_framework_html_marker": True,
        "has_action_keywords": True,
        "has_action_content_type": False,
        "has_flight_marker": False,
        "has_digest": False,
        "is_html": True,
        "action_not_found_header": False,
        "action_not_found_body": False,
        "vary_has_rsc": False,
        "flight_format": "unknown",
        "react_major_from_flight": None,
    }
    outcome = server_actions.apply_server_actions_probe_results(
        base_url="http://example",
        probe_result=probe_result,
        tags=tags,
        signals=signals,
        fallback_html_signal_key="html_response",
        set_defaults=True,
    )
    assert outcome["supported"] is True
    assert signals["server_actions_enabled"] is True
    assert signals["server_actions_confidence"]
