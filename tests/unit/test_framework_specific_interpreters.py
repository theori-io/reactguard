from reactguard.models.poc import PocStatus
from reactguard.vulnerability_detection.interpreters.expo_interpreter import ExpoInterpreter
from reactguard.vulnerability_detection.interpreters.react_router_interpreter import ReactRouterInterpreter
from reactguard.vulnerability_detection.journal import PocJournal


def test_expo_connection_closed_is_likely_not_vulnerable():
    """
    Regression: Expo (patched) fixtures can return small plaintext 5xx ("Connection closed.")
    for proto probes while control succeeds. This should not be treated as VULNERABLE.
    """
    probe_results = [
        {"status_code": 500, "body_snippet": "Connection closed.", "headers": {"content-type": "text/plain"}},
        {"status_code": 500, "body_snippet": "Connection closed.", "headers": {"content-type": "text/plain"}},
        {"status_code": 500, "body_snippet": "Connection closed.", "headers": {"content-type": "text/plain"}},
    ]
    control_results = [{"status_code": 200, "body_snippet": '0:{"_value":"echo:hello"}\n', "headers": {"content-type": "text/plain"}}]

    analyzer = ExpoInterpreter(
        is_rsc_framework=True,
        server_actions_expected=True,
        journal=PocJournal(),
    )
    result = analyzer.analyze(probe_results, control_results=control_results)

    assert result["status"] == PocStatus.LIKELY_NOT_VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_expo_connection_closed"
    assert result["details"]["surface_detected"] is True
    assert result["details"]["decode_surface_reached"] is True


def test_expo_prototype_error_is_vulnerable():
    probe_results = [
        {"status_code": 500, "body_snippet": "Cannot read properties of null (reading 'id')", "headers": {"content-type": "text/plain"}},
        {"status_code": 500, "body_snippet": "Cannot read properties of null (reading 'id')", "headers": {"content-type": "text/plain"}},
    ]
    control_results = [{"status_code": 200, "body_snippet": '0:{"_value":"ok"}\n', "headers": {"content-type": "text/plain"}}]

    analyzer = ExpoInterpreter(
        is_rsc_framework=True,
        server_actions_expected=True,
        journal=PocJournal(),
    )
    result = analyzer.analyze(probe_results, control_results=control_results)

    assert result["status"] == PocStatus.VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_prototype_errors"
    assert result["details"]["surface_detected"] is True
    assert result["details"]["decode_surface_reached"] is True


def test_react_router_structural_divergence_is_vulnerable():
    probe_results = [
        {"status_code": 500, "body_snippet": "Internal Server Error", "headers": {"content-type": "text/plain"}},
        {"status_code": 500, "body_snippet": "Internal Server Error", "headers": {"content-type": "text/plain"}},
        {"status_code": 500, "body_snippet": "Internal Server Error", "headers": {"content-type": "text/plain"}},
    ]
    control_results = [{"status_code": 200, "body_snippet": '0:{"type":"action"}\n', "headers": {"x-powered-by": "Express"}}]

    analyzer = ReactRouterInterpreter(
        is_rsc_framework=True,
        server_actions_expected=True,
        journal=PocJournal(),
    )
    result = analyzer.analyze(probe_results, control_results=control_results)

    assert result["status"] == PocStatus.VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_structural_divergence"
    assert result["details"]["surface_detected"] is True
    assert result["details"]["decode_surface_reached"] is True
