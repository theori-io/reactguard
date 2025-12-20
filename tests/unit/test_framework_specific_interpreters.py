# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.http.models import HttpResponse
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
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Connection closed."),
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Connection closed."),
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Connection closed."),
    ]
    control_results = [
        HttpResponse(ok=True, status_code=200, headers={"content-type": "text/plain"}, text='0:{"_value":"echo:hello"}\n')
    ]

    analyzer = ExpoInterpreter(
        is_rsc_framework=True,
        invocation_expected=True,
        journal=PocJournal(),
    )
    result = analyzer.analyze(probe_results, control_results=control_results)

    assert result["status"] == PocStatus.LIKELY_NOT_VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_expo_connection_closed"
    assert result["details"]["surface_detected"] is True
    assert result["details"]["decode_surface_reached"] is True


def test_expo_prototype_error_is_vulnerable():
    probe_results = [
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Cannot read properties of null (reading 'id')"),
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Cannot read properties of null (reading 'id')"),
    ]
    control_results = [HttpResponse(ok=True, status_code=200, headers={"content-type": "text/plain"}, text='0:{"_value":"ok"}\n')]

    analyzer = ExpoInterpreter(
        is_rsc_framework=True,
        invocation_expected=True,
        journal=PocJournal(),
    )
    result = analyzer.analyze(probe_results, control_results=control_results)

    assert result["status"] == PocStatus.VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_prototype_errors"
    assert result["details"]["surface_detected"] is True
    assert result["details"]["decode_surface_reached"] is True


def test_react_router_structural_divergence_is_vulnerable():
    probe_results = [
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Internal Server Error"),
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Internal Server Error"),
        HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Internal Server Error"),
    ]
    control_results = [HttpResponse(ok=True, status_code=200, headers={"x-powered-by": "Express"}, text='0:{"type":"action"}\n')]

    analyzer = ReactRouterInterpreter(
        is_rsc_framework=True,
        invocation_expected=True,
        journal=PocJournal(),
    )
    result = analyzer.analyze(probe_results, control_results=control_results)

    assert result["status"] == PocStatus.VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_structural_divergence"
    assert result["details"]["surface_detected"] is True
    assert result["details"]["decode_surface_reached"] is True
