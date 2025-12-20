# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.http.models import HttpResponse
from reactguard.models.poc import PocStatus
from reactguard.vulnerability_detection.interpreters.expo_interpreter import ExpoInterpreter


def test_error_path_tolerates_timeouts_when_control_matches():
    interpreter = ExpoInterpreter(is_rsc_framework=True, invocation_expected=True)

    timeout_result = HttpResponse(ok=False, status_code=None, headers={}, text="", error_type="ReadTimeout")
    invalid_reference = HttpResponse(ok=True, status_code=500, headers={"content-type": "text/plain"}, text="Invalid reference.")

    result = interpreter.analyze(
        [timeout_result, invalid_reference, timeout_result],
        control_results=[invalid_reference],
    )

    assert result["status"] == PocStatus.LIKELY_NOT_VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_server_actions_error_path"


def test_error_path_still_flags_divergence_with_timeouts():
    interpreter = ExpoInterpreter(is_rsc_framework=True, invocation_expected=True)

    timeout_result = HttpResponse(ok=False, status_code=None, headers={}, text="", error_type="ReadTimeout")
    control_error = HttpResponse(
        ok=True,
        status_code=500,
        headers={"content-type": "text/plain"},
        text="Cannot read properties of undefined (reading 'id')",
    )
    proto_error = HttpResponse(
        ok=True,
        status_code=500,
        headers={"content-type": "text/plain"},
        text="Unable to resolve module /app/undefined from /app/.",
    )

    result = interpreter.analyze(
        [timeout_result, proto_error, timeout_result],
        control_results=[control_error],
    )

    assert result["status"] == PocStatus.LIKELY_VULNERABLE
    assert result["details"]["decision_rule"] == "_rule_server_actions_error_path"
