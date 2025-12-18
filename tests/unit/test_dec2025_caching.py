# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.utils.context import scan_context
from reactguard.vulnerability_detection.assessors import ReactServerComponentsDec2025Assessor, RscDec2025Spec


def test_dec2025_fingerprint_cache_is_scoped_to_scan_context(monkeypatch):
    """
    Regression test: ensure Dec 2025 fingerprint caching does not leak across tests/runs.

    The assessor should:
    - cache within a scan_context(extra={...}) so repeated CVEs can reuse probing work
    - NOT cache globally across independent scan contexts
    """

    calls = {"control": 0, "conn": 0, "marker": 0}

    def _control_stub(_endpoint: str, **_kwargs):
        calls["control"] += 1
        return {"status_code": 200, "headers": {"content-type": "text/plain"}, "body": "ok"}

    def _conn_stub(_endpoint: str, **_kwargs):
        calls["conn"] += 1
        return {"status_code": 500, "headers": {"content-type": "text/plain"}, "body": "Connection closed."}

    def _marker_stub(_endpoint: str, *, server_ref_marker: str, **_kwargs):
        calls["marker"] += 1
        if server_ref_marker == "h":
            return {"status_code": 500, "headers": {"content-type": "text/plain"}, "body": "Connection closed."}
        return {"status_code": 500, "headers": {"content-type": "text/plain"}, "body": "Args shape error"}

    monkeypatch.setattr("reactguard.vulnerability_detection.assessors.rsc_dec2025.send_dec2025_safe_control_probe", _control_stub)
    monkeypatch.setattr("reactguard.vulnerability_detection.assessors.rsc_dec2025.send_dec2025_missing_chunk_probe", _conn_stub)
    monkeypatch.setattr("reactguard.vulnerability_detection.assessors.rsc_dec2025.send_dec2025_server_reference_marker_root_probe", _marker_stub)

    base_url = "http://example"
    detect_context = {"invocation_endpoints": [base_url], "invocation_enabled": True, "invocation_confidence": "high"}

    assessor = ReactServerComponentsDec2025Assessor(RscDec2025Spec(cve_id="CVE-2025-55184", title="t"))

    with scan_context(extra={}):
        assessor.evaluate(base_url, {}, detect_context=detect_context)
        first = dict(calls)
        assessor.evaluate(base_url, {}, detect_context=detect_context)
        assert calls == first, "fingerprint should be reused within the same scan_context(extra=...)"

    with scan_context(extra={}):
        assessor.evaluate(base_url, {}, detect_context=detect_context)
        assert calls["control"] > first["control"], "fingerprint should not be reused across independent scan contexts"
        assert calls["conn"] > first["conn"]
        assert calls["marker"] > first["marker"]

