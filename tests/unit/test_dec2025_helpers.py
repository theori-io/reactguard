# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.vulnerability_detection.assessors.rsc_dec2025 import (
    _chain_has_decode_evidence,
    _looks_like_non_rsc_transport_error,
    _pr35345_evidence_strength,
)


def test_dec2025_looks_like_non_rsc_transport_error_none():
    assert _looks_like_non_rsc_transport_error(None) is True


def test_dec2025_looks_like_non_rsc_transport_error_status_gate():
    assert _looks_like_non_rsc_transport_error({"status_code": 404, "headers": {}, "body": "not found"}) is True
    assert _looks_like_non_rsc_transport_error({"status_code": 404, "headers": {"x-nextjs-action-not-found": "1"}, "body": "not found"}) is False
    assert _looks_like_non_rsc_transport_error({"status_code": 401, "headers": {}, "body": '{"digest":"aaaaaa"}'}) is False


def test_dec2025_pr35345_evidence_strength_from_signatures():
    assert _pr35345_evidence_strength({}, ["status:404", "status:403"]) == "none"
    assert _pr35345_evidence_strength({}, ["connection_closed"]) == "medium"


def test_dec2025_pr35345_evidence_strength_from_content_type():
    strength = _pr35345_evidence_strength(
        {"control": {"status_code": 200, "headers": {"content-type": "text/x-component"}, "body": "ok"}},
        ["ok"],
    )
    assert strength == "strong"


def test_dec2025_chain_has_decode_evidence():
    assert _chain_has_decode_evidence({1000: "digest:aaaaaa"}, []) is True
    assert _chain_has_decode_evidence({1000: "connection_closed"}, []) is True
    assert _chain_has_decode_evidence({1000: "status:404"}, ["connection_closed"]) is False

