# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.vulnerability_detection.assessors.rsc_dec2025_evidence import (
    chain_has_decode_evidence,
    looks_like_non_rsc_transport_error,
    pr35345_evidence_strength,
)


def test_dec2025_looks_like_non_rsc_transport_error_none():
    assert looks_like_non_rsc_transport_error(None) is True


def test_dec2025_looks_like_non_rsc_transport_error_status_gate():
    assert looks_like_non_rsc_transport_error({"status_code": 404, "headers": {}, "body": "not found"}) is True
    assert looks_like_non_rsc_transport_error({"status_code": 404, "headers": {"x-nextjs-action-not-found": "1"}, "body": "not found"}) is False
    assert looks_like_non_rsc_transport_error({"status_code": 401, "headers": {}, "body": '{\"digest\":\"aaaaaa\"}'}) is False


def test_dec2025_pr35345_evidence_strength_from_signatures():
    assert pr35345_evidence_strength({}, ["status:404", "status:403"]) == "none"
    assert pr35345_evidence_strength({}, ["connection_closed"]) == "medium"


def test_dec2025_pr35345_evidence_strength_from_content_type():
    strength = pr35345_evidence_strength(
        {"control": {"status_code": 200, "headers": {"content-type": "text/x-component"}, "body": "ok"}},
        ["ok"],
    )
    assert strength == "strong"


def test_dec2025_pr35345_evidence_strength_from_temporary_reference_error_messages():
    strength = pr35345_evidence_strength(
        {
            "control": {
                "status_code": 500,
                "headers": {"content-type": "text/plain"},
                "body": (
                    "Cannot access then on the server. "
                    "You cannot dot into a temporary client reference from a server component. "
                    "You can only pass the value through to the client."
                ),
            }
        },
        ["status:500"],
    )
    assert strength == "strong"

    strength = pr35345_evidence_strength(
        {
            "control": {
                "status_code": 500,
                "headers": {"content-type": "text/plain"},
                "body": (
                    "Could not reference an opaque temporary reference. "
                    "This is likely due to misconfiguring the temporaryReferences options on the server."
                ),
            }
        },
        ["status:500"],
    )
    assert strength == "strong"


def test_dec2025_chain_has_decode_evidence():
    assert chain_has_decode_evidence({1000: "digest:aaaaaa"}, []) is True
    assert chain_has_decode_evidence({1000: "connection_closed"}, []) is True
    assert chain_has_decode_evidence({1000: "status:404"}, ["connection_closed"]) is False
