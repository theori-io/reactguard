from reactguard.rsc.payloads import (
    RscReference,
    build_multipart_decode_payload,
    build_nextjs_action_multipart_payload,
)
from reactguard.rsc.types import RscWireFormat


def test_rsc_reference_render_variants():
    assert RscReference(slot=1, root="x", prop="__proto__", marker="F").render() == "$F1:x:__proto__"
    assert RscReference(slot=1, root="x", prop="__proto__", marker="").render() == "$1:x:__proto__"
    assert RscReference(slot=1, root="x", prop="p", marker="F", trailer=("a", "b")).render() == "$F1:x:p:a:b"


def test_build_multipart_decode_payload_builds_expected_body(monkeypatch):
    monkeypatch.setattr("reactguard.rsc.payloads.secrets.token_hex", lambda *_args, **_kwargs: "feedface")
    payload = build_multipart_decode_payload(RscReference(slot=1, root="x", prop="__proto__", marker="F"))

    assert payload.wire_format == RscWireFormat.MULTIPART_FORM
    assert payload.headers["Content-Type"] == "multipart/form-data; boundary=----FormBoundaryfeedface"
    assert "----FormBoundaryfeedface" in payload.body
    assert "__proto__" in payload.body
    assert '["$F1:x:__proto__"]' in payload.body


def test_build_nextjs_action_multipart_payload_includes_server_ref(monkeypatch):
    monkeypatch.setattr("reactguard.rsc.payloads.secrets.token_hex", lambda *_args, **_kwargs: "feedface")
    payload = build_nextjs_action_multipart_payload(target_prop="__proto__", server_ref_marker="F")

    assert payload.wire_format == RscWireFormat.MULTIPART_FORM
    assert payload.headers["Content-Type"] == "multipart/form-data; boundary=----FormBoundaryfeedface"
    assert "$F4:x:__proto__" in payload.body
    assert 'name="3_title"' in payload.body
