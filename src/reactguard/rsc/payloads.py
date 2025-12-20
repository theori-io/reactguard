# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RSC payload builders (multipart/plain/JSON) shared across frameworks."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .types import PayloadFactory, RscPayload, RscWireFormat


def _json_dumps(value: object) -> str:
    return json.dumps(value, separators=(",", ":"))


SAFE_ARGS_STRATEGY = "safe_args_bigint_length"
SAFE_ARGS_LENGTH_TOKEN = "$n1"
NO_INVOKE_ROOT_REF_STRATEGY = "no_invoke_root_ref_string"
NO_INVOKE_FORCE_FAIL_TRAILER_STRATEGY = "no_invoke_force_fail_trailer"
NO_INVOKE_TEMP_REF_STRATEGY = "no_invoke_temp_reference"
NO_INVOKE_TEMP_REF_TOKEN = "$T1"


def build_no_invoke_args_container(values: list[object], *, length_token: str = SAFE_ARGS_LENGTH_TOKEN) -> dict[str, object]:
    """
    Build an args-like object that cannot be invoked as a valid argument list.

    The `length` is encoded as a BigInt token (e.g. "$n1") so any eventual `apply(...)`
    path throws before calling user code. The container is also non-iterable, so any
    spread path (`fn(...args)`) throws as well.
    """
    out: dict[str, object] = {str(idx): value for idx, value in enumerate(values)}
    out["length"] = str(length_token)
    return out


def _build_multipart_form_data(parts: Iterable[tuple[str, str]], *, boundary: str | None = None) -> tuple[str, str]:
    if boundary is None:
        boundary = f"----FormBoundary{secrets.token_hex(8)}"

    body = ""
    for name, value in parts:
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
    body += f"--{boundary}--\r\n"
    return boundary, body


def build_multipart_form_payload(
    parts: Iterable[tuple[str, str]],
    *,
    boundary: str | None = None,
    meta: dict[str, object] | None = None,
) -> RscPayload:
    """Build a raw multipart/form-data payload from (name, value) parts."""
    parts_list = list(parts)
    boundary_value, body = _build_multipart_form_data(parts_list, boundary=boundary)
    payload_meta: dict[str, object] = {"boundary": boundary_value, "parts": [name for name, _ in parts_list]}
    if meta:
        payload_meta.update(meta)
    return RscPayload(
        wire_format=RscWireFormat.MULTIPART_FORM,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary_value}"},
        body=body,
        meta=payload_meta,
    )


@dataclass(frozen=True)
class RscReference:
    """
    A React Server Components "server reference" string used by RSC Flight protocol payload deserialization
    (e.g. `decodeReply` in react-server-dom-* runtimes).

    Examples:
    - Next.js-style: `$F1:x:__proto__`
    - Waku-style:   `$1:x:__proto__`
    """

    slot: int
    root: str = "x"
    prop: str = "__proto__"
    marker: str = "F"
    trailer: tuple[str, ...] = ()

    def render(self) -> str:
        marker = str(self.marker or "")
        prefix = f"${marker}{int(self.slot)}" if marker else f"${int(self.slot)}"
        parts: list[str] = [prefix, str(self.root), str(self.prop)]
        parts.extend([str(x) for x in self.trailer if x])
        return ":".join(parts)


def build_multipart_decode_payload(
    reference: RscReference,
    *,
    object_slot: str = "1",
    args_slot: str = "0",
    boundary: str | None = None,
    root_object: dict[str, object] | None = None,
) -> RscPayload:
    """
    Minimal multipart payload that exercises RSC Flight protocol payload deserialization.

    Matches the "two-field" pattern used by a number of RSC stacks:
    - one JSON chunk with a root object (default: `{"x":{}}`)
    - one JSON chunk with the argument array referencing that chunk (e.g. `["$F1:x:__proto__"]`)
    """
    ref_str = reference.render()
    root_object = root_object or {reference.root: {}}
    parts = [
        (object_slot, _json_dumps(root_object)),
        (args_slot, _json_dumps([ref_str])),
    ]
    boundary_value, body = _build_multipart_form_data(parts, boundary=boundary)
    return RscPayload(
        wire_format=RscWireFormat.MULTIPART_FORM,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary_value}"},
        body=body,
        meta={
            "boundary": boundary_value,
            "reference": ref_str,
            "object_slot": object_slot,
            "args_slot": args_slot,
        },
    )


def build_plaintext_decode_payload(
    reference: RscReference,
) -> RscPayload:
    """Plaintext body variant that carries the args array directly."""
    ref_str = reference.render()
    return build_plaintext_payload(
        _json_dumps([ref_str]),
        meta={"reference": ref_str},
    )


def build_plaintext_payload(
    body: str,
    *,
    content_type: str = "text/plain;charset=UTF-8",
    meta: dict[str, object] | None = None,
) -> RscPayload:
    """Build a raw text/plain payload (often used when encodeReply returns a string)."""
    payload_meta: dict[str, object] = {}
    if meta:
        payload_meta.update(meta)
    return RscPayload(
        wire_format=RscWireFormat.TEXT,
        headers={"Content-Type": content_type},
        body=body,
        meta=payload_meta,
    )


def build_json_decode_payload(
    reference: RscReference,
    *,
    root_object: dict[str, object] | None = None,
) -> RscPayload:
    """
    JSON payload variant (used by some stacks/labs) that inlines the root object.

    Example:
      [{"x":{}}, "$F0:x:__proto__"]
    """
    ref_str = reference.render()
    root_object = root_object or {reference.root: {}}
    body = _json_dumps([root_object, ref_str])
    return RscPayload(
        wire_format=RscWireFormat.JSON,
        headers={"Content-Type": "application/json"},
        body=body,
        meta={"reference": ref_str},
    )


def _nextjs_default_prev_state() -> dict[str, object]:
    # Minimal ActionState shape for common Next.js `useActionState`-style Server Action signatures.
    return {
        "status": "reactguard probe",
        "queueLength": 0,
        "recent": [],
        "lastDetail": "",
    }


def build_nextjs_action_multipart_payload(
    *,
    target_prop: str,
    server_ref_marker: str = "F",
    reference_slot: int = 4,
    reference_root: str = "x",
    boundary: str | None = None,
    prev_state: dict[str, object] | None = None,
) -> RscPayload:
    """
    Next.js Server Actions multipart payload that keeps typical two-arg actions successful by placing
    the traversal reference in a third argument.

    This mirrors common `useActionState`/form-action calling conventions and reduces false negatives
    caused by app-specific argument shape mismatches.
    """
    if server_ref_marker not in {"F", "h"}:
        raise ValueError("server_ref_marker must be 'F' or 'h'")

    prev_state = prev_state or _nextjs_default_prev_state()
    ref = RscReference(slot=reference_slot, root=reference_root, prop=target_prop, marker=server_ref_marker).render()

    parts = [
        ("1", _json_dumps(prev_state)),
        (str(reference_slot), _json_dumps({reference_root: {}})),
        ("3_title", "reactguard-probe"),
        ("0", _json_dumps(["$1", "$K3", ref])),
    ]
    boundary_value, body = _build_multipart_form_data(parts, boundary=boundary)
    return RscPayload(
        wire_format=RscWireFormat.MULTIPART_FORM,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary_value}"},
        body=body,
        meta={
            "boundary": boundary_value,
            "reference": ref,
            "target_prop": target_prop,
            "server_ref_marker": server_ref_marker,
        },
    )


def build_random_safe_prop(*, prefix: str = "z") -> str:
    return f"{prefix}{secrets.token_hex(4)}"


def _with_payload_meta(payload: RscPayload, meta: dict[str, Any] | None) -> RscPayload:
    if not meta:
        return payload
    payload_meta = dict(payload.meta or {})
    payload_meta.update(meta)
    return RscPayload(
        wire_format=payload.wire_format,
        headers=dict(payload.headers or {}),
        body=payload.body,
        meta=payload_meta,
    )


def build_decode_payload_factories(
    *,
    marker: str = "F",
    proto_prop: str = "__proto__",
    safe_prop_prefix: str = "z",
    root: str = "x",
    slot: int = 1,
    proto_meta: dict[str, Any] | None = None,
    control_meta: dict[str, Any] | None = None,
) -> tuple[PayloadFactory, PayloadFactory]:
    """
    Return proto/control payload factories for a basic decodeReply probe.

    Used by Next.js/Generic/Expo-style probes where the action ID does not affect the payload.
    """

    def _proto_payload(_action_id: str) -> RscPayload:
        payload = build_multipart_decode_payload(RscReference(slot=slot, root=root, prop=proto_prop, marker=marker))
        return _with_payload_meta(payload, proto_meta)

    def _control_payload(_action_id: str) -> RscPayload:
        safe_prop = build_random_safe_prop(prefix=safe_prop_prefix)
        payload = build_multipart_decode_payload(RscReference(slot=slot, root=root, prop=safe_prop, marker=marker))
        return _with_payload_meta(payload, control_meta)

    return _proto_payload, _control_payload


def build_nextjs_action_payload_factories(
    *,
    server_ref_marker: str = "F",
    proto_prop: str = "__proto__",
    safe_prop_prefix: str = "z",
    proto_meta: dict[str, Any] | None = None,
    control_meta: dict[str, Any] | None = None,
) -> tuple[PayloadFactory, PayloadFactory]:
    """
    Return proto/control payload factories using Next.js action payload shape.
    """
    if server_ref_marker not in {"F", "h"}:
        raise ValueError("server_ref_marker must be 'F' or 'h'")

    def _proto_payload(_action_id: str) -> RscPayload:
        payload = build_nextjs_action_multipart_payload(
            target_prop=proto_prop,
            server_ref_marker=server_ref_marker,
        )
        return _with_payload_meta(payload, proto_meta)

    def _control_payload(_action_id: str) -> RscPayload:
        safe_prop = build_random_safe_prop(prefix=safe_prop_prefix)
        payload = build_nextjs_action_multipart_payload(
            target_prop=safe_prop,
            server_ref_marker=server_ref_marker,
        )
        return _with_payload_meta(payload, control_meta)

    return _proto_payload, _control_payload


def build_safe_args_payload_factories(
    *,
    wire_action_id: str,
    probe_targets: dict[str, str],
    safe_prop_prefix: str = "z",
    root: str = "x",
    slot: int = 2,
    proto_meta: dict[str, Any] | None = None,
    control_meta: dict[str, Any] | None = None,
) -> tuple[PayloadFactory, PayloadFactory]:
    """
    Return proto/control payload factories for safe-args multipart probes (React Router style).
    """
    wire_action_id = str(wire_action_id or "")

    def _payload(action_id: str, target_prop: str, *, meta: dict[str, Any] | None) -> RscPayload:
        ref = RscReference(slot=slot, root=root, prop=target_prop, marker="").render()
        args_obj = build_no_invoke_args_container(["$K1", ref])
        payload = build_multipart_form_payload(
            [
                (f"1_$ACTION_ID_{wire_action_id}", ""),
                (str(slot), _json_dumps({root: {}})),
                ("0", _json_dumps(args_obj)),
            ],
            meta=meta,
        )
        return payload

    def _proto_payload(action_id: str) -> RscPayload:
        target_prop = probe_targets.get(action_id, "__proto__")
        meta = {"probe_kind": "proto", "probe_strategy": SAFE_ARGS_STRATEGY, "wire_action_id": wire_action_id, "probe_id": action_id, "target_prop": target_prop}
        if proto_meta:
            meta.update(proto_meta)
        return _payload(action_id, target_prop, meta=meta)

    def _control_payload(action_id: str) -> RscPayload:
        safe_prop = build_random_safe_prop(prefix=safe_prop_prefix)
        meta = {"probe_kind": "control", "probe_strategy": SAFE_ARGS_STRATEGY, "wire_action_id": wire_action_id, "probe_id": action_id}
        if control_meta:
            meta.update(control_meta)
        return _payload(action_id, safe_prop, meta=meta)

    return _proto_payload, _control_payload


def build_no_invoke_temp_ref_payload(
    *,
    meta: dict[str, Any] | None = None,
) -> RscPayload:
    """Payload that triggers temp ref decoding without invoking actions."""
    payload = build_multipart_form_payload(
        [("0", _json_dumps([NO_INVOKE_TEMP_REF_TOKEN]))],
        meta={"probe_strategy": NO_INVOKE_TEMP_REF_STRATEGY},
    )
    return _with_payload_meta(payload, meta)


def build_dec2025_safe_control_payload(
    *,
    prefix_parts: list[tuple[str, str]] | None = None,
    meta: dict[str, Any] | None = None,
) -> RscPayload:
    payload_parts = [("0", _json_dumps([NO_INVOKE_TEMP_REF_TOKEN]))]
    parts = list(prefix_parts or [])
    parts.extend(payload_parts)
    payload = build_multipart_form_payload(
        parts,
        meta={"probe_kind": "dec2025_control_safe", "probe_strategy": NO_INVOKE_TEMP_REF_STRATEGY},
    )
    return _with_payload_meta(payload, meta)


def build_dec2025_missing_chunk_payload(
    *,
    missing_chunk_id_hex: str = "ffff",
    prefix_parts: list[tuple[str, str]] | None = None,
    meta: dict[str, Any] | None = None,
) -> RscPayload:
    missing = (missing_chunk_id_hex or "").lower().strip()
    if not missing or any(ch not in "0123456789abcdef" for ch in missing):
        raise ValueError("missing_chunk_id_hex must be a hex string")
    payload_parts = [("0", f'"$@{missing}"')]
    parts = list(prefix_parts or [])
    parts.extend(payload_parts)
    payload = build_multipart_form_payload(
        parts,
        meta={"probe_kind": "dec2025_missing_chunk", "missing_chunk": missing, "probe_strategy": "missing_chunk_root_thenable"},
    )
    return _with_payload_meta(payload, meta)


def build_dec2025_marker_root_payload(
    *,
    server_ref_marker: str,
    prefix_parts: list[tuple[str, str]] | None = None,
    meta: dict[str, Any] | None = None,
) -> RscPayload:
    if server_ref_marker not in {"F", "h"}:
        raise ValueError("server_ref_marker must be 'F' or 'h'")
    payload_parts = [
        ("1", _json_dumps({"id": None})),
        ("0", _json_dumps({"x": f"${server_ref_marker}1"})),
    ]
    parts = list(prefix_parts or [])
    parts.extend(payload_parts)
    payload = build_multipart_form_payload(
        parts,
        meta={"probe_kind": "dec2025_marker_root", "server_ref_marker": server_ref_marker, "probe_strategy": "marker_root_decode_error"},
    )
    return _with_payload_meta(payload, meta)


def build_dec2025_nextjs_promise_chain_payload(
    *,
    chain_depth: int,
    start_promise_id: int = 10,
    missing_chunk_id_hex: str = "ffff",
    prefix_parts: list[tuple[str, str]] | None = None,
    meta: dict[str, Any] | None = None,
) -> RscPayload:
    if chain_depth < 1:
        raise ValueError("chain_depth must be >= 1")

    missing = (missing_chunk_id_hex or "").lower().strip()
    if not missing or any(ch not in "0123456789abcdef" for ch in missing):
        raise ValueError("missing_chunk_id_hex must be a hex string")

    promise_count = chain_depth + 1
    promise_ids = [start_promise_id + idx for idx in range(promise_count)]
    first_promise_id = promise_ids[0]
    last_promise_id = promise_ids[-1]
    wrapper_chunk_id = last_promise_id + 1

    parts: list[tuple[str, str]] = list(prefix_parts or [])

    parts.append((str(last_promise_id), f'"$@{missing}"'))
    for index in range(len(promise_ids) - 2, -1, -1):
        promise_id = promise_ids[index]
        next_id = promise_ids[index + 1]
        parts.append((str(promise_id), f'"$@{next_id:x}"'))

    wrapper_items: list[str] = [f"$@{first_promise_id:x}"]
    wrapper_items.extend([f"${pid:x}" for pid in promise_ids])
    parts.append((str(wrapper_chunk_id), _json_dumps(wrapper_items)))

    parts.append(("0", f'"${wrapper_chunk_id:x}:0"'))

    payload = build_multipart_form_payload(
        parts,
        meta={
            "probe_kind": "dec2025_chain_root",
            "chain_depth": chain_depth,
            "missing_chunk": missing,
            "probe_strategy": "missing_chunk_chain_terminal",
        },
    )
    return _with_payload_meta(payload, meta)


def build_dec2025_promise_chain_payload(
    *,
    chain_depth: int,
    prefix_parts: list[tuple[str, str]] | None = None,
    meta: dict[str, Any] | None = None,
) -> RscPayload:
    if chain_depth < 1:
        raise ValueError("chain_depth must be >= 1")

    promise_count = chain_depth + 1
    init_chunk_id = promise_count + 1
    root_object_id = promise_count + 2

    parts: list[tuple[str, str]] = list(prefix_parts or [])

    terminal = build_no_invoke_args_container([], length_token=SAFE_ARGS_LENGTH_TOKEN)
    parts.append((str(promise_count), _json_dumps(terminal)))
    for promise_id in range(promise_count - 1, 0, -1):
        next_hex = f"{(promise_id + 1):x}"
        parts.append((str(promise_id), f'"$@{next_hex}"'))

    init_list = [f"${pid:x}" for pid in range(promise_count, 0, -1)]
    parts.append((str(init_chunk_id), _json_dumps(init_list)))
    parts.append((str(root_object_id), f'{{"a":"$@1","b":"${init_chunk_id:x}"}}'))
    parts.append(("0", f'"${root_object_id:x}:a"'))

    payload = build_multipart_form_payload(
        parts,
        meta={
            "probe_kind": "dec2025_chain",
            "chain_depth": chain_depth,
            "probe_strategy": SAFE_ARGS_STRATEGY,
        },
    )
    return _with_payload_meta(payload, meta)


__all__ = [
    "SAFE_ARGS_LENGTH_TOKEN",
    "SAFE_ARGS_STRATEGY",
    "NO_INVOKE_ROOT_REF_STRATEGY",
    "NO_INVOKE_TEMP_REF_STRATEGY",
    "NO_INVOKE_TEMP_REF_TOKEN",
    "build_no_invoke_args_container",
    "RscReference",
    "build_multipart_form_payload",
    "build_json_decode_payload",
    "build_multipart_decode_payload",
    "build_nextjs_action_multipart_payload",
    "build_plaintext_decode_payload",
    "build_plaintext_payload",
    "build_random_safe_prop",
    "build_decode_payload_factories",
    "build_nextjs_action_payload_factories",
    "build_safe_args_payload_factories",
    "build_no_invoke_temp_ref_payload",
    "build_dec2025_safe_control_payload",
    "build_dec2025_missing_chunk_payload",
    "build_dec2025_marker_root_payload",
    "build_dec2025_nextjs_promise_chain_payload",
    "build_dec2025_promise_chain_payload",
]
