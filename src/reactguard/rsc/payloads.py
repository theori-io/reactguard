# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RSC payload builders (multipart/plain/JSON) shared across frameworks."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable
from dataclasses import dataclass

from .types import RscPayload, RscWireFormat


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
    A React Server Components "server reference" string used in decode surfaces.

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
    Minimal multipart payload that exercises React's decode surface.

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
]
