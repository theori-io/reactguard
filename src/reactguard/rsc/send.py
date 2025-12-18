# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP sending routine for RSC probe requests."""

from __future__ import annotations

from ..http import request_with_retries
from .types import RscHttpResult, RscPayload, RscRequestConfig


def send_rsc_request(
    url: str,
    config: RscRequestConfig,
    payload: RscPayload,
    *,
    action_id: str | None = None,
) -> RscHttpResult:
    """
    Send an RSC probe request using the shared HTTP stack.

    Returns a request_with_retries-compatible mapping with additional fields:
    - endpoint: request URL used
    - action_id: action/function identifier used (if provided)
    - request_wire_format: payload encoding identifier
    """
    headers = dict(config.base_headers or {})
    headers.update(payload.headers or {})
    if config.action_id_header and action_id:
        headers[config.action_id_header] = action_id

    try:
        raw = request_with_retries(
            url,
            method=config.method,
            headers=headers,
            body=payload.body,
            allow_redirects=config.allow_redirects,
        )
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raw = {
            "ok": False,
            "status_code": None,
            "headers": {},
            "body": "",
            "body_snippet": "",
            "url": url,
            "error_message": str(exc),
            "error_type": exc.__class__.__name__,
            "error": str(exc),
        }

    result: RscHttpResult = raw  # type: ignore[assignment]
    result.setdefault("endpoint", url)
    if action_id is not None:
        result.setdefault("action_id", action_id)
    result.setdefault("request_wire_format", str(payload.wire_format.value))
    result.setdefault("payload_meta", payload.meta)
    return result


__all__ = ["send_rsc_request"]
