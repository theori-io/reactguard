# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP sending routine for RSC probe requests."""

from __future__ import annotations

from ..http import request_with_retries
from ..http.models import HttpResponse
from .types import RscPayload, RscRequestConfig, RscResponse


def send_rsc_request(
    url: str,
    config: RscRequestConfig,
    payload: RscPayload,
    *,
    action_id: str | None = None,
) -> RscResponse:
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
        response = request_with_retries(
            url,
            method=config.method,
            headers=headers,
            body=payload.body,
            allow_redirects=config.allow_redirects,
        )
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        response = HttpResponse(
            ok=False,
            status_code=None,
            headers={},
            text="",
            url=url,
            error_message=str(exc),
            error_type=exc.__class__.__name__,
        )

    return RscResponse(
        ok=response.ok,
        status_code=response.status_code,
        headers=dict(response.headers or {}),
        text=response.text or "",
        content=response.content or b"",
        url=response.url or url,
        error_message=response.error_message,
        error_type=response.error_type,
        meta=dict(response.meta or {}),
        endpoint=url,
        action_id=action_id,
        request_wire_format=str(payload.wire_format.value),
        payload_meta=dict(payload.meta or {}),
    )


__all__ = ["send_rsc_request"]
