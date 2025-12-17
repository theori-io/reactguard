from __future__ import annotations

"""
ReactGuard, framework- and vulnerability-detection tooling for CVE-2025-55182 (React2Shell).
Copyright (C) 2025  Theori Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""HTTP sending routine for RSC probe requests."""

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
