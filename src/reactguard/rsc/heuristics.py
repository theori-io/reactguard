# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared response heuristics for RSC/Server Actions probing."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..http.headers import header_value
from ..http.heuristics import looks_like_html
from ..http.models import HttpResponse
from ..utils.react_major import infer_react_major_from_flight_text

RSC_CONTENT_TYPE = "text/x-component"

ACTION_NOT_FOUND_BODY_EXACT = "server action not found."
ACTION_NOT_FOUND_PHRASES = (
    "action not found",
    "invalid action",
    "unknown action",
    "action id not found",
    "no server action found",
    "server action not found",
)

ERROR_DIGEST_PATTERN = re.compile(r'"digest"\s*:\s*"([0-9A-Za-z@._:-]{6,128})"')

FLIGHT_DOC_START_RE = re.compile(r"^\s*\d+:")
FLIGHT_LINE_RE = re.compile(r"^\d+:(?:I\[|\[|\{)", re.MULTILINE)
FLIGHT_HINT_RE = re.compile(
    r'^\d+:(?:\["\$|\[null,\["\$|\{|I\["react-server-dom-|\{\s*"a"\s*:\s*"\$|\{\s*"id"\s*:\s*"\$)',
    re.MULTILINE,
)
FLIGHT_LREF_RE = re.compile(r'^\s*0:"\\?\$L', re.MULTILINE)


def response_body_text(result: Mapping[str, Any] | HttpResponse | None) -> str:
    """Return the best-available response body text from a result mapping or HttpResponse."""
    if not result:
        return ""
    if isinstance(result, HttpResponse):
        return str(result.text or result.body_snippet or "")
    body = result.get("body")
    if body:
        return str(body)
    snippet = result.get("body_snippet")
    return str(snippet) if snippet else ""


def is_rsc_content_type(headers: Mapping[object, object] | None) -> bool:
    """Return True when the Content-Type indicates an RSC Flight response."""
    content_type = header_value(headers, "content-type").lower()
    return RSC_CONTENT_TYPE in content_type


def looks_like_flight_payload(body: str | None) -> bool:
    """Return True when the body contains RSC Flight-like rows."""
    if not body:
        return False
    text = str(body)
    if FLIGHT_HINT_RE.search(text):
        return True
    if FLIGHT_LINE_RE.search(text):
        return True
    if FLIGHT_LREF_RE.search(text):
        return True
    if infer_react_major_from_flight_text(text) is not None:
        return True
    return False


def response_looks_like_flight(
    headers: Mapping[object, object] | None,
    body: str | None,
    *,
    allow_html: bool = False,
) -> bool:
    """Return True when headers/body indicate RSC Flight (optionally rejecting HTML)."""
    if not allow_html and looks_like_html(headers, body):
        return False
    return is_rsc_content_type(headers) or looks_like_flight_payload(body)


def flight_format_from_body(body: str | None) -> str:
    """Return 'object', 'array', or 'unknown' based on Flight payload shape."""
    major = infer_react_major_from_flight_text(str(body or ""))
    if major == 19:
        return "object"
    if major == 18:
        return "array"
    return "unknown"


def is_action_not_found_header(headers: Mapping[object, object] | None) -> bool:
    return header_value(headers, "x-nextjs-action-not-found") == "1"


def is_action_not_found_body(body: str | None) -> bool:
    text = str(body or "").strip().lower()
    if not text:
        return False
    if text == ACTION_NOT_FOUND_BODY_EXACT:
        return True
    return any(phrase in text for phrase in ACTION_NOT_FOUND_PHRASES)


def is_action_not_found(headers: Mapping[object, object] | None, body: str | None) -> bool:
    return is_action_not_found_header(headers) or is_action_not_found_body(body)


def is_action_not_found_response(result: Mapping[str, Any] | HttpResponse | None) -> bool:
    if not result:
        return False
    if isinstance(result, HttpResponse):
        headers = result.headers
    else:
        headers = result.get("headers")
    body = response_body_text(result)
    return is_action_not_found(headers, body)


def extract_error_digest(body: str | None) -> str | None:
    """Extract the digest token from an RSC error payload."""
    if not body:
        return None
    match = ERROR_DIGEST_PATTERN.search(str(body))
    return match.group(1) if match else None


def is_timeout_result(result: Mapping[str, Any] | HttpResponse | None) -> bool:
    """Return True when a result mapping indicates a transport timeout."""
    if not result:
        return False
    if isinstance(result, HttpResponse):
        error_type = str(result.error_type or "").lower()
        if "timeout" in error_type:
            return True
        error_message = str(result.error_message or "").lower()
        return "timed out" in error_message or "timeout" in error_message
    error_type = str(result.get("error_type") or "").lower()
    if "timeout" in error_type:
        return True
    error_message = str(result.get("error_message") or "").lower()
    return "timed out" in error_message or "timeout" in error_message


@dataclass(frozen=True)
class RscResponseClassification:
    is_html: bool
    looks_like_flight: bool
    action_not_found: bool
    digest: str | None
    content_type: str
    status_code: int | None
    flight_format: str


def classify_rsc_response(result: Mapping[str, Any] | HttpResponse | None, *, allow_html: bool = False) -> RscResponseClassification:
    """
    Normalize common RSC response heuristics (HTML detection, Flight markers, action-not-found, digest).
    """
    if isinstance(result, HttpResponse):
        headers = result.headers or {}
        body = response_body_text(result)
        status_code = result.status_code
    else:
        headers = (result.get("headers") if isinstance(result, Mapping) else {}) or {}
        body = response_body_text(result)
        status_code = result.get("status_code") if isinstance(result, Mapping) else None

    content_type = header_value(headers, "content-type").lower()
    is_html = looks_like_html(headers, body)
    looks_like_flight = response_looks_like_flight(headers, body, allow_html=allow_html)
    action_not_found = is_action_not_found(headers, body)
    digest = extract_error_digest(body)
    flight_format = flight_format_from_body(body)

    return RscResponseClassification(
        is_html=is_html,
        looks_like_flight=looks_like_flight,
        action_not_found=action_not_found,
        digest=digest,
        content_type=content_type,
        status_code=status_code,
        flight_format=flight_format,
    )


__all__ = [
    "ERROR_DIGEST_PATTERN",
    "ACTION_NOT_FOUND_BODY_EXACT",
    "ACTION_NOT_FOUND_PHRASES",
    "FLIGHT_DOC_START_RE",
    "FLIGHT_HINT_RE",
    "FLIGHT_LINE_RE",
    "FLIGHT_LREF_RE",
    "RSC_CONTENT_TYPE",
    "extract_error_digest",
    "flight_format_from_body",
    "is_action_not_found",
    "is_action_not_found_body",
    "is_action_not_found_header",
    "is_action_not_found_response",
    "is_rsc_content_type",
    "is_timeout_result",
    "looks_like_flight_payload",
    "classify_rsc_response",
    "RscResponseClassification",
    "response_body_text",
    "response_looks_like_flight",
]
