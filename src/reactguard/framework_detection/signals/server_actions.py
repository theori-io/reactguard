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

"""Server Actions probing helpers (httpx-backed)."""

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from ...config import load_http_settings
from ...errors import ErrorCategory
from ...http import scan_with_retry
from ...http.client import HttpClient
from ...utils import TagSet
from ...utils.actions import generate_action_id
from ...utils.context import scan_context
from ..constants import (
    FRAMEWORK_HTML_MARKERS,
    SERVER_ACTIONS_ACTION_KEYWORDS,
    SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    SERVER_ACTIONS_FLIGHT_PATTERN,
    SERVER_ACTIONS_HTML_PATTERN,
    SERVER_ACTIONS_RSC_CONTENT_TYPE,
    SERVER_ACTIONS_RSC_ERROR_PATTERN,
    SERVER_ACTIONS_RSC_FLIGHT_PATTERN,
    SERVER_ACTIONS_STRONG_ACTION_KEYWORDS,
)


@dataclass
class ServerActionsSignalApplier:
    """Stateful applier for folding server action probe results into tags/signals."""

    tags: TagSet
    signals: dict[str, Any]
    base_url: str | None = None
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER
    payload_style: str = "multipart"
    server_actions_tag: str | None = None
    not_found_signal_key: str | None = None
    vary_signal_key: str | None = None
    react_major_signal_key: str | None = None
    rsc_flight_signal_key: str | None = None
    fallback_html_signal_key: str | None = None
    set_defaults: bool = False
    default_confidence: str = "medium"
    action_endpoints: list[str] | None = None

    def apply(
        self,
        probe_result: dict[str, Any] | None = None,
        *,
        html_marker_hint: bool = False,
        proxy_profile: str | None = None,
        correlation_id: str | None = None,
        http_client: HttpClient | None = None,
    ) -> dict[str, Any]:
        if probe_result is None:
            if proxy_profile is not None or correlation_id is not None or http_client is not None:
                with scan_context(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client):
                    probe_result = _probe_server_actions_support_ctx(
                        self.base_url or "",
                        action_header=self.action_header,
                        payload_style=self.payload_style,
                        action_endpoints=self.action_endpoints,
                    )
            else:
                probe_result = _probe_server_actions_support_ctx(
                    self.base_url or "",
                    action_header=self.action_header,
                    payload_style=self.payload_style,
                    action_endpoints=self.action_endpoints,
                )

        status = probe_result.get("status_code")
        has_framework_marker = bool(probe_result.get("has_framework_html_marker") or probe_result.get("has_next_marker") or html_marker_hint)
        has_action_keywords = bool(probe_result.get("has_action_keywords"))
        has_action_content_type = bool(probe_result.get("has_action_content_type"))
        has_flight_marker = bool(probe_result.get("has_flight_marker"))
        has_digest = bool(probe_result.get("has_digest"))
        is_html = bool(probe_result.get("is_html"))
        action_not_found = bool(probe_result.get("action_not_found_header") or probe_result.get("action_not_found_body"))
        vary_has_rsc = bool(probe_result.get("vary_has_rsc"))
        flight_format = probe_result.get("flight_format")
        react_major_from_flight = probe_result.get("react_major_from_flight")

        supported = bool(probe_result.get("supported"))
        confidence = probe_result.get("confidence") or self.default_confidence

        strong_rsc_signal = has_action_content_type or has_flight_marker or has_digest

        if self.not_found_signal_key and action_not_found:
            self.signals[self.not_found_signal_key] = True

        # Only promote "action not found" when paired with strong RSC evidence; plain 404 text should stay unknown.
        if action_not_found and strong_rsc_signal:
            supported = True
            confidence = "high"

        if not supported:
            if strong_rsc_signal:
                supported = True
            elif status in (400, 404, 500) and has_action_keywords and has_framework_marker:
                supported = True
            elif is_html and has_action_keywords and has_framework_marker and status in (400, 404, 500, 200):
                supported = True

        if flight_format in {"object", "array"} and self.rsc_flight_signal_key:
            self.signals[self.rsc_flight_signal_key] = True

        if self.react_major_signal_key and react_major_from_flight is not None and self.signals.get(self.react_major_signal_key) is None:
            self.signals[self.react_major_signal_key] = react_major_from_flight
            self.signals.setdefault(f"{self.react_major_signal_key}_confidence", "medium")

        if self.vary_signal_key and vary_has_rsc:
            self.signals[self.vary_signal_key] = True

        if supported:
            self.signals["server_actions_enabled"] = True
            self.signals["server_actions_confidence"] = confidence
            if self.server_actions_tag:
                self.tags.add(self.server_actions_tag)
        elif status in (404, 405) and not action_not_found:
            self.signals["server_actions_enabled"] = False
            self.signals["server_actions_confidence"] = "high"
        elif is_html and has_framework_marker:
            self.signals["server_actions_enabled"] = False
            self.signals["server_actions_confidence"] = "low"
            if self.fallback_html_signal_key:
                self.signals[self.fallback_html_signal_key] = True
        elif self.set_defaults:
            self.signals.setdefault("server_actions_enabled", None)
            self.signals.setdefault("server_actions_confidence", "none")

        return {
            "supported": supported,
            "confidence": self.signals.get("server_actions_confidence"),
            "status_code": status,
            "probe_result": probe_result,
        }


def _user_agent() -> str:
    return load_http_settings().user_agent


def _probe_server_actions_support_ctx(
    base_url: str,
    *,
    action_id: str = "probe",
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    payload_style: str = "plain",
    action_endpoints: list[str] | None = None,
) -> dict[str, Any]:
    if not base_url:
        return {
            "supported": False,
            "error_category": ErrorCategory.UNKNOWN_ERROR.value,
            "error_message": "No base URL provided",
        }

    def _build_boundary() -> str:
        return f"----FormBoundary{secrets.token_hex(8)}"

    headers = {
        action_header: action_id,
        "Accept": "text/x-component",
        "User-Agent": _user_agent(),
    }

    if payload_style == "multipart":
        boundary = _build_boundary()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        body = "\r\n".join(
            [
                f"--{boundary}",
                'Content-Disposition: form-data; name="0"',
                "",
                "[]",
                f"--{boundary}--",
                "",
            ]
        )
    else:
        headers["Content-Type"] = "text/plain;charset=UTF-8"
        body = ""

    target_url = base_url
    if action_endpoints:
        preferred = action_endpoints[0]
        target_url = preferred if preferred.startswith("http") else urljoin(base_url, preferred)

    resp = scan_with_retry(
        target_url,
        method="POST",
        headers=headers,
        body=body,
    )

    headers_lower = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    content_type = headers_lower.get("content-type", "").lower()
    vary = headers_lower.get("vary", "").lower()
    body_text = resp.get("body") or resp.get("body_snippet") or ""
    body_lower = body_text.lower()
    status = resp.get("status_code")

    action_not_found_header = headers_lower.get("x-nextjs-action-not-found") == "1"
    action_not_found_body = body_lower.strip() == "server action not found."
    vary_has_rsc = False
    if vary:
        vary_parts = [part.strip().lower() for part in vary.split(",")]
        vary_has_rsc = any(part == "rsc" for part in vary_parts)
    has_action_keywords = any(keyword in body_lower for keyword in SERVER_ACTIONS_ACTION_KEYWORDS)
    has_strong_action_keywords = any(keyword in body_lower for keyword in SERVER_ACTIONS_STRONG_ACTION_KEYWORDS)
    has_generic_action_keywords = has_action_keywords and not has_strong_action_keywords
    has_flight_marker = bool(SERVER_ACTIONS_FLIGHT_PATTERN.match(body_text.strip()))
    has_action_content_type = content_type.startswith(SERVER_ACTIONS_RSC_CONTENT_TYPE) or content_type.startswith("application/json")
    is_html = bool(SERVER_ACTIONS_HTML_PATTERN.search(body_text))
    has_digest = '"digest"' in body_lower
    has_framework_html_marker = any(marker in body_lower for marker in FRAMEWORK_HTML_MARKERS)
    has_next_marker = "__next_f" in body_lower or "__next_data__" in body_lower

    flight_format = "unknown"
    react_major_from_flight: int | None = None
    body_stripped = body_text.lstrip()
    if body_stripped.startswith("0:{") or '0:[null,["$' in body_text or '0:[null,[\\"$' in body_text:
        flight_format = "object"
        react_major_from_flight = 19
    elif body_stripped.startswith("0:[") or '0:["$' in body_text or '0:[\\"$' in body_text or '0:\\"$L' in body_text:
        flight_format = "array"
        react_major_from_flight = 18
    elif '"a":"$' in body_text:
        flight_format = "object"
        react_major_from_flight = 19

    supported = False
    if resp.get("ok"):
        strong_rsc_signal = has_action_content_type or has_flight_marker or has_digest
        keyword_hint = has_strong_action_keywords and (has_action_content_type or has_flight_marker or has_digest or has_framework_html_marker)
        generic_keyword_hint = has_generic_action_keywords and (has_framework_html_marker or has_action_content_type or has_flight_marker)

        if strong_rsc_signal:
            supported = True
        elif keyword_hint or generic_keyword_hint:
            supported = True
        elif is_html and has_framework_html_marker and has_action_keywords:
            supported = True

    if not supported and status and status >= 500:
        if has_action_content_type or has_action_keywords or has_framework_html_marker or has_flight_marker or is_html:
            supported = True

    if not supported and status not in (404, 405) and is_html and has_framework_html_marker and (has_action_keywords or has_flight_marker or has_action_content_type):
        supported = True

    return {
        "supported": bool(supported),
        "status_code": status,
        "content_type": content_type,
        "has_action_content_type": has_action_content_type,
        "has_action_keywords": has_action_keywords,
        "has_flight_marker": has_flight_marker,
        "has_digest": has_digest,
        "has_framework_html_marker": has_framework_html_marker,
        "has_next_marker": has_next_marker,
        "is_html": is_html,
        "action_not_found_header": action_not_found_header,
        "action_not_found_body": action_not_found_body,
        "vary_has_rsc": vary_has_rsc,
        "flight_format": flight_format,
        "react_major_from_flight": react_major_from_flight,
        "body_snippet": resp.get("body_snippet", ""),
        "body": resp.get("body"),
        "error_category": resp.get("error_category"),
        "error_message": resp.get("error_message"),
        "payload_style": payload_style,
        "ok": resp.get("ok", False),
        "probe_url": target_url,
    }


def probe_server_actions_support(
    base_url: str,
    *,
    action_id: str = "probe",
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    payload_style: str = "plain",
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    timeout: float | None = None,
    http_client: HttpClient | None = None,
    action_endpoints: list[str] | None = None,
) -> dict[str, Any]:
    if proxy_profile is not None or correlation_id is not None or timeout is not None or http_client is not None:
        with scan_context(
            proxy_profile=proxy_profile,
            correlation_id=correlation_id,
            timeout=timeout,
            http_client=http_client,
        ):
            return _probe_server_actions_support_ctx(
                base_url,
                action_id=action_id,
                action_header=action_header,
                payload_style=payload_style,
                action_endpoints=action_endpoints,
            )
    return _probe_server_actions_support_ctx(
        base_url,
        action_id=action_id,
        action_header=action_header,
        payload_style=payload_style,
        action_endpoints=action_endpoints,
    )


def _detect_server_actions_ctx(
    url: str,
    *,
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
) -> dict[str, Any]:
    action_id = generate_action_id()
    boundary = f"----FormBoundary{secrets.token_hex(8)}"
    body = "\r\n".join(
        [
            f"--{boundary}",
            'Content-Disposition: form-data; name="0"',
            "",
            "[]",
            f"--{boundary}--",
            "",
        ]
    )
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        action_header: action_id,
        "Accept": "text/x-component",
        "User-Agent": _user_agent(),
    }

    scan = scan_with_retry(
        url,
        method="POST",
        headers=headers,
        body=body,
    )

    if not scan.get("ok"):
        return {
            "supported": False,
            "confidence": "none",
            "reason": scan.get("error_message", "Probe failed"),
            "error_category": scan.get("error_category"),
        }

    status_code = scan.get("status_code", 0)
    response_headers = scan.get("headers", {})
    body_text = scan.get("body") or scan.get("body_snippet", "")
    content_type = response_headers.get("content-type", "")

    is_rsc_content_type = SERVER_ACTIONS_RSC_CONTENT_TYPE in content_type
    has_flight_format = bool(SERVER_ACTIONS_RSC_FLIGHT_PATTERN.match(body_text))
    has_rsc_error = bool(SERVER_ACTIONS_RSC_ERROR_PATTERN.search(body_text))
    is_html = bool(SERVER_ACTIONS_HTML_PATTERN.search(body_text))

    if status_code in (404, 405):
        return {
            "supported": False,
            "confidence": "high",
            "reason": f"Endpoint returned {status_code} - server actions not available",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if is_html and status_code == 200:
        return {
            "supported": True,
            "confidence": "low",
            "reason": "HTML response with framework markers - likely dev/HTML wrapper on action path",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if is_html and status_code == 500:
        return {
            "supported": True,
            "confidence": "low",
            "reason": "HTML 500 from POST with framework markers - likely dev overlay on action path",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if is_rsc_content_type or has_flight_format:
        if status_code == 200:
            return {
                "supported": True,
                "confidence": "high",
                "reason": "RSC response received - server actions enabled",
                "status_code": status_code,
                "content_type": content_type,
                "has_rsc_format": True,
            }
        if status_code == 500 and has_rsc_error:
            return {
                "supported": True,
                "confidence": "high",
                "reason": "RSC error response - server actions enabled (error in action processing)",
                "status_code": status_code,
                "content_type": content_type,
                "has_rsc_format": True,
            }
        return {
            "supported": True,
            "confidence": "medium",
            "reason": f"RSC format detected with status {status_code}",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": True,
        }

    if status_code == 500 and not is_html:
        return {
            "supported": True,
            "confidence": "low",
            "reason": "Server error (500) from POST - possible server action processing",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if status_code in (301, 302, 303, 307, 308):
        return {
            "supported": False,
            "confidence": "medium",
            "reason": f"Redirect ({status_code}) - server actions likely not enabled",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    return {
        "supported": False,
        "confidence": "low",
        "reason": f"Inconclusive response (status {status_code})",
        "status_code": status_code,
        "content_type": content_type,
        "has_rsc_format": has_flight_format,
    }


def detect_server_actions(
    url: str,
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    http_client: HttpClient | None = None,
) -> dict[str, Any]:
    if proxy_profile is not None or correlation_id is not None or http_client is not None:
        with scan_context(proxy_profile=proxy_profile, correlation_id=correlation_id, http_client=http_client):
            return _detect_server_actions_ctx(url, action_header=action_header)
    return _detect_server_actions_ctx(url, action_header=action_header)


def apply_server_actions_probe_results(
    *,
    base_url: str | None = None,
    probe_result: dict[str, Any] | None = None,
    tags: TagSet,
    signals: dict[str, Any],
    proxy_profile: str | None = None,
    correlation_id: str | None = None,
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    payload_style: str = "multipart",
    server_actions_tag: str | None = None,
    html_marker_hint: bool = False,
    not_found_signal_key: str | None = None,
    vary_signal_key: str | None = None,
    react_major_signal_key: str | None = None,
    rsc_flight_signal_key: str | None = None,
    fallback_html_signal_key: str | None = None,
    set_defaults: bool = False,
    default_confidence: str = "medium",
    http_client: HttpClient | None = None,
    action_endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """
    Interpret a server actions probe and fold results into tags/signals.

    - Accepts either an existing probe_result or base_url to probe.
    - Applies standard heuristics (action keywords + framework markers, RSC content, etc.).
    - Optionally tags, sets defaults, and records framework-specific signal keys.
    """
    applier = ServerActionsSignalApplier(
        tags=tags,
        signals=signals,
        base_url=base_url,
        action_header=action_header,
        payload_style=payload_style,
        server_actions_tag=server_actions_tag,
        not_found_signal_key=not_found_signal_key,
        vary_signal_key=vary_signal_key,
        react_major_signal_key=react_major_signal_key,
        rsc_flight_signal_key=rsc_flight_signal_key,
        fallback_html_signal_key=fallback_html_signal_key,
        set_defaults=set_defaults,
        default_confidence=default_confidence,
        action_endpoints=action_endpoints,
    )
    return applier.apply(
        probe_result=probe_result,
        html_marker_hint=html_marker_hint,
        proxy_profile=proxy_profile,
        correlation_id=correlation_id,
        http_client=http_client,
    )


__all__ = [
    "detect_server_actions",
    "generate_action_id",
    "apply_server_actions_probe_results",
    "probe_server_actions_support",
]
