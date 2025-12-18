# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Server Actions probing helpers (httpx-backed)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from ...config import load_http_settings
from ...http.headers import header_value, normalize_headers
from ...rsc.payloads import build_multipart_form_payload, build_plaintext_payload
from ...rsc.send import send_rsc_request
from ...rsc.types import RscRequestConfig
from ...utils import TagSet
from ...utils.actions import generate_action_id
from ...utils.confidence import confidence_score
from ...utils.react_major import infer_react_major_from_flight_text, react_major_source_priority
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
from ..keys import SIG_SERVER_ACTIONS_CONFIDENCE, SIG_SERVER_ACTIONS_ENABLED


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
    ) -> dict[str, Any]:
        if probe_result is None:
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

        strong_rsc_signal = has_action_content_type or has_flight_marker or has_digest or (
            # `Vary: RSC` is a useful hint, but on HTML responses it can be a false positive for
            # Server Actions (e.g., app/router pages that are RSC-capable but have no actions).
            (not is_html) and vary_has_rsc and (status not in (404, 405) or action_not_found)
        )

        if self.not_found_signal_key and action_not_found:
            self.signals[self.not_found_signal_key] = True

        # Only promote "action not found" when paired with strong RSC evidence; plain 404 text should stay unknown.
        #
        # `x-nextjs-action-not-found: 1` is a reliable indicator that the target is Server Actions-capable,
        # but it does *not* prove a reachable decode surface on this route. Keep confidence at most
        # medium unless we also see concrete Flight/decode evidence (content-type, Flight rows, digest).
        if action_not_found and strong_rsc_signal:
            supported = True
            confidence = "high" if (has_action_content_type or has_flight_marker or has_digest) else "medium"

        if not supported:
            if strong_rsc_signal:
                supported = True
            elif status in (400, 404, 500) and has_action_keywords and has_framework_marker:
                supported = True
            elif is_html and has_action_keywords and has_framework_marker and status in (400, 404, 500, 200):
                supported = True

        if flight_format in {"object", "array"} and self.rsc_flight_signal_key:
            self.signals[self.rsc_flight_signal_key] = True

        if self.react_major_signal_key and react_major_from_flight is not None:
            key = self.react_major_signal_key
            new_confidence = "medium"
            new_source = "flight:server_actions_probe"

            current_confidence = str(self.signals.get(f"{key}_confidence") or "none")
            current_source = str(self.signals.get(f"{key}_source") or "")
            current_major = self.signals.get(key)

            should_set = False
            if current_major is None:
                should_set = True
            elif confidence_score(new_confidence) > confidence_score(current_confidence):
                should_set = True
            elif confidence_score(new_confidence) == confidence_score(current_confidence) and react_major_source_priority(new_source) > react_major_source_priority(current_source):
                should_set = True

            if should_set:
                self.signals[key] = react_major_from_flight
                self.signals[f"{key}_confidence"] = new_confidence
                self.signals[f"{key}_source"] = new_source

        if self.vary_signal_key and vary_has_rsc:
            self.signals[self.vary_signal_key] = True

        if supported:
            self.signals[SIG_SERVER_ACTIONS_ENABLED] = True
            self.signals[SIG_SERVER_ACTIONS_CONFIDENCE] = confidence
            if self.server_actions_tag:
                self.tags.add(self.server_actions_tag)
        elif status in (404, 405) and not action_not_found:
            # A 404/405 on an arbitrary POST probe can mean:
            # - actions disabled, or
            # - wrong route / app blocks POST on this page, or
            # - auth/routing differences.
            #
            # Only treat this as a confident negative when we are probing a known action endpoint.
            if self.action_endpoints:
                self.signals[SIG_SERVER_ACTIONS_ENABLED] = False
                self.signals[SIG_SERVER_ACTIONS_CONFIDENCE] = "high"
            else:
                self.signals.setdefault(SIG_SERVER_ACTIONS_ENABLED, None)
                self.signals.setdefault(SIG_SERVER_ACTIONS_CONFIDENCE, "low")
        elif is_html and has_framework_marker:
            # HTML wrappers/dev overlays are often uninterpretable for action reachability (FN-prone).
            # Record the hint but keep reachability unknown.
            self.signals.setdefault(SIG_SERVER_ACTIONS_ENABLED, None)
            self.signals.setdefault(SIG_SERVER_ACTIONS_CONFIDENCE, "low")
            if self.fallback_html_signal_key:
                self.signals[self.fallback_html_signal_key] = True
        elif self.set_defaults:
            self.signals.setdefault(SIG_SERVER_ACTIONS_ENABLED, None)
            self.signals.setdefault(SIG_SERVER_ACTIONS_CONFIDENCE, "low")

        return {
            "supported": supported,
            "confidence": self.signals.get(SIG_SERVER_ACTIONS_CONFIDENCE),
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
            "error_message": "No base URL provided",
        }

    request_config = RscRequestConfig(
        method="POST",
        base_headers={
            "Accept": "text/x-component",
            "User-Agent": _user_agent(),
        },
        action_id_header=action_header,
    )

    payload = (
        build_multipart_form_payload([("0", "[]")], meta={"probe_kind": "server_actions_support"})
        if payload_style == "multipart"
        else build_plaintext_payload("", meta={"probe_kind": "server_actions_support"})
    )

    target_url = base_url
    if action_endpoints:
        preferred = action_endpoints[0]
        target_url = preferred if preferred.startswith("http") else urljoin(base_url, preferred)

    resp = send_rsc_request(
        target_url,
        request_config,
        payload,
        action_id=action_id,
    )

    headers_lower = normalize_headers(resp.get("headers"))
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

    react_major_from_flight = infer_react_major_from_flight_text(body_text)
    flight_format = "unknown"
    if react_major_from_flight == 19:
        flight_format = "object"
    elif react_major_from_flight == 18:
        flight_format = "array"

    confidence = "none"
    supported = False
    if resp.get("ok"):
        # `Vary: RSC` can appear on ordinary Next.js HTML responses when probing with RSC-ish headers.
        # Treat it as a strong Server Actions signal only when we are *not* looking at an HTML document
        # (e.g., empty body, plaintext errors, Flight payloads). Otherwise it is too FN/FP-prone.
        vary_rsc_strong = (not is_html) and vary_has_rsc and (status not in (404, 405) or action_not_found_header or action_not_found_body)
        strong_rsc_signal = has_action_content_type or has_flight_marker or has_digest or vary_rsc_strong
        keyword_hint = has_strong_action_keywords and (has_action_content_type or has_flight_marker or has_digest or has_framework_html_marker)
        generic_keyword_hint = has_generic_action_keywords and (has_framework_html_marker or has_action_content_type or has_flight_marker)

        if strong_rsc_signal:
            supported = True
            confidence = "high" if (has_action_content_type or has_flight_marker or has_digest) else "medium"
        elif keyword_hint or generic_keyword_hint:
            supported = True
            confidence = "low"
        elif is_html and has_framework_html_marker and has_action_keywords:
            supported = True
            confidence = "low"

    if not supported and status and status >= 500:
        if has_action_content_type or has_action_keywords or has_framework_html_marker or has_flight_marker or is_html:
            supported = True
            confidence = "low" if confidence == "none" else confidence

    if not supported and status not in (404, 405) and is_html and has_framework_html_marker and (has_action_keywords or has_flight_marker or has_action_content_type):
        supported = True
        confidence = "low" if confidence == "none" else confidence

    return {
        "supported": bool(supported),
        "confidence": confidence,
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
        "error_message": resp.get("error_message"),
        "error_type": resp.get("error_type"),
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
    action_endpoints: list[str] | None = None,
) -> dict[str, Any]:
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
    request_config = RscRequestConfig(
        method="POST",
        base_headers={
            "Accept": "text/x-component",
            "User-Agent": _user_agent(),
        },
        action_id_header=action_header,
    )
    payload = build_multipart_form_payload([("0", "[]")], meta={"probe_kind": "server_actions_detect"})

    scan = send_rsc_request(
        url,
        request_config,
        payload,
        action_id=action_id,
    )

    if not scan.get("ok"):
        return {
            "supported": False,
            "confidence": "low",
            "reason": scan.get("error_message", "Server Actions probe failed"),
            "error_message": scan.get("error_message"),
            "error_type": scan.get("error_type"),
        }

    status_code = scan.get("status_code", 0)
    response_headers = scan.get("headers", {})
    body_text = scan.get("body") or scan.get("body_snippet", "")
    content_type = header_value(response_headers, "content-type")
    content_type_lower = content_type.lower()

    is_rsc_content_type = SERVER_ACTIONS_RSC_CONTENT_TYPE in content_type_lower
    has_flight_format = bool(SERVER_ACTIONS_RSC_FLIGHT_PATTERN.match(body_text))
    has_rsc_error = bool(SERVER_ACTIONS_RSC_ERROR_PATTERN.search(body_text))
    is_html = bool(SERVER_ACTIONS_HTML_PATTERN.search(body_text))

    if status_code in (404, 405):
        return {
            "supported": False,
            "confidence": "medium",
            "reason": f"Endpoint returned {status_code} - Server Actions not observed on this route",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if is_html and status_code == 200:
        return {
            "supported": True,
            "confidence": "low",
            "reason": "HTML 200 response to Server Actions probe - possible dev/HTML wrapper on action path",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if is_html and status_code == 500:
        return {
            "supported": True,
            "confidence": "low",
            "reason": "HTML 500 response to Server Actions probe - possible dev error page on action path",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if is_rsc_content_type or has_flight_format:
        if status_code == 200:
            return {
                "supported": True,
                "confidence": "high",
                "reason": "RSC Flight response received - Server Actions enabled",
                "status_code": status_code,
                "content_type": content_type,
                "has_rsc_format": True,
            }
        if status_code == 500 and has_rsc_error:
            return {
                "supported": True,
                "confidence": "high",
                "reason": "RSC error response received - Server Actions enabled (action processing returned 5xx)",
                "status_code": status_code,
                "content_type": content_type,
                "has_rsc_format": True,
            }
        return {
            "supported": True,
            "confidence": "medium",
            "reason": f"RSC Flight format detected with status {status_code}",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": True,
        }

    if status_code == 500 and not is_html:
        return {
            "supported": True,
            "confidence": "low",
            "reason": "Non-HTML 500 response to Server Actions probe - possible Server Actions processing",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    if status_code in (301, 302, 303, 307, 308):
        return {
            "supported": False,
            "confidence": "medium",
            "reason": f"Redirect ({status_code}) - Server Actions likely not enabled",
            "status_code": status_code,
            "content_type": content_type,
            "has_rsc_format": False,
        }

    return {
        "supported": False,
        "confidence": "low",
        "reason": f"Inconclusive Server Actions probe response (status {status_code})",
        "status_code": status_code,
        "content_type": content_type,
        "has_rsc_format": has_flight_format,
    }


def detect_server_actions(
    url: str,
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
) -> dict[str, Any]:
    return _detect_server_actions_ctx(url, action_header=action_header)


def apply_server_actions_probe_results(
    *,
    base_url: str | None = None,
    probe_result: dict[str, Any] | None = None,
    tags: TagSet,
    signals: dict[str, Any],
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
    )


__all__ = [
    "detect_server_actions",
    "generate_action_id",
    "apply_server_actions_probe_results",
    "probe_server_actions_support",
]
