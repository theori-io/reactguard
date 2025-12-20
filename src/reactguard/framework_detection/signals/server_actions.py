# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Next.js Server Actions probing helpers (RSC Flight protocol)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from ...utils.context import get_http_settings
from ...http.headers import header_value, normalize_headers
from ...http.heuristics import looks_like_html
from ...http.models import HttpResponse
from ...rsc.payloads import build_multipart_form_payload, build_plaintext_payload
from ...rsc.send import send_rsc_request
from ...rsc.runner import build_request_config
from ...rsc.heuristics import (
    classify_rsc_response,
    extract_error_digest,
    flight_format_from_body,
    is_action_not_found_body,
    is_action_not_found_header,
    is_rsc_content_type as is_rsc_content_type_header,
    looks_like_flight_payload,
    response_body_text,
)
from ...utils import flatten_version_map, normalize_version_map, TagSet
from ...utils.actions import generate_action_id
from ...utils.confidence import confidence_score
from ...utils.react_major import infer_react_major_from_flight_text, react_major_source_priority
from ...utils.version import update_version_pick
from ..base import DetectionState
from ..constants import (
    FRAMEWORK_HTML_MARKERS,
    SERVER_ACTIONS_ACTION_KEYWORDS,
    SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    SERVER_ACTIONS_RSC_CONTENT_TYPE,
    SERVER_ACTIONS_STRONG_ACTION_KEYWORDS,
)
from ..keys import SIG_DETECTED_VERSIONS, SIG_INVOCATION_CONFIDENCE, SIG_INVOCATION_ENABLED


@dataclass
class ServerActionsProbeResult:
    """Typed result for Server Actions probes (dict-like for compatibility)."""

    supported: bool
    confidence: str | None = None
    reason: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    has_rsc_format: bool | None = None
    has_action_content_type: bool | None = None
    has_action_keywords: bool | None = None
    has_flight_marker: bool | None = None
    has_digest: bool | None = None
    has_framework_html_marker: bool | None = None
    has_next_marker: bool | None = None
    is_html: bool | None = None
    action_not_found_header: bool | None = None
    action_not_found_body: bool | None = None
    vary_has_rsc: bool | None = None
    flight_format: str | None = None
    react_major_from_flight: int | None = None
    body_snippet: str | None = None
    body: str | None = None
    error_message: str | None = None
    error_type: str | None = None
    payload_style: str | None = None
    ok: bool | None = None
    probe_url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def _lookup(self, key: str) -> Any:
        if key in self.__dataclass_fields__:
            return getattr(self, key)
        if key in self.extra:
            return self.extra[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self._lookup(key)
        except KeyError:
            return default

    def __getitem__(self, key: str) -> Any:
        return self._lookup(key)

    def __iter__(self):
        return iter(self.to_mapping())

    def __len__(self) -> int:
        return len(self.to_mapping())

    def keys(self):
        return self.to_mapping().keys()

    def items(self):
        return self.to_mapping().items()

    def values(self):
        return self.to_mapping().values()

    def to_mapping(self) -> dict[str, Any]:
        data = {
            "supported": self.supported,
            "confidence": self.confidence,
            "reason": self.reason,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "has_rsc_format": self.has_rsc_format,
            "has_action_content_type": self.has_action_content_type,
            "has_action_keywords": self.has_action_keywords,
            "has_flight_marker": self.has_flight_marker,
            "has_digest": self.has_digest,
            "has_framework_html_marker": self.has_framework_html_marker,
            "has_next_marker": self.has_next_marker,
            "is_html": self.is_html,
            "action_not_found_header": self.action_not_found_header,
            "action_not_found_body": self.action_not_found_body,
            "vary_has_rsc": self.vary_has_rsc,
            "flight_format": self.flight_format,
            "react_major_from_flight": self.react_major_from_flight,
            "body_snippet": self.body_snippet,
            "body": self.body,
            "error_message": self.error_message,
            "error_type": self.error_type,
            "payload_style": self.payload_style,
            "ok": self.ok,
            "probe_url": self.probe_url,
        }
        data.update(self.extra)
        return data

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ServerActionsProbeResult":
        known_keys = {
            "supported",
            "confidence",
            "reason",
            "status_code",
            "content_type",
            "has_rsc_format",
            "has_action_content_type",
            "has_action_keywords",
            "has_flight_marker",
            "has_digest",
            "has_framework_html_marker",
            "has_next_marker",
            "is_html",
            "action_not_found_header",
            "action_not_found_body",
            "vary_has_rsc",
            "flight_format",
            "react_major_from_flight",
            "body_snippet",
            "body",
            "error_message",
            "error_type",
            "payload_style",
            "ok",
            "probe_url",
        }
        extra = {k: v for k, v in data.items() if k not in known_keys}
        return cls(
            supported=bool(data.get("supported")),
            confidence=data.get("confidence"),
            reason=data.get("reason"),
            status_code=data.get("status_code"),
            content_type=data.get("content_type"),
            has_rsc_format=data.get("has_rsc_format"),
            has_action_content_type=data.get("has_action_content_type"),
            has_action_keywords=data.get("has_action_keywords"),
            has_flight_marker=data.get("has_flight_marker"),
            has_digest=data.get("has_digest"),
            has_framework_html_marker=data.get("has_framework_html_marker"),
            has_next_marker=data.get("has_next_marker"),
            is_html=data.get("is_html"),
            action_not_found_header=data.get("action_not_found_header"),
            action_not_found_body=data.get("action_not_found_body"),
            vary_has_rsc=data.get("vary_has_rsc"),
            flight_format=data.get("flight_format"),
            react_major_from_flight=data.get("react_major_from_flight"),
            body_snippet=data.get("body_snippet"),
            body=data.get("body"),
            error_message=data.get("error_message"),
            error_type=data.get("error_type"),
            payload_style=data.get("payload_style"),
            ok=data.get("ok"),
            probe_url=data.get("probe_url"),
            extra=extra,
        )


def _normalize_probe_result(result: ServerActionsProbeResult | Mapping[str, Any] | None) -> ServerActionsProbeResult | None:
    if result is None:
        return None
    if isinstance(result, ServerActionsProbeResult):
        return result
    if isinstance(result, Mapping):
        return ServerActionsProbeResult.from_mapping(result)
    raise TypeError("Unsupported probe result type")


def _normalize_response(result: HttpResponse | Mapping[str, Any]) -> HttpResponse:
    if isinstance(result, HttpResponse):
        return result
    if isinstance(result, Mapping):
        return HttpResponse.from_mapping(result)
    raise TypeError("Unsupported response type")


@dataclass
class ServerActionsSignalApplier:
    """Stateful applier for folding server action probe results into tags/signals."""

    state: DetectionState
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

    @classmethod
    def from_state(cls, state: DetectionState, **kwargs: Any) -> "ServerActionsSignalApplier":
        return cls(state=state, **kwargs)

    @property
    def tags(self) -> TagSet:
        return self.state.tags

    @property
    def signals(self) -> dict[str, Any]:
        return self.state.signals

    def apply(
        self,
        probe_result: ServerActionsProbeResult | Mapping[str, Any] | None = None,
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

        normalized = _normalize_probe_result(probe_result) or ServerActionsProbeResult(supported=False)

        status = normalized.status_code
        has_framework_marker = bool(normalized.has_framework_html_marker or normalized.has_next_marker or html_marker_hint)
        has_action_keywords = bool(normalized.has_action_keywords)
        has_action_content_type = bool(normalized.has_action_content_type)
        has_flight_marker = bool(normalized.has_flight_marker)
        has_digest = bool(normalized.has_digest)
        is_html = bool(normalized.is_html)
        action_not_found = bool(normalized.action_not_found_header or normalized.action_not_found_body)
        vary_has_rsc = bool(normalized.vary_has_rsc)
        flight_format = normalized.flight_format
        react_major_from_flight = normalized.react_major_from_flight

        supported = bool(normalized.supported)
        confidence = normalized.confidence or self.default_confidence

        strong_rsc_signal = has_action_content_type or has_flight_marker or has_digest or (
            # `Vary: RSC` is a useful hint, but on HTML responses it can be a false positive for
            # Server Actions (e.g., App Router pages that are RSC-capable but have no actions).
            (not is_html) and vary_has_rsc and (status not in (404, 405) or action_not_found)
        )

        if self.not_found_signal_key and action_not_found:
            self.signals[self.not_found_signal_key] = True

        # Only promote "action not found" when paired with strong RSC evidence; plain 404 text should stay unknown.
        #
        # `x-nextjs-action-not-found: 1` is a reliable indicator that the target is Server Actions-capable,
        # but it does *not* prove a reachable Flight protocol payload deserialization surface on this route. Keep
        # confidence at most medium unless we also see concrete Flight evidence (content-type, Flight rows, digest).
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
            new_confidence = "medium"
            new_source = "flight:server_actions_probe"

            detected_versions = normalize_version_map(self.signals.get(SIG_DETECTED_VERSIONS))
            current_pick = detected_versions.get("react_major")
            current_confidence = str(current_pick.confidence if current_pick else (self.signals.get(f"{self.react_major_signal_key}_confidence") or "none"))
            current_source = str(current_pick.source if current_pick else (self.signals.get(f"{self.react_major_signal_key}_source") or ""))
            current_major = current_pick.value if current_pick else self.signals.get(self.react_major_signal_key)

            should_set = False
            if current_major is None:
                should_set = True
            elif confidence_score(new_confidence) > confidence_score(current_confidence):
                should_set = True
            elif confidence_score(new_confidence) == confidence_score(current_confidence) and react_major_source_priority(new_source) > react_major_source_priority(current_source):
                should_set = True

            if should_set:
                update_version_pick(
                    detected_versions,
                    "react_major",
                    react_major_from_flight,
                    source=new_source,
                    confidence=new_confidence,
                    prefer_semver=False,
                )
                self.signals[SIG_DETECTED_VERSIONS] = {key: pick.to_mapping() for key, pick in detected_versions.items()}
                self.signals.update(flatten_version_map(detected_versions, prefix="detected_"))

        if self.vary_signal_key and vary_has_rsc:
            self.signals[self.vary_signal_key] = True

        if supported:
            self.signals[SIG_INVOCATION_ENABLED] = True
            self.signals[SIG_INVOCATION_CONFIDENCE] = confidence
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
                self.signals[SIG_INVOCATION_ENABLED] = False
                self.signals[SIG_INVOCATION_CONFIDENCE] = "high"
            else:
                self.signals.setdefault(SIG_INVOCATION_ENABLED, None)
                self.signals.setdefault(SIG_INVOCATION_CONFIDENCE, "low")
        elif is_html and has_framework_marker:
            # HTML wrappers/dev overlays are often uninterpretable for action reachability (FN-prone).
            # Record the hint but keep reachability unknown.
            self.signals.setdefault(SIG_INVOCATION_ENABLED, None)
            self.signals.setdefault(SIG_INVOCATION_CONFIDENCE, "low")
            if self.fallback_html_signal_key:
                self.signals[self.fallback_html_signal_key] = True
        elif self.set_defaults:
            self.signals.setdefault(SIG_INVOCATION_ENABLED, None)
            self.signals.setdefault(SIG_INVOCATION_CONFIDENCE, "low")

        return {
            "supported": supported,
            "confidence": self.signals.get(SIG_INVOCATION_CONFIDENCE),
            "status_code": status,
            "probe_result": normalized.to_mapping(),
        }


def _user_agent() -> str:
    return get_http_settings().user_agent


def _probe_server_actions_support_ctx(
    base_url: str,
    *,
    action_id: str = "probe",
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    payload_style: str = "plain",
    action_endpoints: list[str] | None = None,
) -> ServerActionsProbeResult:
    if not base_url:
        return ServerActionsProbeResult(
            supported=False,
            confidence="low",
            reason="No base URL provided",
            error_message="No base URL provided",
        )

    request_config = build_request_config(
        action_id_header=action_header,
        base_headers={"User-Agent": _user_agent()},
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

    resp_raw = send_rsc_request(
        target_url,
        request_config,
        payload,
        action_id=action_id,
    )
    resp = _normalize_response(resp_raw)

    headers_lower = normalize_headers(resp.headers or {})
    content_type = headers_lower.get("content-type", "").lower()
    vary = headers_lower.get("vary", "").lower()
    body_text = response_body_text(resp)
    body_lower = body_text.lower()
    status = resp.status_code

    classification = classify_rsc_response(resp)

    action_not_found_header = is_action_not_found_header(headers_lower)
    action_not_found_body = is_action_not_found_body(body_text)
    vary_has_rsc = False
    if vary:
        vary_parts = [part.strip().lower() for part in vary.split(",")]
        vary_has_rsc = any(part == "rsc" for part in vary_parts)
    has_action_keywords = any(keyword in body_lower for keyword in SERVER_ACTIONS_ACTION_KEYWORDS)
    has_strong_action_keywords = any(keyword in body_lower for keyword in SERVER_ACTIONS_STRONG_ACTION_KEYWORDS)
    has_generic_action_keywords = has_action_keywords and not has_strong_action_keywords
    is_html = classification.is_html
    has_flight_marker = classification.looks_like_flight and not is_html
    digest = classification.digest
    has_digest = bool(digest)
    has_rsc_content_type = is_rsc_content_type_header(headers_lower)
    has_json_content_type = content_type.startswith("application/json")

    # `application/json` is common for unrelated APIs and error handlers. Only treat JSON as a strong
    # Server Actions signal when paired with concrete RSC decode evidence (digest/Flight marker) or
    # known Next.js Server Actions error strings.
    json_is_action_response = has_json_content_type and (has_digest or has_flight_marker or has_strong_action_keywords)
    has_action_content_type = has_rsc_content_type or json_is_action_response
    has_framework_html_marker = any(marker in body_lower for marker in FRAMEWORK_HTML_MARKERS)
    has_next_marker = "__next_f" in body_lower or "__next_data__" in body_lower

    react_major_from_flight = infer_react_major_from_flight_text(body_text)
    flight_format = flight_format_from_body(body_text)

    confidence = "none"
    supported = False
    if resp.ok:
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

    has_rsc_format = bool(has_action_content_type or has_flight_marker or has_digest)

    return ServerActionsProbeResult(
        supported=bool(supported),
        confidence=confidence,
        status_code=status,
        content_type=content_type,
        has_rsc_format=has_rsc_format,
        has_action_content_type=has_action_content_type,
        has_action_keywords=has_action_keywords,
        has_flight_marker=has_flight_marker,
        has_digest=has_digest,
        has_framework_html_marker=has_framework_html_marker,
        has_next_marker=has_next_marker,
        is_html=is_html,
        action_not_found_header=action_not_found_header,
        action_not_found_body=action_not_found_body,
        vary_has_rsc=vary_has_rsc,
        flight_format=flight_format,
        react_major_from_flight=react_major_from_flight,
        body_snippet=resp.body_snippet,
        body=resp.text,
        error_message=resp.error_message,
        error_type=resp.error_type,
        payload_style=payload_style,
        ok=resp.ok,
        probe_url=target_url,
    )


def probe_server_actions_support(
    base_url: str,
    *,
    action_id: str = "probe",
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
    payload_style: str = "plain",
    action_endpoints: list[str] | None = None,
) -> ServerActionsProbeResult:
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
) -> ServerActionsProbeResult:
    action_id = generate_action_id()
    request_config = build_request_config(
        action_id_header=action_header,
        base_headers={"User-Agent": _user_agent()},
    )
    payload = build_multipart_form_payload([("0", "[]")], meta={"probe_kind": "server_actions_detect"})

    scan_raw = send_rsc_request(
        url,
        request_config,
        payload,
        action_id=action_id,
    )
    scan = _normalize_response(scan_raw)

    if not scan.ok:
        return ServerActionsProbeResult(
            supported=False,
            confidence="low",
            reason=scan.error_message or "Server Actions probe failed",
            error_message=scan.error_message,
            error_type=scan.error_type,
            ok=scan.ok,
            status_code=scan.status_code,
            probe_url=url,
            payload_style="multipart",
        )

    status_code = scan.status_code or 0
    response_headers = scan.headers or {}
    body_text = response_body_text(scan)
    content_type = header_value(response_headers, "content-type")

    has_rsc_content_type = is_rsc_content_type_header(response_headers)
    has_flight_format = looks_like_flight_payload(body_text)
    has_rsc_error = bool(extract_error_digest(body_text))
    is_html = looks_like_html(response_headers, body_text)

    if status_code in (404, 405):
        return ServerActionsProbeResult(
            supported=False,
            confidence="medium",
            reason=f"Endpoint returned {status_code} - Server Actions not observed on this route",
            status_code=status_code,
            content_type=content_type,
            has_rsc_format=False,
            ok=scan.ok,
            probe_url=url,
            payload_style="multipart",
        )

    if is_html and status_code == 200:
        return ServerActionsProbeResult(
            supported=True,
            confidence="low",
            reason="HTML 200 response to Server Actions probe - possible dev/HTML wrapper on action path",
            status_code=status_code,
            content_type=content_type,
            has_rsc_format=False,
            ok=scan.ok,
            probe_url=url,
            payload_style="multipart",
        )

    if is_html and status_code == 500:
        return ServerActionsProbeResult(
            supported=True,
            confidence="low",
            reason="HTML 500 response to Server Actions probe - possible dev error page on action path",
            status_code=status_code,
            content_type=content_type,
            has_rsc_format=False,
            ok=scan.ok,
            probe_url=url,
            payload_style="multipart",
        )

    if has_rsc_content_type or has_flight_format:
        if status_code == 200:
            return ServerActionsProbeResult(
                supported=True,
                confidence="high",
                reason="RSC Flight response received - Server Actions enabled",
                status_code=status_code,
                content_type=content_type,
                has_rsc_format=True,
                ok=scan.ok,
                probe_url=url,
                payload_style="multipart",
            )
        if status_code == 500 and has_rsc_error:
            return ServerActionsProbeResult(
                supported=True,
                confidence="high",
                reason="RSC error response received - Server Actions enabled (action processing returned 5xx)",
                status_code=status_code,
                content_type=content_type,
                has_rsc_format=True,
                ok=scan.ok,
                probe_url=url,
                payload_style="multipart",
            )
        return ServerActionsProbeResult(
            supported=True,
            confidence="medium",
            reason=f"RSC Flight format detected with status {status_code}",
            status_code=status_code,
            content_type=content_type,
            has_rsc_format=True,
            ok=scan.ok,
            probe_url=url,
            payload_style="multipart",
        )

    if status_code == 500 and not is_html:
        return ServerActionsProbeResult(
            supported=True,
            confidence="low",
            reason="Non-HTML 500 response to Server Actions probe - possible Server Actions processing",
            status_code=status_code,
            content_type=content_type,
            has_rsc_format=False,
            ok=scan.ok,
            probe_url=url,
            payload_style="multipart",
        )

    if status_code in (301, 302, 303, 307, 308):
        return ServerActionsProbeResult(
            supported=False,
            confidence="medium",
            reason=f"Redirect ({status_code}) - Server Actions not observed on this route",
            status_code=status_code,
            content_type=content_type,
            has_rsc_format=False,
            ok=scan.ok,
            probe_url=url,
            payload_style="multipart",
        )

    return ServerActionsProbeResult(
        supported=False,
        confidence="low",
        reason=f"Inconclusive Server Actions probe response (status {status_code})",
        status_code=status_code,
        content_type=content_type,
        has_rsc_format=has_flight_format,
        ok=scan.ok,
        probe_url=url,
        payload_style="multipart",
    )


def detect_server_actions(
    url: str,
    action_header: str = SERVER_ACTIONS_DEFAULT_ACTION_HEADER,
) -> ServerActionsProbeResult:
    return _detect_server_actions_ctx(url, action_header=action_header)


def apply_server_actions_probe_results(
    *,
    base_url: str | None = None,
    probe_result: ServerActionsProbeResult | Mapping[str, Any] | None = None,
    state: DetectionState | None = None,
    tags: TagSet | None = None,
    signals: dict[str, Any] | None = None,
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
    - Prefer ``state``; ``tags/signals`` are legacy shims.
    """
    if state is None:
        if tags is None or signals is None:
            raise ValueError("state is required (or provide legacy tags/signals)")
        state = DetectionState(tags=tags, signals=signals)

    applier = ServerActionsSignalApplier(
        state=state,
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
    "ServerActionsProbeResult",
    "detect_server_actions",
    "generate_action_id",
    "apply_server_actions_probe_results",
    "probe_server_actions_support",
    "SERVER_ACTIONS_RSC_CONTENT_TYPE",
]
