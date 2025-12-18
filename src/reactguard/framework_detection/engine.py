# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Framework detection orchestrator."""

from __future__ import annotations

import logging
from typing import Any

from ..http import (
    HttpRequest,
    create_default_http_client,
    get_http_client,
    normalize_headers,
    send_with_retries,
)
from ..http.client import HttpClient
from ..models import FrameworkDetectionResult, ScanRequest
from ..utils import TagSet, confidence_score, extract_versions, parse_semver
from ..utils.context import get_scan_context, scan_context
from .base import DetectionContext
from .keys import (
    SIG_DETECTION_CONFIDENCE,
    SIG_DETECTION_CONFIDENCE_BREAKDOWN,
    SIG_DETECTION_CONFIDENCE_LEVEL,
    SIG_DETECTOR_ERRORS,
    SIG_FETCH_ERROR_MESSAGE,
    SIG_FINAL_URL,
    SIG_REACT_BUNDLE,
    SIG_REACT_BUNDLE_ONLY,
    SIG_REACT_SERVER_DOM_BUNDLE,
    SIG_RSC_DEPENDENCY_ONLY,
    SIG_RSC_ENDPOINT_FOUND,
    TAG_RSC,
)
from .registry import DETECTORS
from .scoring import score_confidence

logger = logging.getLogger(__name__)


class FrameworkDetectionEngine:
    """Coordinates framework detectors and produces detection results."""

    def __init__(self, http_client: HttpClient | None = None):
        self.http_client = http_client or create_default_http_client()

    def detect(self, request: ScanRequest) -> FrameworkDetectionResult:
        context = get_scan_context()
        needs_http_client = context.http_client is None
        needs_extra = not isinstance(context.extra, dict)

        if needs_http_client or needs_extra:
            overrides: dict[str, Any] = {}
            if needs_http_client:
                overrides.update(
                    {
                        "http_client": self.http_client,
                        "proxy_profile": request.proxy_profile,
                        "correlation_id": request.correlation_id,
                    }
                )
            if needs_extra:
                overrides["extra"] = {}
            with scan_context(**overrides):
                return self._detect_ctx(request)
        return self._detect_ctx(request)

    def _detect_ctx(self, request: ScanRequest) -> FrameworkDetectionResult:
        response = request.response or self._fetch(request)
        signals = self._initial_signals(response)
        if response and response.url:
            signals[SIG_FINAL_URL] = response.url
        headers = self._normalize_headers(request, response)
        body = self._resolve_body(request, response)
        tags = TagSet()
        context = self._build_context(request, response)

        signals.update(self._collect_version_signals(headers, body))
        self._run_detectors(body, headers, tags, signals, context)
        self._apply_confidence(signals)
        self._apply_rsc_flags(tags, signals)
        self._annotate_react_major_evidence(signals)

        return FrameworkDetectionResult(tags=tags.to_list(), signals=signals)

    def _fetch(self, request: ScanRequest):
        if not request.url:
            return None

        http_request = HttpRequest(
            url=request.url,
            method="GET",
            headers=request.request_headers,
            allow_redirects=True,
        )
        response = send_with_retries(get_http_client(), http_request)

        if not response.ok:
            logger.debug(
                "Initial fetch failed for %s: %s (%s)",
                request.url,
                response.error_message,
                response.error_type,
            )
        return response

    @staticmethod
    def _initial_signals(response) -> dict[str, Any]:
        if response and not response.ok:
            return {
                SIG_FETCH_ERROR_MESSAGE: response.error_message,
            }
        return {}

    @staticmethod
    def _normalize_headers(request: ScanRequest, response) -> dict[str, str]:
        raw_headers: dict[object, object] = {}
        if request.response_headers:
            raw_headers.update(request.response_headers)
        if response and response.headers:
            # Response headers should take precedence over any offline overrides.
            raw_headers.update(response.headers)
        return normalize_headers(raw_headers)

    @staticmethod
    def _resolve_body(request: ScanRequest, response) -> str:
        return request.body or (response.text if response else "") or ""

    def _build_context(self, request: ScanRequest, response) -> DetectionContext:
        return DetectionContext(
            url=(response.url if response and response.url else request.url),
            http_client=get_http_client(),
        )

    @staticmethod
    def _collect_version_signals(headers: dict[str, str], body: str) -> dict[str, Any]:
        signals: dict[str, Any] = {}
        versions = extract_versions(headers, body)
        for key, value in versions.items():
            if value is not None:
                signals[f"detected_{key}"] = value
        return signals

    def _run_detectors(
        self,
        body: str,
        headers: dict[str, str],
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
        for detector in DETECTORS:
            if detector.should_skip(tags):
                continue
            try:
                detector.detect(body, headers, tags, signals, context)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Detector %s failed: %s", detector.name, exc)
                signals.setdefault(SIG_DETECTOR_ERRORS, []).append(detector.name)

    @staticmethod
    def _apply_confidence(signals: dict[str, Any]) -> None:
        confidence_score, confidence_level, breakdown = score_confidence(signals)
        signals[SIG_DETECTION_CONFIDENCE] = confidence_score
        signals[SIG_DETECTION_CONFIDENCE_LEVEL] = confidence_level
        signals[SIG_DETECTION_CONFIDENCE_BREAKDOWN] = breakdown

    @staticmethod
    def _apply_rsc_flags(tags: TagSet, signals: dict[str, Any]) -> None:
        has_react_bundle = signals.get(SIG_REACT_BUNDLE)
        has_rsc_runtime = signals.get(SIG_REACT_SERVER_DOM_BUNDLE)
        has_rsc_endpoint = signals.get(SIG_RSC_ENDPOINT_FOUND) or TAG_RSC in tags
        if has_rsc_runtime and not has_rsc_endpoint:
            signals[SIG_RSC_DEPENDENCY_ONLY] = True
        if has_react_bundle and not has_rsc_endpoint and not has_rsc_runtime:
            signals[SIG_REACT_BUNDLE_ONLY] = True

    @staticmethod
    def _annotate_react_major_evidence(signals: dict[str, Any]) -> None:
        """
        Attach machine-readable evidence for React major inference.

        This makes major selection auditable and enables downstream CVE logic to downgrade
        when evidence sources disagree.
        """
        evidence: list[dict[str, Any]] = []

        def _add_major_evidence(
            *,
            major_key: str,
            source_key: str,
            confidence_key: str,
            default_source: str,
        ) -> None:
            raw = signals.get(major_key)
            if raw is None:
                return
            try:
                major = int(raw)
            except (TypeError, ValueError):
                return
            evidence.append(
                {
                    "major": major,
                    "signal": major_key,
                    "source": str(signals.get(source_key) or default_source),
                    "confidence": str(signals.get(confidence_key) or "none"),
                }
            )

        def _add_version_evidence(
            *,
            version_key: str,
            source_key: str,
            confidence_key: str,
            default_source: str,
        ) -> None:
            version = signals.get(version_key)
            if not version:
                return
            parsed = parse_semver(str(version))
            if not parsed:
                return
            evidence.append(
                {
                    "major": parsed.major,
                    "signal": version_key,
                    "version": str(version),
                    "source": str(signals.get(source_key) or default_source),
                    "confidence": str(signals.get(confidence_key) or "none"),
                }
            )

        # Order: prefer runtime version markers, then explicit React version, then major-only heuristics.
        _add_version_evidence(
            version_key="detected_rsc_runtime_version",
            source_key="detected_rsc_runtime_version_source",
            confidence_key="detected_rsc_runtime_version_confidence",
            default_source="detected_rsc_runtime_version",
        )
        _add_version_evidence(
            version_key="detected_react_version",
            source_key="detected_react_version_source",
            confidence_key="detected_react_version_confidence",
            default_source="detected_react_version",
        )
        _add_major_evidence(
            major_key="detected_react_major",
            source_key="detected_react_major_source",
            confidence_key="detected_react_major_confidence",
            default_source="detected_react_major",
        )

        _add_version_evidence(
            version_key="bundle_rsc_runtime_version",
            source_key="bundle_rsc_runtime_version_source",
            confidence_key="bundle_rsc_runtime_version_confidence",
            default_source="bundle_rsc_runtime_version",
        )
        _add_version_evidence(
            version_key="bundle_react_version",
            source_key="bundle_react_version_source",
            confidence_key="bundle_react_version_confidence",
            default_source="bundle_react_version",
        )
        _add_major_evidence(
            major_key="bundle_react_major",
            source_key="bundle_react_major_source",
            confidence_key="bundle_react_major_confidence",
            default_source="bundle_react_major",
        )

        if not evidence:
            return

        signals["react_major_evidence"] = evidence

        strong_majors = {
            item["major"]
            for item in evidence
            if confidence_score(str(item.get("confidence") or "none")) >= confidence_score("medium")
        }
        if len(strong_majors) > 1:
            signals["react_major_conflict"] = True
            signals["react_major_conflict_confidence"] = "high"
            signals["react_major_conflict_majors"] = sorted(strong_majors)
            return

        all_majors = {item["major"] for item in evidence}
        signals["react_major_conflict"] = len(all_majors) > 1
        signals["react_major_conflict_confidence"] = "low" if signals["react_major_conflict"] else "none"
        if signals["react_major_conflict"]:
            signals["react_major_conflict_majors"] = sorted(all_majors)
