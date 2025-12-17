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

"""Framework detection orchestrator."""

import logging
from typing import Any

from ..http import (
    HttpRequest,
    create_default_http_client,
    get_http_client,
    send_with_retries,
)
from ..http.client import HttpClient
from ..models import FrameworkDetectionResult, ScanRequest
from ..utils import TagSet, extract_versions
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
        if context.http_client is None:
            with scan_context(
                http_client=self.http_client,
                proxy_profile=request.proxy_profile,
                correlation_id=request.correlation_id,
            ):
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
        raw_headers: dict[str, str] = {}
        if request.response_headers:
            raw_headers.update(request.response_headers)
        if response and response.headers:
            # Response headers should take precedence over any offline overrides.
            raw_headers.update(response.headers)
        return {k.lower(): v for k, v in raw_headers.items()}

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
