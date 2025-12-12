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
    send_with_retries,
)
from ..http.client import HttpClient
from ..models import FrameworkDetectionResult, ScanRequest
from ..utils import TagSet, extract_versions
from .base import DetectionContext
from .registry import DETECTORS
from .scoring import score_confidence

logger = logging.getLogger(__name__)


class FrameworkDetectionEngine:
    """Coordinates framework detectors and produces detection results."""

    def __init__(self, http_client: HttpClient | None = None):
        self.http_client = http_client or create_default_http_client()

    def detect(self, request: ScanRequest) -> FrameworkDetectionResult:
        response = request.response or self._fetch(request)
        signals = self._initial_signals(response)
        if response and response.url:
            signals["final_url"] = response.url
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
            proxy=request.proxy_profile,
            correlation_id=request.correlation_id,
        )
        response = send_with_retries(self.http_client, http_request)

        if not response.ok:
            logger.debug(
                "Initial fetch failed for %s: %s (%s)",
                request.url,
                response.error_message,
                response.error_category,
            )
        return response

    @staticmethod
    def _initial_signals(response) -> dict[str, Any]:
        if response and not response.ok:
            return {
                "fetch_error_category": response.error_category,
                "fetch_error_message": response.error_message,
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
            url=request.url or (response.url if response else None),
            proxy_profile=request.proxy_profile,
            correlation_id=request.correlation_id,
            http_client=self.http_client,
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
                signals.setdefault("detector_errors", []).append(detector.name)

    @staticmethod
    def _apply_confidence(signals: dict[str, Any]) -> None:
        confidence_score, confidence_level, breakdown = score_confidence(signals)
        signals["detection_confidence"] = confidence_score
        signals["detection_confidence_level"] = confidence_level
        signals["detection_confidence_breakdown"] = breakdown

    @staticmethod
    def _apply_rsc_flags(tags: TagSet, signals: dict[str, Any]) -> None:
        has_rsc_library = signals.get("react_bundle")
        has_rsc_endpoint = signals.get("rsc_endpoint_found") or "rsc" in tags
        if has_rsc_library and not has_rsc_endpoint:
            signals["rsc_dependency_only"] = True
