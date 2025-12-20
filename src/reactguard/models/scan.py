# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Scan request/result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..framework_detection.keys import SIG_DETECTION_CONFIDENCE, SIG_DETECTION_CONFIDENCE_LEVEL
from ..http.models import HttpResponse


@dataclass
class ScanRequest:
    """
    Represents a scan request spanning framework detection plus vulnerability detection.

    Either `url` or a pre-fetched `response` must be supplied.

    - `request_headers` are sent with outbound HTTP requests.
    - `response_headers` are optional headers to use for detection when a response
      object is not available (offline/fixture scans).
    - `headers` is a deprecated alias for `response_headers`, kept for backwards compatibility.
    """

    url: str | None = None
    response: HttpResponse | None = None
    body: str | None = None
    request_headers: dict[str, str] | None = None
    response_headers: dict[str, str] | None = None
    headers: dict[str, str] | None = None
    proxy_profile: str | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        # Backwards-compatible mapping for legacy callers that still pass `headers=`.
        if self.headers and self.request_headers is None and self.response_headers is None:
            self.response_headers = dict(self.headers)


@dataclass
class FrameworkDetectionResult:
    """Normalized framework detection result."""

    tags: list[str]
    signals: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        return float(self.signals.get(SIG_DETECTION_CONFIDENCE, 0.0))

    @property
    def confidence_level(self) -> str:
        return str(self.signals.get(SIG_DETECTION_CONFIDENCE_LEVEL, "unknown"))
