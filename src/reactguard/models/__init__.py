# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dataclass exports for ReactGuard."""

from ..http.models import Headers, HttpRequest, HttpResponse, RetryConfig
from .poc import PocRequest, PocResult, PocStatus
from .probe import ProbeRequest, ProbeResult
from .report import ScanReport, VulnerabilityReport
from .scan import FrameworkDetectionResult, ScanRequest

__all__ = [
    "FrameworkDetectionResult",
    "ScanRequest",
    "ScanReport",
    "VulnerabilityReport",
    "Headers",
    "HttpRequest",
    "HttpResponse",
    "PocRequest",
    "PocResult",
    "PocStatus",
    "ProbeRequest",
    "ProbeResult",
    "RetryConfig",
]
