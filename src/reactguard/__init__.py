# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
ReactGuard package entrypoint.

This package provides framework detection and vulnerability detection engines
used to assess React Server Components (RSC) implementations for CVE-2025-55182.
HTTP behavior is abstracted behind an injectable client interface, and domain
objects are modeled with typed dataclasses for clarity.
"""

from .config import HttpSettings, load_http_settings
from .framework_detection import FrameworkDetectionEngine
from .http import (
    HttpClient,
    HttpRequest,
    HttpResponse,
    HttpxClient,
    RetryConfig,
    create_default_http_client,
)
from .log import setup_logging
from .models import ScanReport, VulnerabilityReport
from .models.poc import PocStatus
from .runtime import ReactGuard
from .scan import ScanEngine
from .version import __version__
from .vulnerability_detection import (
    CVE202555182VulnerabilityDetector,
    PocPlugin,
    VulnerabilityDetectionEngine,
)

__all__ = [
    "CVE202555182VulnerabilityDetector",
    "FrameworkDetectionEngine",
    "HttpClient",
    "HttpRequest",
    "HttpResponse",
    "HttpSettings",
    "HttpxClient",
    "PocPlugin",
    "PocStatus",
    "ScanReport",
    "ScanEngine",
    "VulnerabilityDetectionEngine",
    "VulnerabilityReport",
    "RetryConfig",
    "ReactGuard",
    "create_default_http_client",
    "load_http_settings",
    "setup_logging",
    "__version__",
]
