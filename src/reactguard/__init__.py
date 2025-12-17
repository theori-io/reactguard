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
