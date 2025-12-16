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

"""HTTP client exports."""

from .adapters import StubHttpClient, WorkerHttpClientAdapter
from .client import HttpClient, create_default_http_client
from .httpx_client import HttpxClient
from .models import Headers, HttpRequest, HttpResponse, RetryConfig
from .retry import build_default_retry_config, send_with_retries
from .utils import (
    DEFAULT_USER_AGENT,
    ErrorCategory,
    get_http_client,
    request_with_retries,
    scan_with_retry,
    set_shared_http_client,
)

__all__ = [
    "DEFAULT_USER_AGENT",
    "ErrorCategory",
    "Headers",
    "HttpClient",
    "HttpxClient",
    "HttpRequest",
    "HttpResponse",
    "RetryConfig",
    "StubHttpClient",
    "WorkerHttpClientAdapter",
    "build_default_retry_config",
    "create_default_http_client",
    "get_http_client",
    "request_with_retries",
    "scan_with_retry",
    "send_with_retries",
    "set_shared_http_client",
]
