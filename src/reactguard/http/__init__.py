# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP client exports."""

from .adapters import StubHttpClient, WorkerHttpClientAdapter
from .client import HttpClient, create_default_http_client
from .headers import header_value, normalize_headers
from .httpx_client import HttpxClient
from .models import Headers, HttpRequest, HttpResponse, RetryConfig
from .retry import build_default_retry_config, send_with_retries
from .utils import (
    DEFAULT_USER_AGENT,
    get_http_client,
    request_with_retries,
    scan_with_retry,
)

__all__ = [
    "DEFAULT_USER_AGENT",
    "Headers",
    "HttpClient",
    "HttpxClient",
    "HttpRequest",
    "HttpResponse",
    "RetryConfig",
    "StubHttpClient",
    "WorkerHttpClientAdapter",
    "header_value",
    "normalize_headers",
    "build_default_retry_config",
    "create_default_http_client",
    "get_http_client",
    "request_with_retries",
    "scan_with_retry",
    "send_with_retries",
]
