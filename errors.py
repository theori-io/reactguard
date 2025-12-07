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

"""Error taxonomy and exception helpers."""

from enum import Enum
from typing import Optional


class ErrorCategory(str, Enum):
    TIMEOUT = "TIMEOUT"
    WAF_SUSPECTED = "WAF_SUSPECTED"
    SSL_ERROR = "SSL_ERROR"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    DNS_ERROR = "DNS_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    NONE = "NONE"


def categorize_exception(exc: Exception) -> ErrorCategory:
    """
    Map Python/httpx exceptions to ErrorCategory.
    """
    import socket
    import ssl as ssl_module

    try:
        import httpx
    except Exception:  # pragma: no cover - defensive
        httpx = None  # type: ignore

    if httpx and isinstance(exc, httpx.TimeoutException):
        return ErrorCategory.TIMEOUT

    if httpx and isinstance(
        exc, (httpx.ConnectError, httpx.RemoteProtocolError, httpx.NetworkError, httpx.ProxyError)
    ):
        return ErrorCategory.CONNECTION_ERROR

    if isinstance(exc, (ssl_module.SSLError, ssl_module.CertificateError)):
        return ErrorCategory.SSL_ERROR

    if isinstance(exc, (socket.gaierror, socket.herror)):
        return ErrorCategory.DNS_ERROR

    if isinstance(exc, (ConnectionError, ConnectionRefusedError, ConnectionResetError)):
        return ErrorCategory.CONNECTION_ERROR

    if getattr(exc, "response", None) is not None:
        status = getattr(exc.response, "status_code", None)
        if status in (403, 429):
            return ErrorCategory.WAF_SUSPECTED

    return ErrorCategory.UNKNOWN_ERROR


def error_category_to_reason(category: Optional[ErrorCategory]) -> str:
    """User-facing reason string."""
    mapping = {
        ErrorCategory.TIMEOUT: "Network timeout during probe",
        ErrorCategory.WAF_SUSPECTED: "WAF or rate limiting detected",
        ErrorCategory.SSL_ERROR: "TLS/certificate issue",
        ErrorCategory.CONNECTION_ERROR: "Network connectivity issue",
        ErrorCategory.DNS_ERROR: "DNS resolution failure",
        ErrorCategory.UNKNOWN_ERROR: "Network error during probe",
        ErrorCategory.NONE: "",
        None: "",
    }
    return mapping.get(category, "Probe failed due to network error")
