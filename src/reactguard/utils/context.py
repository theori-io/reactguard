from __future__ import annotations

"""
Per-scan ambient context.

This module provides a ContextVar-backed ScanContext that carries common scan
plumbing (proxy profile, correlation id, timeout, http client). Helpers can
read from this context when explicit arguments are omitted.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any

from ..http.client import HttpClient


@dataclass(frozen=True)
class ScanContext:
    proxy_profile: str | None = None
    correlation_id: str | None = None
    timeout: float | None = None
    http_client: HttpClient | None = None
    extra: dict[str, Any] | None = None


_current_scan_context: ContextVar[ScanContext | None] = ContextVar("reactguard_scan_context", default=None)


def get_scan_context() -> ScanContext:
    """Return the current ambient scan context."""
    return _current_scan_context.get() or ScanContext()


@contextmanager
def scan_context(**overrides: Any) -> Iterator[ScanContext]:
    """
    Context manager that layers overrides onto the ambient ScanContext.

    None-valued overrides are ignored to preserve outer context values.
    """
    current = get_scan_context()
    filtered = {key: value for key, value in overrides.items() if value is not None}
    new_context = replace(current, **filtered) if filtered else current
    token = _current_scan_context.set(new_context)
    try:
        yield new_context
    finally:
        _current_scan_context.reset(token)


__all__ = ["ScanContext", "get_scan_context", "scan_context"]
