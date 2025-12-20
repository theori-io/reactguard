# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Per-scan ambient context.

This module provides a ContextVar-backed ScanContext that carries common scan
plumbing (timeout, http client). Helpers can
read from this context when explicit arguments are omitted.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any

from ..config import HttpSettings, load_http_settings
from ..http.client import HttpClient


@dataclass(frozen=True)
class ScanContext:
    timeout: float | None = None
    http_client: HttpClient | None = None
    http_settings: HttpSettings | None = None
    extra: dict[str, Any] | None = None
    proxy_profile: str | None = None
    correlation_id: str | None = None


_current_scan_context: ContextVar[ScanContext | None] = ContextVar("reactguard_scan_context", default=None)


def get_scan_context() -> ScanContext:
    """Return the current ambient scan context."""
    return _current_scan_context.get() or ScanContext()


def get_http_settings() -> HttpSettings:
    """Return HttpSettings from context, falling back to loading defaults."""
    context = get_scan_context()
    if context.http_settings is not None:
        return context.http_settings
    return load_http_settings()


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

def scan_cache(namespace: str, *, legacy_key: str | None = None) -> dict[str, Any]:
    """
    Return a namespaced cache dict stored on ScanContext.extra.

    If legacy_key is provided and present, that dict is returned to preserve
    backward-compatible cache locations.
    """
    context = get_scan_context()
    extra = context.extra
    if not isinstance(extra, dict):
        return {}

    if legacy_key:
        legacy = extra.get(legacy_key)
        if isinstance(legacy, dict):
            return legacy

    cache = extra.get("reactguard_cache")
    if not isinstance(cache, dict):
        cache = {}
        extra["reactguard_cache"] = cache

    namespace_key = str(namespace or "default")
    bucket = cache.get(namespace_key)
    if not isinstance(bucket, dict):
        bucket = {}
        cache[namespace_key] = bucket
    return bucket


__all__ = ["ScanContext", "get_http_settings", "get_scan_context", "scan_cache", "scan_context"]
