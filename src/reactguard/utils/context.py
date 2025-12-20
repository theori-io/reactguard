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
from urllib.parse import urlsplit, urlunsplit

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
_SCAN_TARGETS_KEY = "_reactguard_scan_targets"
_CACHE_KEY = "reactguard_cache"
_LEGACY_CACHE_KEYS = {
    "rsc_server_functions_surface_missing",
    "rsc_surface_resolver_cache",
    "rsc_dec2025_probe_cache",
    "js_bundle_probe_cache",
}


def get_scan_context() -> ScanContext:
    """Return the current ambient scan context."""
    return _current_scan_context.get() or ScanContext()


def get_http_settings() -> HttpSettings:
    """Return HttpSettings from context, falling back to loading defaults."""
    context = get_scan_context()
    if context.http_settings is not None:
        return context.http_settings
    return load_http_settings()


def _normalize_scan_target(target_url: str | None) -> str:
    raw = str(target_url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except Exception:
        return raw
    if not parts.scheme or not parts.netloc:
        return raw
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or ""
    if path.endswith("/") and path != "/":
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _get_scan_targets(extra: dict[str, Any]) -> list[str]:
    raw = extra.get(_SCAN_TARGETS_KEY)
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    if isinstance(raw, set):
        return [str(item) for item in raw if item]
    return []


def _set_scan_targets(extra: dict[str, Any], targets: list[str]) -> None:
    extra[_SCAN_TARGETS_KEY] = targets


def _clear_scan_caches(extra: dict[str, Any]) -> None:
    extra.pop(_SCAN_TARGETS_KEY, None)
    extra.pop(_CACHE_KEY, None)
    for key in _LEGACY_CACHE_KEYS:
        extra.pop(key, None)


def ensure_scan_extra(
    target_url: str | None,
    *,
    extra: dict[str, Any] | None = None,
    reset: bool = False,
) -> tuple[dict[str, Any], bool]:
    """
    Ensure ScanContext.extra is safe for a new target.

    - When reset=True, always clear ReactGuard caches for a fresh scan.
    - Otherwise, clear caches only if the target does not match the current scan target set.
    Returns (extra, needs_override) where needs_override indicates a new dict was created.
    """
    needs_override = not isinstance(extra, dict)
    extra_dict: dict[str, Any] = extra if isinstance(extra, dict) else {}

    target_norm = _normalize_scan_target(target_url)
    targets = _get_scan_targets(extra_dict)

    if reset or not targets or (target_norm and target_norm not in targets):
        _clear_scan_caches(extra_dict)
        targets = [target_norm] if target_norm else []

    _set_scan_targets(extra_dict, targets)
    if _CACHE_KEY not in extra_dict:
        extra_dict[_CACHE_KEY] = {}

    return extra_dict, needs_override


def register_scan_target(target_url: str | None, *, extra: dict[str, Any] | None = None) -> None:
    """Register an additional URL as part of the current scan target set (e.g., final redirect URL)."""
    if extra is None:
        extra = get_scan_context().extra if isinstance(get_scan_context().extra, dict) else None
    if not isinstance(extra, dict):
        return
    target_norm = _normalize_scan_target(target_url)
    if not target_norm:
        return
    targets = _get_scan_targets(extra)
    if target_norm not in targets:
        targets.append(target_norm)
        _set_scan_targets(extra, targets)


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

    cache = extra.get(_CACHE_KEY)
    if not isinstance(cache, dict):
        cache = {}
        extra[_CACHE_KEY] = cache

    namespace_key = str(namespace or "default")
    bucket = cache.get(namespace_key)
    if not isinstance(bucket, dict):
        bucket = {}
        cache[namespace_key] = bucket
    return bucket


__all__ = [
    "ScanContext",
    "ensure_scan_extra",
    "get_http_settings",
    "get_scan_context",
    "register_scan_target",
    "scan_cache",
    "scan_context",
]
