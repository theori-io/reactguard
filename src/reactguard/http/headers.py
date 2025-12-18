# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Header normalization utilities.

HTTP header field names are case-insensitive (RFC 9110). ReactGuard stores headers as plain
dicts in many internal result mappings, so we normalize and read them defensively to avoid
flaky detection across differing client/server stacks.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _coerce_headers_mapping(headers: Any) -> Mapping[object, object] | None:
    """
    Best-effort coercion of "dict-like" header containers into a Mapping.

    This keeps header handling robust across different HttpClient implementations which may use:
    - plain dicts
    - httpx.Headers
    - email.message.Message / HTTPMessage-like types (support `.items()`)
    - iterable-of-pairs (e.g. list[tuple[str, str]])
    """
    if not headers:
        return None
    if isinstance(headers, Mapping):
        return headers

    items = getattr(headers, "items", None)
    if callable(items):
        try:
            return dict(items())
        except Exception:
            pass

    try:
        return dict(headers)
    except Exception:
        return None


def normalize_headers(headers: Mapping[object, object] | None) -> dict[str, str]:
    """Return a lowercase-keyed copy of a header mapping."""
    coerced = _coerce_headers_mapping(headers)
    if not coerced:
        return {}
    out: dict[str, str] = {}
    for key, value in coerced.items():
        if key is None:
            continue
        name = str(key).strip().lower()
        if not name:
            continue
        out[name] = "" if value is None else str(value)
    return out


def header_value(headers: Mapping[object, object] | None, name: str, default: str = "") -> str:
    """
    Return a header value using case-insensitive key matching.

    Fast-paths common key casings before falling back to a full scan.
    """
    if not headers or not name:
        return default

    coerced = _coerce_headers_mapping(headers)
    if not coerced:
        return default

    lower = str(name).lower()
    for key in (name, lower, lower.title()):
        try:
            if key in coerced:
                value = coerced.get(key)
                return default if value is None else str(value).strip()
        except Exception:
            # Some Mapping implementations may raise for non-string keys; fall back to scan.
            break

    for key, value in coerced.items():
        if key is None:
            continue
        if str(key).lower() == lower:
            return default if value is None else str(value).strip()

    return default


__all__ = ["header_value", "normalize_headers"]
