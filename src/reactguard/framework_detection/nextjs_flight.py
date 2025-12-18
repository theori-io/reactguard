# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Next.js HTML helpers for RSC Flight markers."""

from __future__ import annotations

from .constants import (
    NEXTJS_NEXT_F_PATTERN,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED,
)


def infer_nextjs_rsc_signals_from_html(body: str) -> tuple[bool, int | None]:
    """
    Infer whether a Next.js HTML page likely contains RSC Flight data and, if so, the React major.

    This is intentionally conservative and uses Next.js-specific hydration markers and Flight root patterns
    (escaped or structured) to reduce false positives from arbitrary HTML/JS.
    """
    if not body:
        return False, None

    text = str(body)
    has_next_f = bool(NEXTJS_NEXT_F_PATTERN.search(text))

    has_v19_flight_hint = (
        NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED in text
        or NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT in text
        or NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED in text
    )
    has_v18_flight_hint = (
        NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED in text
        or NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED_ESCAPED in text
        or NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML.search(text) is not None
        or NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED.search(text) is not None
        or NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE.search(text) is not None
        or NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED.search(text) is not None
    )

    is_rsc_framework = has_next_f or has_v19_flight_hint or has_v18_flight_hint
    react_major = 19 if has_v19_flight_hint else 18 if has_v18_flight_hint else None
    return is_rsc_framework, react_major


def infer_react_major_from_nextjs_html(body: str) -> int | None:
    """Convenience wrapper over `infer_nextjs_rsc_signals_from_html`."""
    _is_rsc, major = infer_nextjs_rsc_signals_from_html(body)
    return major


__all__ = [
    "infer_nextjs_rsc_signals_from_html",
    "infer_react_major_from_nextjs_html",
]
