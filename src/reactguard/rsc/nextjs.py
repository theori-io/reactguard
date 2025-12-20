# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Next.js HTML helpers for RSC Flight markers."""

from __future__ import annotations

import re

from ..framework_detection.constants import NEXTJS_NEXT_F_PATTERN

# React 19+ Flight payloads encode the root segment (`0:`) as an object.
# NOTE: Avoid using overly-generic markers like `0:{` for *HTML* detection; prefer escaped/structured
# patterns (e.g. `0:{\\\"`) and/or framework-specific hydration markers to reduce false positives.
NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED = '0:{\\"'
NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT = '0:{"a":"$@'
NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED = '0:{\\"a\\":\\"$@'
# React 18 Flight payloads sometimes wrap the array root segment, e.g.:
#   0:[null,["$","$L1",...]]
NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED = '0:[null,["$"'
NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED_ESCAPED = '0:[null,[\\"$"'
NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML = re.compile(r'^\s*0:\["\$","\$L', re.MULTILINE)
NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED = re.compile(r'^\s*0:\[\\"\\$\\",\\"\$L', re.MULTILINE)
NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE = re.compile(r'^\s*0:"\$L', re.MULTILINE)
NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED = re.compile(r'^\s*0:\\"\\$L', re.MULTILINE)


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
        ((NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED in text) and has_next_f)
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
    "NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML",
    "NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED",
    "NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE",
    "NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED",
    "NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED",
    "NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED_ESCAPED",
    "NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED",
    "NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT",
    "NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED",
    "infer_nextjs_rsc_signals_from_html",
    "infer_react_major_from_nextjs_html",
]
