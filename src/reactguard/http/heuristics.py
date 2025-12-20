# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Heuristics for interpreting HTTP responses."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .headers import header_value
from .models import HttpResponse


def looks_like_html(headers: Mapping[object, object] | None, body: str | None) -> bool:
    """
    Return True when a response likely contains HTML.

    Uses both content-type and body sniffing to preserve existing detection heuristics.
    """
    content_type = header_value(headers, "content-type").lower()
    if "text/html" in content_type:
        return True

    text = str(body or "").lstrip()
    lowered = text[:256].lower()
    return lowered.startswith("<!doctype") or lowered.startswith("<html") or "<html" in lowered


def response_looks_like_html(result: Mapping[str, Any] | HttpResponse | None) -> bool:
    """Convenience wrapper for result mappings or HttpResponse instances."""
    if not result:
        return False
    if isinstance(result, HttpResponse):
        headers = result.headers
        body = result.text or result.body_snippet
    else:
        headers = result.get("headers")
        body = result.get("body") or result.get("body_snippet")
    return looks_like_html(headers, body)


__all__ = ["looks_like_html", "response_looks_like_html"]
