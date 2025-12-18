# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Shared React-major inference and conflict handling helpers.

Multiple subsystems (framework detection, server-action probing, multi-action interpreters)
need to:
- infer the React major from Flight payload shapes when explicit versions are absent
- reconcile multiple evidence sources and avoid overconfident gating
"""

from __future__ import annotations

import re

from .confidence import confidence_score, lower_confidence
from .version import parse_semver

_FLIGHT_DOC_START_RE = re.compile(r"^\d+:")
_FLIGHT_ROOT_OBJECT_RE = re.compile(r"^\s*0:\{", re.MULTILINE)
_FLIGHT_ROOT_ARRAY_RE = re.compile(r"^\s*0:\[", re.MULTILINE)
_FLIGHT_ROOT_LREF_RE = re.compile(r'^\s*0:"\$L', re.MULTILINE)


def react_major_source_priority(source: str | None) -> int:
    """
    Rank evidence sources for React major selection.

    Prefer server-side/runtime evidence over client bundle strings when confidence ties.
    """
    text = str(source or "").lower()
    if any(token in text for token in ("header", "rsc_flight", "rsc_runtime_package", "core_package")):
        return 40
    if text.startswith("flight:"):
        return 30
    if text.startswith("bundle:") or "bundle_assign" in text:
        return 10
    if "plain_text" in text:
        return 5
    return 0


def infer_react_major_from_flight_text(body: str) -> int | None:
    """
    Best-effort React major inference from RSC Flight payload shapes.

    Observed patterns:
    - React 19+ commonly encodes the root `0:` segment as an object (`0:{...}`).
    - React 18 commonly encodes the root `0:` segment as an array (`0:[...]`) or a `$L` string.
    """
    if not body:
        return None

    text = str(body)
    stripped = text.lstrip()

    # This helper is meant for *Flight payloads*, not arbitrary HTML pages. Require the document
    # to start with a Flight-style row (`<id>:`) to avoid false positives from inline JS like
    # `var x = {0:{...}}` in HTML responses.
    if not _FLIGHT_DOC_START_RE.match(stripped):
        return None

    # React 19: object-root Flight payloads.
    if (
        _FLIGHT_ROOT_OBJECT_RE.search(text) is not None
        or '"a":"$@' in text
        or '"a":"$' in text
    ):
        return 19

    # React 18: array-root (or `$L` root) Flight payloads.
    if (
        _FLIGHT_ROOT_ARRAY_RE.search(text) is not None
        or _FLIGHT_ROOT_LREF_RE.search(text) is not None
    ):
        return 18

    return None


def react19_possible(
    *,
    react_major: int | None,
    react_major_confidence: str | None = None,
    react_version: str | None = None,
    react_major_conflict: bool | None = None,
    react_major_conflict_majors: list[int] | None = None,
) -> bool:
    """
    Return True when there is credible evidence that React 19 may be in play.

    Used to avoid hard NOT_APPLICABLE gating on a single major value when evidence sources
    disagree (mixed deployments, cached HTML, noisy bundles, etc.).
    """
    if react_major == 19:
        return True

    # A non-19 major with anything less than "high" confidence is insufficient to rule out React 19.
    if react_major is not None and react_major != 19 and confidence_score(react_major_confidence) < confidence_score("high"):
        return True

    parsed = parse_semver(str(react_version)) if react_version else None
    if parsed and parsed.major == 19:
        return True

    if react_major_conflict and react_major_conflict_majors:
        return 19 in set(react_major_conflict_majors)

    return False


def apply_react_major_conflict_penalty(
    confidence: str,
    *,
    react_major_conflict: bool | None,
    react_major_conflict_confidence: str | None,
) -> str:
    """
    Down-weight a confidence label when React major evidence conflicts.

    This avoids turning disagreements into hard INCONCLUSIVE verdicts while still reflecting
    uncertainty in the final confidence label.
    """
    if not react_major_conflict:
        return confidence

    # Don't penalize below "low" for this adjustment alone.
    if confidence_score(confidence) <= confidence_score("low"):
        return confidence

    conflict_score = confidence_score(react_major_conflict_confidence)
    penalty_steps = 2 if conflict_score >= confidence_score("high") else 1
    adjusted = confidence
    for _ in range(penalty_steps):
        if confidence_score(adjusted) <= confidence_score("low"):
            break
        adjusted = lower_confidence(adjusted)
    return adjusted


__all__ = [
    "apply_react_major_conflict_penalty",
    "infer_react_major_from_flight_text",
    "react19_possible",
    "react_major_source_priority",
]
