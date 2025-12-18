# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Confidence-label utilities shared across detection + vulnerability workflows.

ReactGuard uses a small, ordered set of confidence labels across multiple subsystems
(version extraction, framework detection, vulnerability interpretation). This module
centralizes the ordering and helpers to avoid drift.
"""

from __future__ import annotations

from typing import Final

CONFIDENCE_ORDER: Final[dict[str, int]] = {"none": 0, "low": 1, "medium": 2, "high": 3}
_CONFIDENCE_STEPS: Final[tuple[str, ...]] = ("none", "low", "medium", "high")


def confidence_score(confidence: str | None) -> int:
    """Return a numeric score for a confidence label."""
    return CONFIDENCE_ORDER.get(str(confidence or "").lower(), 0)


def confidence_label(score: int) -> str:
    """Map a numeric score back into a confidence label."""
    if score >= CONFIDENCE_ORDER["high"]:
        return "high"
    if score >= CONFIDENCE_ORDER["medium"]:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def confidence_at_least(confidence: str | None, threshold: str) -> bool:
    """Return True when ``confidence`` is >= ``threshold``."""
    return confidence_score(confidence) >= confidence_score(threshold)


def raise_confidence(confidence: str | None) -> str:
    """Increment confidence label by one step, capping at high."""
    current = str(confidence or "none").lower()
    try:
        idx = _CONFIDENCE_STEPS.index(current)
    except ValueError:
        idx = 0
    return _CONFIDENCE_STEPS[min(idx + 1, len(_CONFIDENCE_STEPS) - 1)]


def lower_confidence(confidence: str | None) -> str:
    """Decrement confidence label by one step, bottoming out at none."""
    current = str(confidence or "none").lower()
    try:
        idx = _CONFIDENCE_STEPS.index(current)
    except ValueError:
        idx = 0
    return _CONFIDENCE_STEPS[max(idx - 1, 0)]


__all__ = [
    "CONFIDENCE_ORDER",
    "confidence_at_least",
    "confidence_label",
    "confidence_score",
    "lower_confidence",
    "raise_confidence",
]
