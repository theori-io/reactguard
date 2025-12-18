# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Utility exports."""

from .actions import generate_action_id, generate_action_ids
from .confidence import (
    confidence_at_least,
    confidence_label,
    confidence_score,
    lower_confidence,
    raise_confidence,
)
from .tag_manager import TagSet
from .version import (
    ParsedVersion,
    compare_semver,
    extract_versions,
    is_next_version_vulnerable,
    is_react_version_vulnerable,
    parse_semver,
    waku_version_implies_react_major,
)

__all__ = [
    "generate_action_id",
    "generate_action_ids",
    "confidence_at_least",
    "confidence_label",
    "confidence_score",
    "lower_confidence",
    "raise_confidence",
    "TagSet",
    "ParsedVersion",
    "compare_semver",
    "extract_versions",
    "is_next_version_vulnerable",
    "is_react_version_vulnerable",
    "parse_semver",
    "waku_version_implies_react_major",
]
