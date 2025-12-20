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
    DetectedVersion,
    ParsedVersion,
    compare_semver,
    derive_react_major,
    extract_versions,
    flatten_version_map,
    is_next_version_vulnerable,
    is_react_version_vulnerable,
    merge_version_maps,
    normalize_version_map,
    parse_semver,
    version_values,
    version_map_from_signals,
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
    "DetectedVersion",
    "ParsedVersion",
    "compare_semver",
    "derive_react_major",
    "extract_versions",
    "flatten_version_map",
    "is_next_version_vulnerable",
    "is_react_version_vulnerable",
    "merge_version_maps",
    "normalize_version_map",
    "parse_semver",
    "version_values",
    "version_map_from_signals",
    "waku_version_implies_react_major",
]
