"""
ReactGuard, framework- and vulnerability-detection tooling for CVE-2025-55182 (React2Shell).
Copyright (C) 2025  Theori Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Utility exports."""

from .actions import generate_action_id, generate_action_ids
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
    "TagSet",
    "ParsedVersion",
    "compare_semver",
    "extract_versions",
    "is_next_version_vulnerable",
    "is_react_version_vulnerable",
    "parse_semver",
    "waku_version_implies_react_major",
]
