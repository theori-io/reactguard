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

"""Shared helpers for server action IDs and probe utilities."""

import secrets
from typing import List


def generate_action_id(prefix: str = "40", token_bytes: int = 20) -> str:
    """Generate a random action identifier matching the Next.js/Waku convention."""
    return f"{prefix}{secrets.token_hex(token_bytes)}"


def generate_action_ids(count: int = 3, prefix: str = "40", token_bytes: int = 20) -> List[str]:
    """Generate a list of action identifiers; count is clamped at zero or higher."""
    safe_count = max(0, int(count))
    return [generate_action_id(prefix=prefix, token_bytes=token_bytes) for _ in range(safe_count)]


__all__ = ["generate_action_id", "generate_action_ids"]
