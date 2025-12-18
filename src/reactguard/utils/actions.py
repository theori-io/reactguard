# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared helpers for server action IDs and probe utilities."""

import secrets


def generate_action_id(prefix: str = "40", token_bytes: int = 20) -> str:
    """Generate a random action identifier matching the Next.js/Waku convention."""
    return f"{prefix}{secrets.token_hex(token_bytes)}"


def generate_action_ids(count: int = 3, prefix: str = "40", token_bytes: int = 20) -> list[str]:
    """Generate a list of action identifiers; count is clamped at zero or higher."""
    safe_count = max(0, int(count))
    return [generate_action_id(prefix=prefix, token_bytes=token_bytes) for _ in range(safe_count)]


__all__ = ["generate_action_id", "generate_action_ids"]
