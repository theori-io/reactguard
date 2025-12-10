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

"""Centralized version thresholds for vulnerability checks."""

# React: explicit vulnerable releases in RSC packages.
REACT_VULNERABLE_VERSIONS = {
    (19, 0, 0),
    (19, 1, 0),
    (19, 1, 1),
    (19, 2, 0),
}

# React: first fixed releases per minor.
REACT_FIXED_VERSIONS = {
    (19, 0, 1),
    (19, 1, 2),
    (19, 2, 1),
}

# Next.js stable patch thresholds per minor (patches at or above these are safe).
NEXT_PATCHED_PATCH_BY_MINOR = {
    15: {0: 5, 1: 9, 2: 6, 3: 6, 4: 8, 5: 7},
    16: {0: 7},
}

# Next.js canary patch thresholds (minor -> minimum canary build that is safe).
NEXT_CANARY_SAFE_BUILD = {
    (14, 3): 76,  # 14.3.0-canary.76 and below safe; 77+ vulnerable
    (15, 6): 58,  # 15.6.0-canary.58 fixed
    (16, 1): 12,  # 16.1.0-canary.12 fixed
}

__all__ = [
    "REACT_VULNERABLE_VERSIONS",
    "REACT_FIXED_VERSIONS",
    "NEXT_PATCHED_PATCH_BY_MINOR",
    "NEXT_CANARY_SAFE_BUILD",
]
