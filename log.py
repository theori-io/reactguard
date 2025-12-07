from __future__ import annotations

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

"""Logging helpers for ReactGuard."""

import logging
import os
from typing import Optional

DEFAULT_LOG_LEVEL = os.getenv("REACTGUARD_LOG_LEVEL", "WARNING").upper()


def setup_logging(level: Optional[str] = None) -> None:
    """Configure standard logging for CLI/library use."""
    effective_level = (level or DEFAULT_LOG_LEVEL).upper()
    logging.basicConfig(
        level=getattr(logging, effective_level, logging.WARNING),
        format="%(levelname)s %(name)s: %(message)s",
    )


__all__ = ["setup_logging"]
