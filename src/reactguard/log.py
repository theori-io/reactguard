# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Logging helpers for ReactGuard."""

from __future__ import annotations

import logging
import os

DEFAULT_LOG_LEVEL = os.getenv("REACTGUARD_LOG_LEVEL", "WARNING").upper()


def setup_logging(level: str | None = None) -> None:
    """Configure standard logging for CLI/library use."""
    effective_level = (level or DEFAULT_LOG_LEVEL).upper()
    logging.basicConfig(
        level=getattr(logging, effective_level, logging.WARNING),
        format="%(levelname)s %(name)s: %(message)s",
    )


__all__ = ["setup_logging"]
