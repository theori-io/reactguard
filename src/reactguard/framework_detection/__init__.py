# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Framework detection engine exports."""

from .engine import FrameworkDetectionEngine
from .registry import DETECTORS

__all__ = ["FrameworkDetectionEngine", "DETECTORS"]
