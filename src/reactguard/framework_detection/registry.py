# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Framework fingerprinter registry."""

from .detectors import (
    ExpoDetector,
    GenericRSCDetector,
    NextJSDetector,
    ReactRouterDetector,
    SPADetector,
    WakuDetector,
)

DETECTORS = sorted(
    [
        NextJSDetector(),
        WakuDetector(),
        ExpoDetector(),
        ReactRouterDetector(),
        GenericRSCDetector(),
        SPADetector(),
    ],
    key=lambda detector: detector.priority,
)

__all__ = ["DETECTORS"]
