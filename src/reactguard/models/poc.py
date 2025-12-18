# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""PoC domain models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .scan import FrameworkDetectionResult


class PocStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    LIKELY_NOT_VULNERABLE = "LIKELY_NOT_VULNERABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class PocRequest:
    url: str
    detection: FrameworkDetectionResult | None = None
    proxy_profile: str | None = None
    correlation_id: str | None = None


@dataclass
class PocResult:
    status: PocStatus
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)
