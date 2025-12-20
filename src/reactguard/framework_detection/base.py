# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Detection base classes and context."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..http import HttpClient
from ..utils import TagSet


@dataclass
class DetectionContext:
    url: str | None
    http_client: HttpClient


@dataclass
class DetectionState:
    """Shared detection state for tags + signals."""

    tags: TagSet
    signals: dict[str, Any]

    def add_tag(self, tag: str) -> bool:
        return self.tags.add(tag)


class FrameworkDetector(ABC):
    name: str = "base"
    produces_tags: list[str] = []
    priority: int = 50

    @abstractmethod
    def detect(
        self,
        body: str,
        headers: dict[str, str],
        state: DetectionState,
        context: DetectionContext,
    ) -> None: ...

    def should_skip(self, state: DetectionState) -> bool:
        return False

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"{self.__class__.__name__}(priority={self.priority})"
