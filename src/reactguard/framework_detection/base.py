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


class FrameworkDetector(ABC):
    name: str = "base"
    produces_tags: list[str] = []
    priority: int = 50

    @abstractmethod
    def detect(
        self,
        body: str,
        headers: dict[str, str],
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None: ...

    def should_skip(self, tags: TagSet) -> bool:
        return False

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"{self.__class__.__name__}(priority={self.priority})"
