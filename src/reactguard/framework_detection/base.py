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

"""Detection base classes and context."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..http import HttpClient
from ..utils import TagSet


@dataclass
class DetectionContext:
    url: str | None
    proxy_profile: str | None
    correlation_id: str | None
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
