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

"""Tag management utilities."""

from typing import Callable, Iterator, List, Set


class TagSet:
    """Ordered, deduplicated tag collection."""

    def __init__(self):
        self._tags: List[str] = []
        self._seen: Set[str] = set()

    def add(self, tag: str) -> bool:
        if tag not in self._seen:
            self._seen.add(tag)
            self._tags.append(tag)
            return True
        return False

    def add_many(self, *tags: str) -> int:
        count = 0
        for tag in tags:
            if self.add(tag):
                count += 1
        return count

    def remove(self, tag: str) -> bool:
        if tag in self._seen:
            self._seen.remove(tag)
            self._tags.remove(tag)
            return True
        return False

    def remove_if(self, predicate: Callable[[str], bool]) -> int:
        to_remove = [t for t in self._tags if predicate(t)]
        for tag in to_remove:
            self._seen.remove(tag)
            self._tags.remove(tag)
        return len(to_remove)

    def contains(self, tag: str) -> bool:
        return tag in self._seen

    def __contains__(self, tag: str) -> bool:
        return self.contains(tag)

    def __iter__(self) -> Iterator[str]:
        return iter(self._tags)

    def __len__(self) -> int:
        return len(self._tags)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"TagSet({self._tags!r})"

    def to_list(self) -> List[str]:
        return list(self._tags)

    def clear(self) -> None:
        self._tags.clear()
        self._seen.clear()
