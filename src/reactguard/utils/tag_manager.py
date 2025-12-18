# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tag management utilities."""

from collections.abc import Callable, Iterator


class TagSet:
    """Ordered, deduplicated tag collection."""

    def __init__(self):
        self._tags: list[str] = []
        self._seen: set[str] = set()

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

    def to_list(self) -> list[str]:
        return list(self._tags)

    def clear(self) -> None:
        self._tags.clear()
        self._seen.clear()
