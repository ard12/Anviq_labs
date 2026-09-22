"""Trivially-correct, O(n) reference model used only by the property test
(test_property.py) to check `LRUTTLCache` against random operation sequences.

Deliberately dumb: a plain list, linear scans, no cleverness. If this and the O(1)
cache ever disagree on a sequence of operations, the O(1) cache has a bug -- that
disagreement is the strongest evidence of correctness in this submission, because
it isn't hand-picked by whoever wrote the O(1) code.
"""

from __future__ import annotations

from collections.abc import Callable

_USE_DEFAULT = object()
MISS = object()


class ReferenceLRUTTLCache[K, V]:
    def __init__(self, capacity: int, default_ttl: float | None, clock: Callable[[], float]) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        if default_ttl is not None and default_ttl <= 0:
            raise ValueError(f"default_ttl must be > 0 or None, got {default_ttl}")
        self._capacity = capacity
        self._default_ttl = default_ttl
        self._clock = clock
        # Ordered oldest/LRU (index 0) -> newest/MRU (last index).
        # Each entry: [key, value, expires_at].
        self._entries: list[list] = []

    def _find(self, key: K) -> int | None:
        for i, entry in enumerate(self._entries):
            if entry[0] == key:
                return i
        return None

    def _expired(self, expires_at: float | None) -> bool:
        return expires_at is not None and self._clock() >= expires_at

    def get(self, key: K, default: object = MISS) -> object:
        i = self._find(key)
        if i is None:
            return default
        entry = self._entries[i]
        if self._expired(entry[2]):
            del self._entries[i]
            return default
        del self._entries[i]
        self._entries.append(entry)
        return entry[1]

    def put(self, key: K, value: V, ttl: object = _USE_DEFAULT) -> None:
        effective_ttl = self._default_ttl if ttl is _USE_DEFAULT else ttl
        if effective_ttl is not None and effective_ttl <= 0:
            raise ValueError(f"ttl must be > 0 or None, got {effective_ttl}")
        expires_at = None if effective_ttl is None else self._clock() + effective_ttl
        i = self._find(key)
        if i is not None:
            del self._entries[i]
            self._entries.append([key, value, expires_at])
            return
        if len(self._entries) >= self._capacity:
            self._entries.pop(0)
        self._entries.append([key, value, expires_at])

    def delete(self, key: K) -> bool:
        i = self._find(key)
        if i is None:
            return False
        del self._entries[i]
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: K) -> bool:
        i = self._find(key)
        return i is not None and not self._expired(self._entries[i][2])
