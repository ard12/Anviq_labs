"""Test doubles shared across the test suite.

``FakeEmbedder`` gives tests exact control over similarity scores (map a query string straight to
a chosen unit vector) instead of depending on ``HashingEmbedder``'s bag-of-words behavior, which
is deterministic but not something you'd want to reverse-engineer angles from in a test. Guard and
policy tests, and anything that only needs "some embedder, any embedder", use
:class:`semantic_cache.embedders.HashingEmbedder` directly instead.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np


class FakeEmbedder:
    """Maps known strings to caller-chosen vectors (assumed already unit-norm); anything else
    maps to a default vector, so a test only has to specify the strings it cares about."""

    model_id = "fake-v1"

    def __init__(self, vectors: dict[str, Sequence[float]], dim: int, default: Sequence[float] | None = None) -> None:
        self.dim = dim
        self._vectors = {k: np.asarray(v, dtype=np.float64) for k, v in vectors.items()}
        self._default = np.asarray(default, dtype=np.float64) if default is not None else np.zeros(dim)

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        return np.array([self._vectors.get(t, self._default) for t in texts])


class FakeClock:
    """Manually-advanced monotonic clock, so TTL tests never sleep."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, dt: float) -> None:
        self.now += dt


def unit_vector(score: float) -> list[float]:
    """A 2D unit vector whose dot product with ``[1.0, 0.0]`` is exactly ``score``.
    Handy for building FakeEmbedder fixtures at a precise, named similarity score."""
    if not -1.0 <= score <= 1.0:
        raise ValueError("score must be in [-1, 1]")
    return [score, (1.0 - score * score) ** 0.5]
