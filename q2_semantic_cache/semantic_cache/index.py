"""Vector similarity index.

``VectorIndex`` is the seam between "how do we store and search vectors" and everything else.
:class:`NumpyIndex` is a brute-force cosine-similarity search over an in-memory matrix -- exact,
simple to explain, and fine up to roughly 100k entries *per partition* (a matmul over a
100k x 384 float64 matrix is a few milliseconds). It is explicitly not an approximate nearest
neighbour (ANN) index: it does not build a graph or tree, it does not trade recall for speed, and
it has no notion of "probe more nodes for better recall". Past that scale (or if partitions get
that large), swap in HNSW -- FAISS, pgvector's ``hnsw`` index, or Qdrant -- behind this same
``add``/``search``/``remove`` interface. Nothing above this module needs to change.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np


class VectorIndex(Protocol):
    """A per-partition similarity index. Implementations own their own storage."""

    def add(self, entry_id: str, vector: np.ndarray) -> None: ...

    def search(self, vector: np.ndarray, k: int) -> list[tuple[str, float]]:
        """Return up to ``k`` ``(entry_id, score)`` pairs, sorted by descending score."""
        ...

    def remove(self, entry_id: str) -> None:
        """No-op if ``entry_id`` is not present -- callers may race a lazy TTL purge."""
        ...

    def __len__(self) -> int: ...


class NumpyIndex:
    """Brute-force cosine similarity over a dense ``float64`` matrix.

    Vectors are expected to already be L2-normalized (every :class:`~semantic_cache.embedders.
    Embedder` guarantees this), so cosine similarity is a plain dot product: ``matrix @ query``.

    ``remove`` is O(n) (it rebuilds the matrix without the removed row) rather than O(1) tombstoning,
    trading a little removal cost for never having to filter tombstones back out of a search --
    simpler to read and to reason about at this scale.
    """

    def __init__(self, dim: int) -> None:
        self.dim = dim
        self._ids: list[str] = []
        self._matrix = np.zeros((0, dim), dtype=np.float64)

    def add(self, entry_id: str, vector: np.ndarray) -> None:
        vector = np.asarray(vector, dtype=np.float64).reshape(1, -1)
        if vector.shape[1] != self.dim:
            raise ValueError(f"expected a vector of dim {self.dim}, got {vector.shape[1]}")
        if not np.isfinite(vector).all():
            raise ValueError("vector must contain only finite numbers")
        if entry_id in self._ids:
            self.remove(entry_id)
        self._ids.append(entry_id)
        self._matrix = np.vstack([self._matrix, vector])

    def search(self, vector: np.ndarray, k: int) -> list[tuple[str, float]]:
        if not self._ids or k <= 0:
            return []
        vector = np.asarray(vector, dtype=np.float64).reshape(-1)
        if vector.size != self.dim or not np.isfinite(vector).all():
            raise ValueError(f"query vector must contain {self.dim} finite numbers")
        scores = self._matrix @ vector
        k = min(k, len(self._ids))
        # argpartition is O(n) vs a full O(n log n) sort; fine to swap for argsort if k ~= n.
        top = np.argpartition(-scores, k - 1)[:k]
        top = top[np.argsort(-scores[top])]
        return [(self._ids[i], float(scores[i])) for i in top]

    def remove(self, entry_id: str) -> None:
        try:
            i = self._ids.index(entry_id)
        except ValueError:
            return
        del self._ids[i]
        self._matrix = np.delete(self._matrix, i, axis=0)

    def __len__(self) -> int:
        return len(self._ids)
