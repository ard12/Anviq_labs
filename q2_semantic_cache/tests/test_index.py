from __future__ import annotations

import numpy as np
import pytest

from semantic_cache.index import NumpyIndex


def test_search_orders_by_descending_score() -> None:
    index = NumpyIndex(dim=2)
    index.add("a", np.array([1.0, 0.0]))
    index.add("b", np.array([0.0, 1.0]))
    index.add("c", np.array([0.7071, 0.7071]))
    results = index.search(np.array([1.0, 0.0]), k=3)
    ids = [r[0] for r in results]
    assert ids == ["a", "c", "b"]
    assert results[0][1] == pytest.approx(1.0)
    assert results[-1][1] == pytest.approx(0.0, abs=1e-6)


def test_search_respects_k() -> None:
    index = NumpyIndex(dim=2)
    for i in range(5):
        index.add(str(i), np.array([1.0, float(i)]) / np.linalg.norm([1.0, float(i)]))
    assert len(index.search(np.array([1.0, 0.0]), k=2)) == 2


def test_search_on_empty_index_returns_empty_list() -> None:
    index = NumpyIndex(dim=4)
    assert index.search(np.zeros(4), k=5) == []


def test_remove_drops_from_results() -> None:
    index = NumpyIndex(dim=2)
    index.add("a", np.array([1.0, 0.0]))
    index.add("b", np.array([0.0, 1.0]))
    index.remove("a")
    ids = [r[0] for r in index.search(np.array([1.0, 0.0]), k=5)]
    assert ids == ["b"]
    assert len(index) == 1


def test_remove_missing_id_is_a_noop() -> None:
    index = NumpyIndex(dim=2)
    index.add("a", np.array([1.0, 0.0]))
    index.remove("does-not-exist")
    assert len(index) == 1


def test_add_same_id_twice_replaces_vector() -> None:
    index = NumpyIndex(dim=2)
    index.add("a", np.array([1.0, 0.0]))
    index.add("a", np.array([0.0, 1.0]))
    assert len(index) == 1
    results = index.search(np.array([0.0, 1.0]), k=1)
    assert results[0] == ("a", pytest.approx(1.0))


def test_add_wrong_dim_raises() -> None:
    index = NumpyIndex(dim=3)
    with pytest.raises(ValueError):
        index.add("a", np.array([1.0, 0.0]))
