from __future__ import annotations

import numpy as np
import pytest

from semantic_cache.embedders import HashingEmbedder


def test_deterministic_across_calls() -> None:
    embedder = HashingEmbedder(dim=64)
    a = embedder.embed(["hello world"])
    b = embedder.embed(["hello world"])
    assert np.allclose(a, b)


def test_l2_normalized() -> None:
    embedder = HashingEmbedder(dim=64)
    vecs = embedder.embed(["hello world", "a completely different sentence about cats"])
    norms = np.linalg.norm(vecs, axis=1)
    assert np.allclose(norms, 1.0)


def test_identical_text_gives_cosine_one() -> None:
    embedder = HashingEmbedder(dim=64)
    vecs = embedder.embed(["what is the capital of France", "what is the capital of France"])
    assert vecs[0] @ vecs[1] == pytest.approx(1.0)


def test_shared_vocabulary_scores_higher_than_unrelated() -> None:
    embedder = HashingEmbedder(dim=128)
    base, paraphrase, unrelated = embedder.embed(
        [
            "what is the capital of France",
            "capital city of France, what is it",
            "how do I bake sourdough bread",
        ]
    )
    assert base @ paraphrase > base @ unrelated


def test_empty_string_is_the_zero_vector_not_nan() -> None:
    embedder = HashingEmbedder(dim=16)
    vec = embedder.embed([""])[0]
    assert not np.any(np.isnan(vec))
    assert np.allclose(vec, 0.0)


def test_dim_validated() -> None:
    with pytest.raises(ValueError):
        HashingEmbedder(dim=0)


def test_local_embedder_gives_helpful_error_without_extra() -> None:
    """Guards the "never imported at module top level" contract: importing this module must not
    require sentence-transformers, and constructing LocalEmbedder without it must fail with a
    message that names the extra to install, not a bare ModuleNotFoundError."""
    from semantic_cache.embedders import LocalEmbedder

    with pytest.raises(ImportError, match="local-embed"):
        LocalEmbedder()


def test_openai_embedder_requires_api_key() -> None:
    import os

    from semantic_cache.embedders import OpenAIEmbedder

    if os.environ.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is set in this environment")
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        OpenAIEmbedder()
