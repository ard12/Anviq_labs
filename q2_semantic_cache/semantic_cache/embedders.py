"""Text -> vector embedders.

``Embedder`` is a structural (``typing.Protocol``) interface, not a base class, so any object with
a matching ``embed``/``dim``/``model_id`` shape works -- including test doubles that don't import
this module at all.

Only :class:`HashingEmbedder` is imported by core code and by the test suite. The other two are
real embedding backends; their heavy dependencies (``sentence-transformers``, ``openai``) are
imported lazily, inside ``__init__``/``embed``, specifically so that importing
``semantic_cache.embedders`` -- or anything that transitively imports it, e.g. ``cache.py`` --
never requires those packages to be installed. See ``pyproject.toml``'s ``[local-embed]`` and
``[api-embed]`` extras.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from typing import Protocol

import numpy as np

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    """Anything that turns text into L2-normalized row vectors."""

    dim: int
    model_id: str

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        """Return an ``(len(texts), self.dim)`` float array with each row L2-normalized (unit
        norm), so that cosine similarity reduces to a plain dot product downstream."""
        ...


class HashingEmbedder:
    """Deterministic, dependency-free bag-of-words hashing embedder.

    This is *not* a semantic embedder -- it has no notion that "purchase" and "buy" mean the same
    thing. It exists so tests (and CI, which must run with no network and no model download) can
    exercise the whole pipeline -- partitioning, thresholds, guards, TTL, single-flight -- with a
    real ``Embedder`` implementation instead of a hand-rolled fake, and get reproducible numbers.
    Two texts that share vocabulary (after casefolding and tokenizing) score high; texts that
    don't share vocabulary score near zero, even if a human would call them paraphrases. See
    ``eval.py`` and the README for why this matters for the numbers in ``EVAL_RESULTS.md``.
    """

    model_id = "hashing-v1"

    def __init__(self, dim: int = 256) -> None:
        if dim < 1:
            raise ValueError("dim must be >= 1")
        self.dim = dim

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        vectors = np.zeros((len(texts), self.dim), dtype=np.float64)
        for row, text in enumerate(texts):
            for token in _TOKEN_RE.findall(text.lower()):
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                bucket = int.from_bytes(digest[:4], "big") % self.dim
                sign = 1.0 if digest[4] % 2 == 0 else -1.0
                vectors[row, bucket] += sign
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0  # empty string / all-stopword input -> stay the zero vector
        return vectors / norms


class LocalEmbedder:
    """sentence-transformers ``all-MiniLM-L6-v2``, loaded lazily.

    Requires the ``[local-embed]`` extra (``pip install semantic_cache[local-embed]``). Not
    imported by any test.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - exercised only when extra is missing
            raise ImportError(
                "LocalEmbedder requires the 'local-embed' extra: "
                "pip install semantic_cache[local-embed]"
            ) from exc
        self._model = SentenceTransformer(model_name)
        self.model_id = model_name
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        vectors = self._model.encode(list(texts), normalize_embeddings=True, convert_to_numpy=True)
        return np.asarray(vectors, dtype=np.float64)


class OpenAIEmbedder:
    """OpenAI embeddings API. Requires the ``[api-embed]`` extra and an API key.

    Never called in tests -- there is no fake for it and no test imports it, by design (the brief
    is explicit that tests need no network). The key is read from ``OPENAI_API_KEY`` at
    construction time unless passed explicitly, and the client is created lazily on first
    ``embed()`` call so constructing this object doesn't require the ``openai`` package to be
    importable until you actually use it.
    """

    def __init__(self, model: str = "text-embedding-3-small", api_key: str | None = None, dim: int = 1536) -> None:
        self.model_id = model
        self.dim = dim
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise RuntimeError("OPENAI_API_KEY is not set and no api_key was passed to OpenAIEmbedder")
        self._client: object | None = None

    def _client_or_create(self) -> object:
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(api_key=self._api_key)
        return self._client

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        client = self._client_or_create()
        response = client.embeddings.create(model=self.model_id, input=list(texts))  # type: ignore[attr-defined]
        vectors = np.array([row.embedding for row in response.data], dtype=np.float64)
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vectors / norms
