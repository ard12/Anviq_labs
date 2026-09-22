"""Grey-zone verification.

Between ``tau_verify`` and ``tau_hit`` the embedding score is not confident enough to serve
automatically, but too high to throw away without a second opinion. A :class:`Verifier` is that
second opinion. It is deliberately not on the hot path for confident hits or confident misses --
only the narrow grey-zone band pays for it, which keeps the average cost close to zero even if a
single verifier call is expensive (a cross-encoder pass or an LLM judge call).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol


class Verifier(Protocol):
    def same_intent(self, a: str, b: str) -> bool:
        """Return True if ``a`` and ``b`` ask the same underlying question."""
        ...


class NoopVerifier:
    """The conservative default: reject every grey-zone candidate.

    Shipping with this verifier means the grey zone behaves exactly like "below tau_hit" --
    always a miss -- until a real verifier is wired in. That is a deliberate, safe starting point:
    it never introduces a new way to serve a wrong answer, it only ever makes the cache *more*
    conservative than a bare threshold would be.
    """

    def same_intent(self, a: str, b: str) -> bool:
        return False


class LLMJudgeVerifier:
    """Delegates the grey-zone decision to an LLM (or cross-encoder) judge call.

    The actual model call is injected as ``judge_fn`` -- a plain ``(a, b) -> bool`` callable --
    rather than constructed inside this class. That keeps this module importable with no network
    and no API key, and keeps ``semantic_cache.verifier`` free of a hard dependency on any
    specific LLM SDK. A convenience constructor, :meth:`LLMJudgeVerifier.using_openai`, builds a
    ``judge_fn`` backed by the OpenAI SDK (the ``[llm-judge]`` extra) for callers who want a
    default instead of writing their own.

    Never constructed by the test suite or by ``eval.py``: doing so would require a real API key
    and a network call, which the brief explicitly rules out for tests.
    """

    def __init__(self, judge_fn: Callable[[str, str], bool]) -> None:
        self._judge_fn = judge_fn

    def same_intent(self, a: str, b: str) -> bool:
        return self._judge_fn(a, b)

    @classmethod
    def using_openai(cls, model: str = "gpt-4o-mini", api_key: str | None = None) -> LLMJudgeVerifier:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)  # falls back to the OPENAI_API_KEY env var itself

        def judge_fn(a: str, b: str) -> bool:
            prompt = (
                "Do these two questions ask for the same information, such that an answer to "
                "one would correctly answer the other? Reply with exactly one word, "
                f"'yes' or 'no'.\n\nQuestion A: {a}\nQuestion B: {b}"
            )
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=1,
            )
            answer = (response.choices[0].message.content or "").strip().lower()
            return answer.startswith("y")

        return cls(judge_fn)
