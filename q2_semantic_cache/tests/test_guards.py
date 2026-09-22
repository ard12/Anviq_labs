from __future__ import annotations

from semantic_cache.guards import (
    first_failure,
    guard_direction,
    guard_entities,
    guard_negation,
    guard_numbers,
    run_guards,
)


def test_guard_numbers_rejects_hard_negative() -> None:
    assert guard_numbers("what are the top 5 startups", "what are the top 10 startups") is not None


def test_guard_numbers_allows_paraphrase() -> None:
    assert guard_numbers("what are the top 5 startups", "give me the top 5 startups") is None


def test_guard_numbers_rejects_year_change() -> None:
    assert guard_numbers("revenue in 2023", "revenue in 2024") is not None


def test_guard_negation_rejects_hard_negative() -> None:
    assert guard_negation("is Austria safe to visit", "is Austria not safe to visit") is not None


def test_guard_negation_allows_matching_negation() -> None:
    assert guard_negation("Austria is not safe", "Austria isn't safe") is None


def test_guard_entities_rejects_hard_negative() -> None:
    assert guard_entities("what is the capital of Austria", "what is the capital of Australia") is not None


def test_guard_entities_rejects_language_swap() -> None:
    assert guard_entities("how do I read a file in Python", "how do I read a file in Java") is not None


def test_guard_entities_allows_paraphrase() -> None:
    assert guard_entities("what is the capital of Austria", "tell me Austria's capital city") is None


def test_guard_direction_rejects_hard_negative() -> None:
    assert guard_direction("should I buy this stock", "should I sell this stock") is not None


def test_guard_direction_allows_paraphrase() -> None:
    assert guard_direction("should I buy this stock", "is it a good idea to buy this stock") is None


def test_run_guards_reports_every_guard() -> None:
    results = run_guards("top 5 startups", "top 10 startups")
    names = {r.name for r in results}
    assert names == {"numbers", "negation", "entities", "direction"}
    failed = {r.name for r in results if not r.passed}
    assert failed == {"numbers"}


def test_first_failure_returns_none_when_all_pass() -> None:
    assert first_failure("what is the capital of France", "what's France's capital") is None


def test_first_failure_returns_name_and_reason() -> None:
    result = first_failure("top 5 startups", "top 10 startups")
    assert result is not None
    name, reason = result
    assert name == "numbers"
    assert "mismatch" in reason
