from __future__ import annotations

from semantic_cache.policy import is_cacheable
from semantic_cache.types import CacheContext

CTX = CacheContext(tenant="acme", model="gpt-4o", system_prompt_hash="sp1", params_hash="p1")


def test_refuses_time_sensitive() -> None:
    for query in ["what's the current price of AAPL", "what's the latest news today", "what time is it now"]:
        decision = is_cacheable(query, CTX)
        assert not decision.cacheable, query
        assert decision.reason == "time-sensitive query"


def test_refuses_personal() -> None:
    for query in ["what is my order status", "can you check my account balance", "am I eligible for a refund"]:
        decision = is_cacheable(query, CTX)
        assert not decision.cacheable, query
        assert decision.reason == "personal query"


def test_refuses_email_pii() -> None:
    decision = is_cacheable("please send the report to jane.doe@example.com", CTX)
    assert not decision.cacheable
    assert decision.reason == "query contains an email address"


def test_refuses_phone_pii() -> None:
    decision = is_cacheable("call me back at 555-123-4567", CTX)
    assert not decision.cacheable
    # "call me" also trips the personal check; either reason is a correct refusal.
    assert decision.reason in {"personal query", "query contains a phone number"}


def test_refuses_tool_use() -> None:
    decision = is_cacheable("what is the capital of France", CTX, has_tools=True)
    assert not decision.cacheable
    assert decision.reason == "request has tool calls"


def test_refuses_high_temperature() -> None:
    decision = is_cacheable("write a short poem about the sea", CTX, temperature=0.9)
    assert not decision.cacheable
    assert "temperature" in decision.reason


def test_allows_low_temperature() -> None:
    decision = is_cacheable("write a short poem about the sea", CTX, temperature=0.2)
    assert decision.cacheable


def test_allows_ordinary_factual_query() -> None:
    decision = is_cacheable("what is the capital of France", CTX)
    assert decision.cacheable
    assert decision.reason is None
