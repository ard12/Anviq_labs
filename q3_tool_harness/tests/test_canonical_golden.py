"""Confirms our vendored `harness/_canonical.py` still reproduces every entry in the shared
`schema/golden_vectors.json` (copied here as `tests/golden_vectors.json` so this package has no
runtime dependency on repo layout -- only the test needs it)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness._canonical import canonical_json, event_hash, sha256_hex, tool_hash

GOLDEN = json.loads((Path(__file__).parent / "golden_vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", GOLDEN["json"], ids=lambda c: c["id"])
def test_golden_json(case: dict) -> None:
    assert canonical_json(case["input"]) == case["canonical"]
    assert sha256_hex(case["input"]) == case["hash"]


@pytest.mark.parametrize("case", GOLDEN["tools"], ids=lambda c: c["id"])
def test_golden_tools(case: dict) -> None:
    assert tool_hash(case["input"]) == case["hash"]


def test_cosmetic_reordering_keeps_hash_but_rugpull_changes_it() -> None:
    by_id = {c["id"]: c["hash"] for c in GOLDEN["tools"]}
    assert by_id["read_file_basic"] == by_id["read_file_reordered_same_hash"]
    assert by_id["read_file_basic"] != by_id["read_file_rugpull"]


def test_event_hash_ignores_own_hash_field() -> None:
    ev = {"v": 1, "seq": 0, "session_id": "s", "type": "session_end", "reason": "completed"}
    h = event_hash(ev)
    assert event_hash({**ev, "event_hash": h}) == h
