"""Tests for the cross-language canonical form. Run: pytest schema/"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canonical import canonical_json, event_hash, sha256_hex, tool_hash

HERE = Path(__file__).parent
GOLDEN = json.loads((HERE / "golden_vectors.json").read_text(encoding="utf-8"))


# Expected strings are what ECMAScript's Number.prototype.toString / RFC 8785 produce.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.5, "-1.5"),
        (0.1, "0.1"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (333333333.3333333, "333333333.3333333"),
        (123456789.125, "123456789.125"),
        (-2.5e-8, "-2.5e-8"),
        (9007199254740991, "9007199254740991"),
    ],
)
def test_numbers_match_ecmascript(value, expected):
    assert canonical_json(value) == expected


def test_keys_sorted_by_utf16_code_units():
    # U+1F600 (surrogate pair D83D..) sorts before U+FB33 in UTF-16, after it in code points.
    assert canonical_json({"דּ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"דּ":1}'


def test_string_escaping():
    assert canonical_json("a\"b\\c\nde/€") == '"a\\"b\\\\c\\nd\\u0001e/€"'


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 2**60, {1: "x"}, "\ud800", object()])
def test_rejects_non_portable_values(bad):
    with pytest.raises((ValueError, TypeError)):
        canonical_json(bad)


@pytest.mark.parametrize("case", GOLDEN["json"], ids=lambda c: c["id"])
def test_golden_json(case):
    assert canonical_json(case["input"]) == case["canonical"]
    assert sha256_hex(case["input"]) == case["hash"]


@pytest.mark.parametrize("case", GOLDEN["tools"], ids=lambda c: c["id"])
def test_golden_tools(case):
    assert tool_hash(case["input"]) == case["hash"]


def test_cosmetic_reordering_keeps_hash_but_rugpull_changes_it():
    by_id = {c["id"]: c["hash"] for c in GOLDEN["tools"]}
    assert by_id["read_file_basic"] == by_id["read_file_reordered_same_hash"]
    assert by_id["read_file_basic"] != by_id["read_file_rugpull"]


def test_event_hash_ignores_own_hash_field():
    ev = {"v": 1, "seq": 0, "session_id": "s", "type": "session_end", "reason": "completed"}
    h = event_hash(ev)
    assert event_hash({**ev, "event_hash": h}) == h


def test_golden_vectors_validate_against_recording_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((HERE / "recording.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    tool = GOLDEN["tools"][0]["input"]
    ev = {
        "v": 1, "seq": 1, "ts": "2026-09-18T12:00:00Z", "session_id": "s1", "type": "tool_definition",
        "prev_hash": None, "server": "fs", "tool": tool, "def_hash": tool_hash(tool),
    }
    ev["event_hash"] = event_hash(ev)
    jsonschema.validate(ev, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**ev, "def_hash": "md5:nope"}, schema)
