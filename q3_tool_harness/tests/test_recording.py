from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness._canonical import event_hash
from harness.recorder import Recorder
from harness.recording import IntegrityError, load

READ_FILE = {
    "name": "read_file",
    "description": "Read a file.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
}


def _make_recording(tmp_path: Path) -> Path:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="a") as rec:
        rec.record_definitions("local", [READ_FILE])
        rec.call("local", "read_file", {"path": "/a"}, lambda path: {"content": "a"})
    return out


def test_load_valid_recording_has_no_problems(tmp_path: Path) -> None:
    out = _make_recording(tmp_path)
    recording = load(out)
    assert recording.integrity_problems == []
    assert recording.verify() == []


def test_load_strict_raises_on_clean_file(tmp_path: Path) -> None:
    out = _make_recording(tmp_path)
    load(out, strict=True)  # must not raise


def test_tampered_event_breaks_hash_chain(tmp_path: Path) -> None:
    out = _make_recording(tmp_path)
    lines = out.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    for event in events:
        if event["type"] == "tool_call":
            event["args"] = {"path": "/tampered"}  # edited after the fact, event_hash now stale
    out.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    recording = load(out)
    assert recording.integrity_problems != []
    assert any("tampered" in p or "event_hash mismatch" in p for p in recording.integrity_problems)

    with pytest.raises(IntegrityError):
        load(out, strict=True)


def test_seq_gap_is_detected(tmp_path: Path) -> None:
    out = _make_recording(tmp_path)
    lines = out.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    del events[2]  # remove one event entirely, leaving a seq gap
    out.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    recording = load(out)
    assert any("seq" in p for p in recording.integrity_problems)


def test_malformed_json_line_is_reported(tmp_path: Path) -> None:
    out = tmp_path / "bad.jsonl"
    out.write_text('{"not": "valid"\n', encoding="utf-8")
    recording = load(out)
    assert recording.integrity_problems != []
    with pytest.raises(IntegrityError):
        load(out, strict=True)


def test_tools_and_calls_are_indexed(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="a") as rec:
        rec.record_definitions("local", [READ_FILE])
        rec.call("local", "read_file", {"path": "/a"}, lambda path: {"content": "a"})
        rec.call("local", "read_file", {"path": "/b"}, lambda path: {"content": "b"})

    recording = load(out)
    assert recording.tool_keys() == {("local", "read_file")}
    assert recording.latest_tool("local", "read_file").tool["name"] == "read_file"
    calls = recording.calls_for("local", "read_file")
    assert len(calls) == 2
    assert calls[0].args == {"path": "/a"}
    assert calls[0].result == {"content": "a"}


def test_empty_recording_cannot_pass_strict_validation(tmp_path):
    out = tmp_path / "empty.jsonl"
    out.write_text("", encoding="utf-8")
    with pytest.raises(IntegrityError, match="empty"):
        load(out, strict=True)


@pytest.mark.parametrize("mutation", ["malformed_tool", "wrong_hash", "wrong_session", "nonfinite", "bad_timestamp"])
def test_invalid_recordings_report_integrity_errors_without_crashing(tmp_path, mutation):
    out = _make_recording(tmp_path)
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    if mutation == "malformed_tool":
        events[1]["tool"] = []
    elif mutation == "wrong_hash":
        events[1]["def_hash"] = "sha256:" + "0" * 64
    elif mutation == "wrong_session":
        events[1]["session_id"] = "different-session"
    elif mutation == "nonfinite":
        events[2]["args"]["number"] = float("nan")
    else:
        events[1]["ts"] = "not-a-date"
    # Even a consistent event chain must not hide a wrong definition hash or session.
    if mutation != "nonfinite":
        previous = None
        for event in events:
            event["prev_hash"] = previous
            event["event_hash"] = previous = event_hash(event)
    out.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    assert load(out).integrity_problems
    with pytest.raises(IntegrityError):
        load(out, strict=True)
