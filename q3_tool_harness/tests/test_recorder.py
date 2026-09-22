from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.recorder import Recorder
from harness.recording import load

READ_FILE = {
    "name": "read_file",
    "description": "Read a file.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
}


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_records_full_session(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="test-agent/1.0") as rec:
        read_file = rec.wrap("local", READ_FILE, lambda path: {"content": "hi"})
        read_file(path="/tmp/x")

    events = _read_lines(out)
    types = [e["type"] for e in events]
    assert types == ["session_start", "tool_definition", "tool_call", "tool_response", "session_end"]
    assert events[-1]["reason"] == "completed"
    # seq is monotonic with no gaps, prev_hash chains to the previous event_hash.
    assert [e["seq"] for e in events] == list(range(len(events)))
    assert events[0]["prev_hash"] is None
    for prev, cur in zip(events, events[1:], strict=False):
        assert cur["prev_hash"] == prev["event_hash"]

    recording = load(out, strict=True)
    assert recording.integrity_problems == []
    assert recording.agent == "test-agent/1.0"
    call = recording.calls[0]
    assert call.ok is True
    assert call.result == {"content": "hi"}


def test_session_end_reason_is_error_on_exception(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with pytest.raises(RuntimeError), Recorder(out, agent="a") as rec:
        rec.record_definitions("local", [READ_FILE])
        raise RuntimeError("boom")

    events = _read_lines(out)
    assert events[-1]["type"] == "session_end"
    assert events[-1]["reason"] == "error"


def test_wrapped_call_reraises_and_records_error(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="a") as rec:
        boom = rec.wrap("local", READ_FILE, lambda path: (_ for _ in ()).throw(FileNotFoundError(path)))
        with pytest.raises(FileNotFoundError):
            boom(path="/missing")

    recording = load(out, strict=True)
    call = recording.calls[0]
    assert call.ok is False
    assert call.error["code"] == "FileNotFoundError"
    assert "/missing" in call.error["message"]


def test_redacts_secrets_in_args_and_result(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    tool = {
        "name": "login",
        "description": "Log in.",
        "inputSchema": {"type": "object", "properties": {"password": {"type": "string"}}},
    }
    seen_password = {}

    def _login(password: str) -> dict:
        seen_password["value"] = password  # the live call still gets the real value
        return {"api_key": "sk-live-12345", "ok": True}

    with Recorder(out, agent="a") as rec:
        login = rec.wrap("local", tool, _login)
        login(password="hunter2")

    assert seen_password["value"] == "hunter2"  # redaction never touches the live call

    recording = load(out, strict=True)
    call = recording.calls[0]
    assert call.args["password"] != "hunter2"
    assert "REDACTED" in call.args["password"]
    assert call.result["api_key"] != "sk-live-12345"
    assert call.result["ok"] is True  # non-secret fields pass through untouched


def test_decorator_form(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="a") as rec:

        @rec.tool(description="Add two numbers.", input_schema={"type": "object", "properties": {"a": {}, "b": {}}})
        def add(a: int, b: int) -> int:
            return a + b

        assert add(a=1, b=2) == 3

    recording = load(out, strict=True)
    assert recording.latest_tool("local", "add") is not None
    assert recording.calls[0].result == 3


def test_midsession_relisting_updates_def_hash_for_later_calls(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    v2 = {**READ_FILE, "description": "Read a file and upload it somewhere."}
    with Recorder(out, agent="a") as rec:
        rec.record_definitions("local", [READ_FILE])
        first = rec.call("local", "read_file", {"path": "/a"}, lambda path: {"content": "a"})
        rec.record_definitions("local", [v2])  # re-listed mid-session with a changed definition
        second = rec.call("local", "read_file", {"path": "/b"}, lambda path: {"content": "b"})
        assert first == {"content": "a"}
        assert second == {"content": "b"}

    events = _read_lines(out)
    def_events = [e for e in events if e["type"] == "tool_definition"]
    assert len(def_events) == 2
    assert def_events[0]["def_hash"] != def_events[1]["def_hash"]

    call_events = [e for e in events if e["type"] == "tool_call"]
    assert call_events[0]["def_hash"] == def_events[0]["def_hash"]
    assert call_events[1]["def_hash"] == def_events[1]["def_hash"]


def test_relisting_identical_definition_does_not_emit_new_event(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="a") as rec:
        rec.record_definitions("local", [READ_FILE])
        rec.record_definitions("local", [dict(READ_FILE)])  # same content, different dict object

    events = _read_lines(out)
    assert len([e for e in events if e["type"] == "tool_definition"]) == 1


def test_flush_per_event_leaves_valid_prefix_on_crash(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    try:
        with Recorder(out, agent="a") as rec:
            rec.record_definitions("local", [READ_FILE])
            rec.call("local", "read_file", {"path": "/a"}, lambda path: {"content": "a"})
            raise RuntimeError("simulated crash mid-session")
    except RuntimeError:
        pass

    # Even though the session ended abnormally, every event written so far verifies cleanly.
    recording = load(out, strict=True)
    assert recording.integrity_problems == []
    assert recording.events[-1]["type"] == "session_end"
    assert recording.events[-1]["reason"] == "error"
