from __future__ import annotations

from pathlib import Path

import pytest

from harness.recorder import Recorder
from harness.recording import load
from harness.replay import ReplayServer, UnrecordedCallError

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
        with pytest.raises(FileNotFoundError):  # the failure is recorded, then re-raised
            rec.call("local", "read_file", {"path": "/b"}, _missing)
    return out


def _missing(path: str) -> dict:
    raise FileNotFoundError(path)


def test_list_tools_returns_recorded_definitions(tmp_path: Path) -> None:
    recording = load(_make_recording(tmp_path))
    server = ReplayServer(recording)
    tools = server.list_tools()
    assert [t["name"] for t in tools] == ["read_file"]


def test_call_returns_recorded_response_by_matching_args(tmp_path: Path) -> None:
    recording = load(_make_recording(tmp_path))
    server = ReplayServer(recording)
    result = server.call("read_file", {"path": "/a"})
    assert result.ok is True
    assert result.result == {"content": "a"}


def test_call_matches_args_regardless_of_key_order(tmp_path: Path) -> None:
    out = tmp_path / "rec.jsonl"
    with Recorder(out, agent="a") as rec:
        rec.record_definitions(
            "local", [{**READ_FILE, "inputSchema": {"type": "object", "properties": {"path": {}, "mode": {}}}}]
        )
        rec.call("local", "read_file", {"path": "/a", "mode": "r"}, lambda path, mode: {"content": "a"})
    recording = load(out)
    server = ReplayServer(recording)
    result = server.call("read_file", {"mode": "r", "path": "/a"})  # different key order
    assert result.result == {"content": "a"}


def test_call_returns_recorded_error(tmp_path: Path) -> None:
    recording = load(_make_recording(tmp_path))
    server = ReplayServer(recording)
    result = server.call("read_file", {"path": "/b"})
    assert result.ok is False
    assert result.error["code"] == "FileNotFoundError"


def test_strict_mode_raises_on_unseen_call(tmp_path: Path) -> None:
    recording = load(_make_recording(tmp_path))
    server = ReplayServer(recording)
    with pytest.raises(UnrecordedCallError):
        server.call("read_file", {"path": "/never/recorded"}, strict=True)


def test_non_strict_mode_falls_back_to_first_recorded_call(tmp_path: Path) -> None:
    recording = load(_make_recording(tmp_path))
    server = ReplayServer(recording)
    result = server.call("read_file", {"path": "/never/recorded"}, strict=False)
    assert result.result == {"content": "a"}  # falls back to the first call to this tool


def test_unknown_tool_raises_even_when_not_strict(tmp_path: Path) -> None:
    recording = load(_make_recording(tmp_path))
    server = ReplayServer(recording)
    with pytest.raises(UnrecordedCallError):
        server.call("no_such_tool", {})


def test_omitted_server_uses_first_recorded_server(tmp_path):
    out = tmp_path / "multiple.jsonl"
    with Recorder(out, agent="test") as recorder:
        for server in ("z-first", "a-second"):
            recorder.record_definitions(server, [READ_FILE])
            recorder.call(server, "read_file", {"path": server}, lambda path: path)
    replay = ReplayServer(load(out, strict=True))
    assert replay.call("read_file", {"path": "unknown"}).result == "z-first"
