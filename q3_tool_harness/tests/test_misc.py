from __future__ import annotations

from pathlib import Path

from harness.recorder import Recorder
from harness.recording import load
from harness.redact import default_redact


def test_default_redact_is_recursive_and_case_insensitive():
    out = default_redact({"a": {"Authorization": "Bearer x", "n": [{"API_KEY": "k"}]}, "keep": 1})
    assert out["a"]["Authorization"] != "Bearer x"
    assert out["a"]["n"][0]["API_KEY"] != "k"
    assert out["keep"] == 1


def test_custom_redactor_is_used(tmp_path: Path):
    out = tmp_path / "r.jsonl"
    tool = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
    with Recorder(out, agent="a", redact=lambda v: {"x": "X"}) as rec:
        rec.call("local", "t", {"a": 1}, lambda a: 1, tool_def=tool)
    call = load(out, strict=True).calls[0]
    assert call.args == {"x": "X"}


def test_mcp_adapter_module_imports_without_mcp_installed():
    import harness.adapters.mcp as adapter

    assert hasattr(adapter, "RecordingClientSession")
