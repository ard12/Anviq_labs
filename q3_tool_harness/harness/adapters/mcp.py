"""Wraps a real MCP `ClientSession` so its `list_tools`/`call_tool` traffic is recorded.

Requires the `mcp` package (extra `[mcp]`). No test in this package depends on it being
installed: importing this module is always safe, and constructing `RecordingClientSession` is
the only thing that requires `mcp` to actually be present.
"""

from __future__ import annotations

from typing import Any

from harness.recorder import Recorder


def _tool_to_dict(tool: Any) -> dict[str, Any]:
    """MCP's `Tool` is a pydantic model; project it onto the plain dict shape our schema expects."""
    if isinstance(tool, dict):
        return tool
    d = tool.model_dump(exclude_none=True) if hasattr(tool, "model_dump") else dict(tool)
    out: dict[str, Any] = {
        "name": d["name"],
        "description": d.get("description", ""),
        "inputSchema": d.get("inputSchema", {}),
    }
    if "outputSchema" in d:
        out["outputSchema"] = d["outputSchema"]
    if d.get("annotations") is not None:
        out["annotations"] = d["annotations"]
    return out


class RecordingClientSession:
    """Thin proxy around an MCP `ClientSession` that records every `list_tools`/`call_tool`.

    MCP's session is async; `Recorder.wrap()` assumes a synchronous callable, so this adapter
    drives the emit/measure/record sequence itself instead of reusing `wrap()`.
    """

    def __init__(self, session: Any, recorder: Recorder, *, server: str = "mcp") -> None:
        try:
            import mcp  # noqa: F401  (import-guard: raises ImportError without the [mcp] extra)
        except ImportError as exc:  # pragma: no cover - exercised only when mcp is absent
            raise ImportError("harness.adapters.mcp requires the 'mcp' package; install harness[mcp]") from exc
        self._session = session
        self._recorder = recorder
        self._server = server

    async def list_tools(self) -> Any:
        result = await self._session.list_tools()
        tools = [_tool_to_dict(t) for t in result.tools]
        self._recorder.record_definitions(self._server, tools)
        return result

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        args = arguments or {}
        recorder = self._recorder
        def_hash = recorder.ensure_def_hash(self._server, name)
        call_id = recorder.emit_call(self._server, name, def_hash, args)

        start = recorder.now()
        try:
            result = await self._session.call_tool(name, args)
        except Exception as exc:
            recorder.emit_error_response(call_id, exc, recorder.now() - start)
            raise

        payload = result.model_dump(exclude_none=True) if hasattr(result, "model_dump") else result
        recorder.emit_ok_response(call_id, payload, recorder.now() - start)
        return result


__all__ = ["RecordingClientSession"]
