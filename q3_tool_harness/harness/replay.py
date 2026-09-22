"""Replays a recording as a fake tool server: same definitions, same responses, no network."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness._canonical import canonical_json
from harness.recording import CallRecord, Recording


class UnrecordedCallError(LookupError):
    """Raised in strict mode when a call has no matching recorded (tool, args) pair."""


@dataclass(slots=True)
class ReplayResult:
    ok: bool
    result: Any = None
    error: dict[str, Any] | None = None
    latency_ms: float | None = None


class ReplayServer:
    """A drop-in fake tool server backed by a `Recording`.

    `list_tools()` returns the latest recorded definition of every tool. `call()` returns the
    recorded response for a matching (tool, args) pair, matched by canonical JSON equality of
    the arguments (so key order / whitespace in the caller's dict does not matter).
    """

    def __init__(self, recording: Recording) -> None:
        self.recording = recording
        # (server, name, canonical(args)) -> CallRecord, first match wins on replay.
        self._by_args: dict[tuple[str, str, str], CallRecord] = {}
        # (server, name) -> first CallRecord, for the best-effort non-strict fallback.
        self._first_by_tool: dict[tuple[str, str], CallRecord] = {}
        for call in recording.calls:
            key = (call.server, call.tool_name, canonical_json(call.args))
            self._by_args.setdefault(key, call)
            self._first_by_tool.setdefault((call.server, call.tool_name), call)

    def list_tools(self, server: str | None = None) -> list[dict[str, Any]]:
        out = []
        for (srv, _name), versions in self.recording.tools.items():
            if server is not None and srv != server:
                continue
            out.append(versions[-1].tool)
        return out

    def call(self, name: str, args: dict[str, Any], *, server: str | None = None, strict: bool = False) -> ReplayResult:
        """Return the recorded response for `name(**args)`.

        If `server` is omitted, the first server that recorded a matching call wins. In strict
        mode an unseen (tool, args) pair raises `UnrecordedCallError`; otherwise we fall back to
        the first recorded call for that tool name, if any.
        """
        candidates = (
            [server] if server is not None else list(dict.fromkeys(s for s, n in self._first_by_tool if n == name))
        )
        for srv in candidates:
            rec = self._by_args.get((srv, name, canonical_json(args)))
            if rec is not None:
                return ReplayResult(ok=bool(rec.ok), result=rec.result, error=rec.error, latency_ms=rec.latency_ms)
        if strict:
            raise UnrecordedCallError(f"no recorded call for tool={name!r} args={args!r}")
        for srv in candidates:
            rec = self._first_by_tool.get((srv, name))
            if rec is not None:
                return ReplayResult(ok=bool(rec.ok), result=rec.result, error=rec.error, latency_ms=rec.latency_ms)
        raise UnrecordedCallError(f"tool {name!r} was never called in this recording")


__all__ = ["ReplayResult", "ReplayServer", "UnrecordedCallError"]
