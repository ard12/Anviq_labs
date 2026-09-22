"""Records tool definitions, calls, and responses to a JSONL recording.

Every event carries a monotonic `seq` and a hash chain (`prev_hash` -> `event_hash`) so a
recording can be checked for tampering later (see `harness/recording.py`). Writes are flushed
per event: a crash mid-session leaves a valid, truncated-but-verifiable prefix.
"""

from __future__ import annotations

import functools
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import IO, Any

from harness._canonical import canonical_json, event_hash, tool_hash
from harness.redact import default_redact

Redactor = Callable[[Any], Any]
Clock = Callable[[], str]
IdGen = Callable[[], str]


def _default_clock() -> str:
    return datetime.now(UTC).isoformat()


def _uuid_ids() -> Iterator[str]:
    while True:
        yield uuid.uuid4().hex


class Recorder:
    """Context manager that writes a `session_start` ... `session_end` event stream.

    Usage:
        with Recorder("session.jsonl", agent="demo-agent/1.0") as rec:
            rec.record_definitions("local", [tool_def, ...])
            read_file = rec.wrap("local", tool_def, actual_fn)
            read_file(path="/etc/hosts")
    """

    def __init__(
        self,
        path: str | Path | IO[str],
        *,
        session_id: str | None = None,
        agent: str = "unknown",
        meta: dict[str, Any] | None = None,
        redact: Redactor | None = None,
        clock: Clock | None = None,
        id_gen: Iterator[str] | None = None,
        timer: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.session_id = session_id or uuid.uuid4().hex
        self.agent = agent
        self.meta = meta
        self._redact: Redactor = redact if redact is not None else default_redact
        self._clock: Clock = clock or _default_clock
        self._timer = timer  # injectable so fixtures get deterministic latencies
        self._ids: Iterator[str] = id_gen if id_gen is not None else _uuid_ids()

        self._owns_fh = isinstance(path, (str, Path))
        self._fh: IO[str] = open(path, "w", encoding="utf-8", newline="\n") if self._owns_fh else path  # type: ignore[arg-type]

        self._seq = 0
        self._prev_hash: str | None = None
        # (server, name) -> (def_hash, tool dict) for the definition currently in force.
        self._defs: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}

    # -- context manager -----------------------------------------------------------------

    def __enter__(self) -> Recorder:
        fields: dict[str, Any] = {"agent": self.agent}
        if self.meta is not None:
            fields["meta"] = self.meta
        self._emit("session_start", fields)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        reason = "error" if exc_type is not None else "completed"
        self._emit("session_end", {"reason": reason})
        if self._owns_fh:
            self._fh.close()
        # Do not suppress the exception, if any.
        return None

    # -- low-level event emission --------------------------------------------------------

    def _emit(self, event_type: str, fields: dict[str, Any]) -> dict[str, Any]:
        event: dict[str, Any] = {
            "v": 1,
            "seq": self._seq,
            "ts": self._clock(),
            "session_id": self.session_id,
            "type": event_type,
            "prev_hash": self._prev_hash,
            **fields,
        }
        h = event_hash(event)
        event["event_hash"] = h
        self._fh.write(canonical_json(event) + "\n")
        self._fh.flush()
        self._seq += 1
        self._prev_hash = h
        return event

    # -- tool definitions -----------------------------------------------------------------

    def record_definitions(self, server: str, tools: list[dict[str, Any]]) -> None:
        """Emit `tool_definition` for each tool whose hash differs from what we've recorded.

        Called once per session for the initial `list_tools`, and again whenever the agent
        re-lists tools mid-session. A hash that differs from the last one we saw for that
        (server, name) -- including the very first time we see it -- triggers a new event, and
        later calls reference the new `def_hash`. This is the hook Q4's proxy builds on to
        catch a tool rug-pulling its own definition mid-session.
        """
        for tool in tools:
            key = (server, tool["name"])
            h = tool_hash(tool)
            prior = self._defs.get(key)
            if prior is not None and prior[0] == h:
                continue
            self._defs[key] = (h, tool)
            self._emit("tool_definition", {"server": server, "tool": tool, "def_hash": h})

    def _def_hash(self, server: str, name: str, tool_def: dict[str, Any] | None) -> str:
        key = (server, name)
        prior = self._defs.get(key)
        if prior is None:
            if tool_def is None:
                raise KeyError(f"no definition recorded yet for {key!r}; call record_definitions() first")
            self.record_definitions(server, [tool_def])
            return self._defs[key][0]
        return prior[0]

    # -- calls --------------------------------------------------------------------------

    def wrap(self, server: str, tool_def: dict[str, Any], fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap `fn` so every call emits `tool_call` + `tool_response` (ok or error).

        `fn` is called as `fn(**args)`. The wrapped callable has the same signature and
        re-raises whatever `fn` raises, after recording the failure.
        """
        name = tool_def["name"]
        self._def_hash(server, name, tool_def)  # ensure a definition is on record

        @functools.wraps(fn)
        def wrapped(**args: Any) -> Any:
            return self.call(server, name, args, fn, tool_def=tool_def)

        return wrapped

    def call(
        self,
        server: str,
        name: str,
        args: dict[str, Any],
        fn: Callable[..., Any],
        *,
        tool_def: dict[str, Any] | None = None,
    ) -> Any:
        """Record and execute a single call to `fn(**args)`, without needing a persistent wrapper."""
        def_hash = self._def_hash(server, name, tool_def)
        call_id = self.emit_call(server, name, def_hash, args)
        start = self._timer()
        try:
            result = fn(**args)
        except Exception as exc:
            self.emit_error_response(call_id, exc, self._timer() - start)
            raise
        self.emit_ok_response(call_id, result, self._timer() - start)
        return result

    # -- building blocks for adapters that can't use call()/wrap() directly (e.g. async ones) ---

    def now(self) -> float:
        """Monotonic timestamp (seconds) from the recorder's timer, for adapters measuring latency."""
        return self._timer()

    def ensure_def_hash(self, server: str, name: str) -> str:
        """The `def_hash` currently in force for (server, name). Raises if never recorded."""
        return self._def_hash(server, name, None)

    def emit_call(self, server: str, name: str, def_hash: str, args: dict[str, Any]) -> str:
        call_id = next(self._ids)
        self._emit(
            "tool_call",
            {"call_id": call_id, "server": server, "tool_name": name, "def_hash": def_hash, "args": self._redact(args)},
        )
        return call_id

    def emit_ok_response(self, call_id: str, result: Any, elapsed_seconds: float) -> None:
        self._emit(
            "tool_response",
            {"call_id": call_id, "ok": True, "result": self._redact(result), "latency_ms": elapsed_seconds * 1000},
        )

    def emit_error_response(self, call_id: str, exc: Exception, elapsed_seconds: float) -> None:
        self._emit(
            "tool_response",
            {
                "call_id": call_id,
                "ok": False,
                "error": {"code": type(exc).__name__, "message": str(exc)},
                "latency_ms": elapsed_seconds * 1000,
            },
        )

    def tool(
        self,
        *,
        server: str = "local",
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        annotations: dict[str, Any] | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator form of `wrap` for plain Python functions.

        @recorder.tool(description="Read a file.", input_schema={...})
        def read_file(path: str) -> dict: ...
        """

        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_def: dict[str, Any] = {
                "name": name or fn.__name__,
                "description": description,
                "inputSchema": input_schema if input_schema is not None else {"type": "object", "properties": {}},
            }
            if output_schema is not None:
                tool_def["outputSchema"] = output_schema
            if annotations is not None:
                tool_def["annotations"] = annotations
            return self.wrap(server, tool_def, fn)

        return deco

    def policy_decision(
        self,
        *,
        server: str,
        tool_name: str,
        action: str,
        reason: str,
        call_id: str | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Record a policy decision (e.g. from Q4's gate) alongside the call stream."""
        fields: dict[str, Any] = {"server": server, "tool_name": tool_name, "action": action, "reason": reason}
        if call_id is not None:
            fields["call_id"] = call_id
        if findings is not None:
            fields["findings"] = findings
        self._emit("policy_decision", fields)


__all__ = ["Recorder"]
