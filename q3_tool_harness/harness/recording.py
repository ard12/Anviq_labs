"""Loads a JSONL recording, validates it against the shared schema, and verifies its hash chain.

`load()` never silently accepts a tampered or malformed file: problems are collected in
`Recording.integrity_problems`, and with `strict=True` (what `harness check` uses) they raise
`IntegrityError` instead. `harness diff` uses `strict=False` and reports problems as warnings
so a human can still see a best-effort diff of a suspect file.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

from harness._canonical import event_hash, tool_hash

_SCHEMA_PATH = Path(__file__).parent / "_schema" / "recording.schema.json"
_RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str) or _RFC3339_DATE_TIME.fullmatch(value) is None:
        return False
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None


_FORMAT_CHECKER = jsonschema.FormatChecker()
_FORMAT_CHECKER.checks("date-time")(_is_rfc3339_date_time)


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    schema = _schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema, format_checker=_FORMAT_CHECKER)


class IntegrityError(Exception):
    """Raised by `load(..., strict=True)` when a recording fails schema/hash-chain checks."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(slots=True)
class ToolVersion:
    server: str
    name: str
    tool: dict[str, Any]
    def_hash: str
    seq: int


@dataclass(slots=True)
class CallRecord:
    call_id: str
    server: str
    tool_name: str
    def_hash: str
    args: dict[str, Any]
    call_seq: int
    ok: bool | None = None
    result: Any = None
    error: dict[str, Any] | None = None
    latency_ms: float | None = None
    response_seq: int | None = None


@dataclass(slots=True)
class Recording:
    path: str
    session_id: str
    agent: str
    events: list[dict[str, Any]] = field(default_factory=list)
    # (server, name) -> every definition seen, in seq order (last element = current).
    tools: dict[tuple[str, str], list[ToolVersion]] = field(default_factory=dict)
    calls: list[CallRecord] = field(default_factory=list)
    integrity_problems: list[str] = field(default_factory=list)

    def latest_tool(self, server: str, name: str) -> ToolVersion | None:
        versions = self.tools.get((server, name))
        return versions[-1] if versions else None

    def tool_keys(self) -> set[tuple[str, str]]:
        return set(self.tools)

    def calls_for(self, server: str, name: str) -> list[CallRecord]:
        return [c for c in self.calls if c.server == server and c.tool_name == name]

    def verify(self) -> list[str]:
        """Recompute schema validation, seq continuity, and the hash chain. Returns problems."""
        problems: list[str] = []
        validator = _validator()
        if not self.events:
            return ["recording is empty: missing session_start"]
        if self.events[0].get("type") != "session_start":
            problems.append("recording must begin with session_start")
        definitions: set[tuple[str, str, str]] = set()
        calls: set[str] = set()
        responses: set[str] = set()
        ended = False
        prev_hash: str | None = None
        expected_seq = 0
        for i, event in enumerate(self.events):
            errors = list(validator.iter_errors(event))
            for err in errors:
                problems.append(f"event[{i}] (seq={event.get('seq')}): schema violation: {err.message}")
            if event.get("session_id") != self.session_id:
                problems.append(f"event[{i}]: session_id differs from the recording's session")
            if ended:
                problems.append(f"event[{i}]: event appears after session_end")
            if i and event.get("type") == "session_start":
                problems.append(f"event[{i}]: duplicate session_start")
            ended = ended or event.get("type") == "session_end"
            seq = event.get("seq")
            if seq != expected_seq:
                problems.append(f"event[{i}]: expected seq={expected_seq}, got {seq!r}")
            expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1

            stored_prev = event.get("prev_hash")
            if stored_prev != prev_hash:
                problems.append(
                    f"event[{i}] (seq={seq}): prev_hash mismatch: recording says {stored_prev!r}, "
                    f"chain expects {prev_hash!r}"
                )
            stored_hash = event.get("event_hash")
            try:
                recomputed = event_hash(event)
                if stored_hash != recomputed:
                    problems.append(f"event[{i}] (seq={seq}): event_hash mismatch -- event was tampered with")
            except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
                problems.append(f"event[{i}]: cannot hash event: {exc}")
            prev_hash = stored_hash
            if errors:
                continue  # malformed fields must not crash semantic validation/indexing
            etype = event["type"]
            if etype == "tool_definition":
                try:
                    if tool_hash(event["tool"]) != event["def_hash"]:
                        problems.append(f"event[{i}]: def_hash does not match tool definition")
                except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
                    problems.append(f"event[{i}]: cannot hash tool definition: {exc}")
                definitions.add((event["server"], event["tool"]["name"], event["def_hash"]))
            elif etype == "tool_call":
                if (event["server"], event["tool_name"], event["def_hash"]) not in definitions:
                    problems.append(f"event[{i}]: tool_call references an unknown definition")
                if event["call_id"] in calls:
                    problems.append(f"event[{i}]: duplicate call_id")
                calls.add(event["call_id"])
            elif etype == "tool_response":
                if event["call_id"] not in calls:
                    problems.append(f"event[{i}]: tool_response references unknown call_id")
                if event["call_id"] in responses:
                    problems.append(f"event[{i}]: duplicate tool_response")
                responses.add(event["call_id"])
        return problems


def _validate_jsonl_line(raw: str, line_no: int) -> dict[str, Any] | str:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return f"line {line_no}: invalid JSON: {exc}"
    if not isinstance(parsed, dict):
        return f"line {line_no}: event is not a JSON object"
    return parsed


def load(path: str | Path, *, strict: bool = False) -> Recording:
    """Parse and validate a JSONL recording.

    With `strict=True`, any schema violation, seq gap, or hash-chain break raises
    `IntegrityError` instead of being recorded in `.integrity_problems`.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    events: list[dict[str, Any]] = []
    problems: list[str] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        parsed = _validate_jsonl_line(raw, line_no)
        if isinstance(parsed, str):
            problems.append(parsed)
            continue
        events.append(parsed)

    session_id = events[0].get("session_id", "") if events else ""
    agent = ""
    tools: dict[tuple[str, str], list[ToolVersion]] = {}
    calls_by_id: dict[str, CallRecord] = {}
    calls: list[CallRecord] = []

    for event in events:
        if not _validator().is_valid(event):
            continue  # verify() reports it; best-effort indexing uses well-shaped events only
        etype = event.get("type")
        if etype == "session_start":
            agent = event.get("agent", "")
        elif etype == "tool_definition":
            server = event.get("server", "")
            tool = event.get("tool", {})
            name = tool.get("name", "")
            key = (server, name)
            tools.setdefault(key, []).append(
                ToolVersion(server=server, name=name, tool=tool, def_hash=event.get("def_hash", ""), seq=event["seq"])
            )
        elif etype == "tool_call":
            rec = CallRecord(
                call_id=event.get("call_id", ""),
                server=event.get("server", ""),
                tool_name=event.get("tool_name", ""),
                def_hash=event.get("def_hash", ""),
                args=event.get("args", {}),
                call_seq=event["seq"],
            )
            calls_by_id[rec.call_id] = rec
            calls.append(rec)
        elif etype == "tool_response":
            rec = calls_by_id.get(event.get("call_id", ""))
            if rec is not None:
                rec.ok = event.get("ok")
                rec.result = event.get("result")
                rec.error = event.get("error")
                rec.latency_ms = event.get("latency_ms")
                rec.response_seq = event["seq"]
            else:
                problems.append(f"tool_response references unknown call_id {event.get('call_id')!r}")

    recording = Recording(
        path=str(path),
        session_id=session_id,
        agent=agent,
        events=events,
        tools=tools,
        calls=calls,
        integrity_problems=problems,
    )
    recording.integrity_problems = problems + recording.verify()

    if strict and recording.integrity_problems:
        raise IntegrityError(recording.integrity_problems)
    return recording


__all__ = ["CallRecord", "IntegrityError", "Recording", "ToolVersion", "load"]
