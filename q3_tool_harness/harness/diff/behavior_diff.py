"""Diffs *observed behaviour*: the shape of recorded responses and the error rate, plus a scan
for injection-like content leaking into response payloads (a rug-pull that never touches the
tool's advertised schema or description at all -- it just starts returning different data).
"""

from __future__ import annotations

import json
from typing import Any

from harness.diff.patterns import new_matches
from harness.diff.types import Finding
from harness.recording import CallRecord

DEFAULT_MIN_CALLS_FOR_ERROR_RATE = 3
DEFAULT_ERROR_RATE_DELTA = 0.2


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _walk(value: Any, pointer: str, shape: dict[str, set[str]]) -> None:
    shape.setdefault(pointer, set()).add(_json_type(value))
    if isinstance(value, dict):
        for k, v in value.items():
            _walk(v, f"{pointer}/{k}", shape)
    elif isinstance(value, list):
        for v in value:
            _walk(v, f"{pointer}/[]", shape)  # all array elements share one path


def infer_shape(calls: list[CallRecord]) -> dict[str, frozenset[str]]:
    """Map each key path within a tool's recorded (successful) responses to the set of JSON
    types observed there. `""` is the root path (the top-level result's own type)."""
    shape: dict[str, set[str]] = {}
    for call in calls:
        if call.ok:
            _walk(call.result, "", shape)
    return {k: frozenset(v) for k, v in shape.items()}


def compare_shapes(
    tool: str, before_shape: dict[str, frozenset[str]], after_shape: dict[str, frozenset[str]]
) -> list[Finding]:
    findings: list[Finding] = []
    for pointer in sorted(set(before_shape) | set(after_shape)):
        before_types = before_shape.get(pointer, frozenset())
        after_types = after_shape.get(pointer, frozenset())
        if before_types == after_types:
            continue
        path = "/result" + pointer
        findings.append(
            Finding(
                "WARN",
                "RESPONSE_SHAPE_CHANGED",
                tool=tool,
                path=path,
                message=f"response shape at {path!r} changed: {sorted(before_types)} -> {sorted(after_types)}",
                before=sorted(before_types),
                after=sorted(after_types),
            )
        )
    return findings


def _error_rate(calls: list[CallRecord]) -> float | None:
    if not calls:
        return None
    return sum(1 for c in calls if c.ok is False) / len(calls)


def diff_error_rate(
    tool: str,
    before_calls: list[CallRecord],
    after_calls: list[CallRecord],
    *,
    min_calls: int = DEFAULT_MIN_CALLS_FOR_ERROR_RATE,
    delta_threshold: float = DEFAULT_ERROR_RATE_DELTA,
) -> list[Finding]:
    if len(before_calls) < min_calls or len(after_calls) < min_calls:
        return []
    before_rate, after_rate = _error_rate(before_calls), _error_rate(after_calls)
    if before_rate is None or after_rate is None or abs(after_rate - before_rate) < delta_threshold:
        return []
    return [
        Finding(
            "WARN",
            "ERROR_RATE_CHANGED",
            tool=tool,
            path="/responses/error_rate",
            message=(
                f"error rate changed from {before_rate:.0%} ({len(before_calls)} calls) to "
                f"{after_rate:.0%} ({len(after_calls)} calls)"
            ),
            before=before_rate,
            after=after_rate,
        )
    ]


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def diff_response_injection(
    tool: str,
    before_calls: list[CallRecord],
    after_calls: list[CallRecord],
    *,
    other_tool_names: frozenset[str] = frozenset(),
) -> list[Finding]:
    before_text = "\n".join(_stringify(c.result) for c in before_calls if c.ok)
    after_text = "\n".join(_stringify(c.result) for c in after_calls if c.ok)
    findings: list[Finding] = []
    for match in new_matches(before_text, after_text, other_tool_names=other_tool_names):
        findings.append(
            Finding(
                "SECURITY",
                "RESPONSE_INJECTION_PATTERN",
                tool=tool,
                path="/responses",
                message=(
                    f"tool responses now contain {match.category!r}-like content not present in the "
                    f"baseline's responses: {match.snippet!r}"
                ),
                before=None,
                after=match.snippet,
            )
        )
    return findings


def diff_behavior(
    tool: str,
    before_calls: list[CallRecord],
    after_calls: list[CallRecord],
    *,
    min_calls_for_error_rate: int = DEFAULT_MIN_CALLS_FOR_ERROR_RATE,
    error_rate_delta: float = DEFAULT_ERROR_RATE_DELTA,
    other_tool_names: frozenset[str] = frozenset(),
) -> list[Finding]:
    findings = compare_shapes(tool, infer_shape(before_calls), infer_shape(after_calls))
    findings.extend(
        diff_error_rate(
            tool, before_calls, after_calls, min_calls=min_calls_for_error_rate, delta_threshold=error_rate_delta
        )
    )
    findings.extend(diff_response_injection(tool, before_calls, after_calls, other_tool_names=other_tool_names))
    return findings


__all__ = ["compare_shapes", "diff_behavior", "diff_error_rate", "diff_response_injection", "infer_shape"]
