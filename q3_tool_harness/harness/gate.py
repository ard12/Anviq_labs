"""Turns a `Report` into a pass/fail decision, with an accept-file for intentional changes.

This is the "usable as a CI pass/fail check, not just a diff dump" part of the brief: `evaluate()`
is what `harness check` calls, and it is deliberately separate from `diff_recordings()` so Q4 (or
any other caller) can reuse the differ without inheriting our policy.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from harness._canonical import sha256_hex
from harness.diff.differ import Report
from harness.diff.types import Finding

DEFAULT_FAIL_ON: frozenset[str] = frozenset({"SECURITY", "BREAKING"})


def finding_after_hash(finding: Finding) -> str:
    """Stable hash of a finding's `after` value, used as part of the accept-file key so an
    accepted finding stops matching the moment the underlying change moves again."""
    try:
        return sha256_hex(finding.after)
    except TypeError:
        # `after` holds something canonical_json can't serialize (e.g. a float NaN slipped in
        # from a response payload) -- fall back to a hash of its repr rather than crashing.
        return sha256_hex(repr(finding.after))


@dataclass(frozen=True, slots=True)
class AcceptEntry:
    tool: str
    rule_id: str
    path: str
    after_hash: str
    reason: str = ""
    expires: str | None = None  # ISO date; an expired entry stops suppressing its finding.

    def matches(self, finding: Finding, *, today: date | None = None) -> bool:
        if (finding.tool or "", finding.rule_id, finding.path) != (self.tool, self.rule_id, self.path):
            return False
        if finding_after_hash(finding) != self.after_hash:
            return False
        if self.expires:
            today = today or datetime.now(UTC).date()
            if date.fromisoformat(self.expires) < today:
                return False
        return True


def load_accept_file(path: str | Path) -> list[AcceptEntry]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("accepted", data) if isinstance(data, dict) else data
    return [AcceptEntry(**e) for e in entries]


def save_accept_file(path: str | Path, findings: list[Finding], *, reason: str = "") -> None:
    entries = [
        {
            "tool": f.tool or "",
            "rule_id": f.rule_id,
            "path": f.path,
            "after_hash": finding_after_hash(f),
            "reason": reason,
            "expires": None,
        }
        for f in findings
    ]
    Path(path).write_text(json.dumps({"accepted": entries}, indent=2) + "\n", encoding="utf-8")


@dataclass(slots=True)
class GateResult:
    passed: bool
    blocking: list[Finding] = field(default_factory=list)
    accepted: list[Finding] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)


def evaluate(
    report: Report,
    *,
    fail_on: frozenset[str] = DEFAULT_FAIL_ON,
    accept_entries: Sequence[AcceptEntry] = (),
) -> GateResult:
    blocking: list[Finding] = []
    accepted: list[Finding] = []
    today = datetime.now(UTC).date()
    for finding in report.findings:
        if finding.severity not in fail_on:
            continue
        entry = next((e for e in accept_entries if e.matches(finding, today=today)), None)
        if entry is not None:
            accepted.append(finding)
        else:
            blocking.append(finding)
    return GateResult(passed=not blocking, blocking=blocking, accepted=accepted, all_findings=list(report.findings))


__all__ = [
    "DEFAULT_FAIL_ON",
    "AcceptEntry",
    "GateResult",
    "evaluate",
    "finding_after_hash",
    "load_accept_file",
    "save_accept_file",
]
