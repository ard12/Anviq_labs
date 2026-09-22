from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from harness.diff.differ import Report
from harness.diff.types import Finding
from harness.gate import (
    DEFAULT_FAIL_ON,
    AcceptEntry,
    evaluate,
    finding_after_hash,
    load_accept_file,
    save_accept_file,
)


def _report(*findings: Finding) -> Report:
    return Report(baseline="b.jsonl", current="c.jsonl", findings=list(findings))


def test_default_fail_on_blocks_security_and_breaking():
    report = _report(
        Finding("SECURITY", "DESC_EXFIL_PATTERN", "/description", "m", tool="t"),
        Finding("BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "m", tool="t"),
    )
    result = evaluate(report, fail_on=DEFAULT_FAIL_ON)
    assert not result.passed
    assert len(result.blocking) == 2


def test_warn_and_info_never_block_by_default():
    report = _report(
        Finding("WARN", "DESC_SEMANTIC_CHANGE", "/description", "m", tool="t"),
        Finding("INFO", "DESC_REWORDED", "/description", "m", tool="t"),
    )
    result = evaluate(report, fail_on=DEFAULT_FAIL_ON)
    assert result.passed
    assert result.blocking == []


def test_custom_fail_on_can_include_warn():
    report = _report(Finding("WARN", "DEFAULT_CHANGED", "/inputSchema/properties/x/default", "m", tool="t"))
    result = evaluate(report, fail_on=frozenset({"WARN"}))
    assert not result.passed


def test_accept_file_suppresses_matching_finding():
    finding = Finding(
        "BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "m", tool="t", before={"a": 1}, after=None
    )
    entry = AcceptEntry(
        tool="t", rule_id="PARAM_REMOVED", path="/inputSchema/properties/x", after_hash=finding_after_hash(finding)
    )
    result = evaluate(_report(finding), accept_entries=[entry])
    assert result.passed
    assert result.accepted == [finding]
    assert result.blocking == []


def test_accept_file_does_not_suppress_when_after_value_changes():
    old_finding = Finding("BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "m", tool="t", after="v1")
    new_finding = Finding("BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "m", tool="t", after="v2")
    entry = AcceptEntry(
        tool="t", rule_id="PARAM_REMOVED", path="/inputSchema/properties/x", after_hash=finding_after_hash(old_finding)
    )
    result = evaluate(_report(new_finding), accept_entries=[entry])
    assert not result.passed  # the change moved again, so the old acceptance no longer applies
    assert result.blocking == [new_finding]


def test_accept_file_expired_entry_does_not_suppress():
    finding = Finding("BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "m", tool="t", after="v1")
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date().isoformat()
    entry = AcceptEntry(
        tool="t",
        rule_id="PARAM_REMOVED",
        path="/inputSchema/properties/x",
        after_hash=finding_after_hash(finding),
        expires=yesterday,
    )
    result = evaluate(_report(finding), accept_entries=[entry])
    assert not result.passed


def test_save_and_load_accept_file_roundtrip(tmp_path: Path):
    findings = [
        Finding("BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "m", tool="t", after=None),
        Finding("SECURITY", "DESC_EXFIL_PATTERN", "/description", "m", tool="t", after="new text"),
    ]
    out = tmp_path / "accept.json"
    save_accept_file(out, findings, reason="intentional breaking change for v2")

    entries = load_accept_file(out)
    assert len(entries) == 2
    assert all(e.reason == "intentional breaking change for v2" for e in entries)

    result = evaluate(_report(*findings), accept_entries=entries)
    assert result.passed
    assert len(result.accepted) == 2
