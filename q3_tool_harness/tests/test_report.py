from __future__ import annotations

import json

from harness.diff.differ import Report
from harness.diff.types import Finding
from harness.gate import DEFAULT_FAIL_ON, evaluate
from harness.report import render_json, render_markdown, render_sarif, render_text

FINDINGS = [
    Finding("SECURITY", "DESC_EXFIL_PATTERN", "/description", "leaks data", tool="read_file"),
    Finding("BREAKING", "PARAM_REMOVED", "/inputSchema/properties/x", "removed x", tool="read_file"),
    Finding("WARN", "DEFAULT_CHANGED", "/inputSchema/properties/y/default", "default changed", tool="read_file"),
    Finding("INFO", "DESC_REWORDED", "/description", "reworded", tool="search_web"),
]
REPORT = Report(baseline="baseline.jsonl", current="current.jsonl", findings=FINDINGS)


def test_render_text_lists_every_finding():
    text = render_text(REPORT)
    for f in FINDINGS:
        assert f.rule_id in text
        assert f.message in text


def test_render_text_empty_report():
    empty = Report(baseline="a", current="b", findings=[])
    assert "No findings" in render_text(empty)


def test_render_json_round_trips():
    payload = json.loads(render_json(REPORT))
    assert payload["baseline"] == "baseline.jsonl"
    assert len(payload["findings"]) == 4
    assert {f["rule_id"] for f in payload["findings"]} == {f.rule_id for f in FINDINGS}


def test_render_json_includes_gate_verdict():
    gate = evaluate(REPORT, fail_on=DEFAULT_FAIL_ON)
    payload = json.loads(render_json(REPORT, gate))
    assert payload["gate"]["passed"] is False
    assert len(payload["gate"]["blocking"]) == 2  # SECURITY + BREAKING


def test_render_sarif_structure_is_valid():
    sarif = json.loads(render_sarif(REPORT))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    rule_ids_declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids_declared == {f.rule_id for f in FINDINGS}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids_declared
        assert result["level"] in {"error", "warning", "note", "none"}
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "current.jsonl"

    level_by_rule = {r["ruleId"]: r["level"] for r in run["results"]}
    assert level_by_rule["DESC_EXFIL_PATTERN"] == "error"  # SECURITY
    assert level_by_rule["PARAM_REMOVED"] == "error"  # BREAKING
    assert level_by_rule["DEFAULT_CHANGED"] == "warning"  # WARN
    assert level_by_rule["DESC_REWORDED"] == "note"  # INFO


def test_render_markdown_has_summary_table_and_findings():
    md = render_markdown(REPORT)
    assert "| Severity | Count |" in md
    assert "PARAM_REMOVED" in md
    assert md.count("|") > 0
