"""Renders a `Report`/`GateResult` as text, JSON, SARIF 2.1.0, or Markdown."""

from __future__ import annotations

import json
from typing import Any

from harness.diff.differ import Report
from harness.diff.types import SEVERITY_ORDER
from harness.gate import GateResult

_SARIF_LEVEL = {"SECURITY": "error", "BREAKING": "error", "WARN": "warning", "INFO": "note"}


def render_text(report: Report, gate: GateResult | None = None) -> str:
    lines: list[str] = []
    findings = report.sorted_findings()
    if not findings:
        lines.append("No findings.")
    for f in findings:
        tag = "accepted" if gate and f in gate.accepted else None
        suffix = f"  [{tag}]" if tag else ""
        lines.append(f"[{f.severity:8}] {f.rule_id:28} {f.tool or '-':16} {f.path}{suffix}")
        lines.append(f"           {f.message}")
    lines.append("")
    lines.append(f"{len(findings)} finding(s) across {report.baseline} -> {report.current}")
    if gate is not None:
        verdict = "PASS" if gate.passed else "FAIL"
        lines.append(f"gate: {verdict} -- {len(gate.blocking)} blocking, {len(gate.accepted)} accepted-but-shown")
    return "\n".join(lines)


def render_json(report: Report, gate: GateResult | None = None) -> str:
    payload: dict[str, Any] = {
        "baseline": report.baseline,
        "current": report.current,
        "findings": [f.to_dict() for f in report.sorted_findings()],
    }
    if gate is not None:
        payload["gate"] = {
            "passed": gate.passed,
            "blocking": [f.to_dict() for f in gate.blocking],
            "accepted": [f.to_dict() for f in gate.accepted],
        }
    return json.dumps(payload, indent=2, default=str)


def render_sarif(report: Report) -> str:
    findings = report.sorted_findings()
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": rule_id.replace("_", " ").title()},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(next(f.severity for f in findings if f.rule_id == rule_id), "warning")
            },
        }
        for rule_id in rule_ids
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.severity}] {f.message}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.current},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": f"{f.tool or ''}{f.path}"}],
                }
            ],
        }
        for f in findings
    ]
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "harness", "informationUri": "https://anviq.local/harness", "rules": rules}
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_markdown(report: Report, gate: GateResult | None = None) -> str:
    findings = report.sorted_findings()
    lines = ["# Tool-use harness drift report", ""]
    if gate is not None:
        lines.append(f"**Verdict: {'PASS' if gate.passed else 'FAIL'}**")
        lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            lines.append(f"| {sev} | {count} |")
    lines.append("")
    if findings:
        lines.append("| Severity | Rule | Tool | Path | Message |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity} | `{f.rule_id}` | {f.tool or '-'} | `{f.path}` | {msg} |")
    else:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"


FORMATTERS = {
    "text": render_text,
    "json": render_json,
    "sarif": lambda r, g=None: render_sarif(r),
    "markdown": render_markdown,
}


def render(fmt: str, report: Report, gate: GateResult | None = None) -> str:
    if fmt not in FORMATTERS:
        raise ValueError(f"unknown format {fmt!r}; choose one of {sorted(FORMATTERS)}")
    return FORMATTERS[fmt](report, gate)


__all__ = ["render", "render_json", "render_markdown", "render_sarif", "render_text"]
