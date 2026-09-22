"""Runs the Q3 differ on ONE tool's old_def -> new_def, and recomputes `def_hash` the way Q3/Go do.

Deliberately thin: every rule (schema layer, description layer, annotation layer) lives in `harness`.
This mirrors what `harness/diff/differ.py::diff_recordings` does per tool, minus the recording plumbing,
because a change report is one pair of definitions, not two whole recordings.
"""

from __future__ import annotations

from typing import Any

from harness._canonical import tool_hash
from harness.diff import description_diff, schema_diff
from harness.diff.types import SEVERITY_ORDER, Finding


def compute_hash(tool_def: dict[str, Any]) -> str:
    """`sha256:...` of the normalized definition; the same function the Go proxy ports."""
    return tool_hash(tool_def)


def diff_definitions(tool: str, old_def: dict[str, Any], new_def: dict[str, Any]) -> list[Finding]:
    """Schema + annotation findings, then description findings, for one tool.

    `other_tool_names` stays empty: a change report carries one tool only, so the "description now mentions
    another tool" rule (DESC_CROSS_TOOL_REFERENCE) cannot fire here (see DECISIONS Q4-control-09)."""
    findings = schema_diff.diff_tool(tool, old_def, new_def)
    findings.extend(
        description_diff.diff_description(
            tool,
            old_def.get("description", ""),
            new_def.get("description", ""),
            other_tool_names=frozenset(),
        )
    )
    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Worst first, then by path, so the first finding is the one to quote in the verdict's reason."""
    rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (rank.get(f.severity, len(rank)), f.path, f.rule_id))


def highest_severity(findings: list[Finding]) -> str:
    """'SECURITY' > 'BREAKING' > 'WARN' > 'INFO'; 'NONE' when there are no findings."""
    present = {f.severity for f in findings}
    for severity in SEVERITY_ORDER:
        if severity in present:
            return severity
    return "NONE"
