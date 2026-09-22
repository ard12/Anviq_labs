"""`diff_recordings`: the single entry point Q4 (and `harness check`/`harness diff`) call.

Combines the three layers -- tool presence, schema+description (skipped when `def_hash` is
unchanged: the fast path), and behavior -- into one flat `Report`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from harness.diff import behavior_diff, description_diff, schema_diff
from harness.diff.description_diff import Embedder, Judge
from harness.diff.types import SEVERITY_ORDER, Finding
from harness.recording import Recording


@dataclass(slots=True)
class Report:
    baseline: str
    current: str
    findings: list[Finding] = field(default_factory=list)

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def max_severity(self) -> str | None:
        present = {f.severity for f in self.findings}
        for sev in SEVERITY_ORDER:
            if sev in present:
                return sev
        return None

    def sorted_findings(self) -> list[Finding]:
        rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
        return sorted(self.findings, key=lambda f: (rank.get(f.severity, len(rank)), f.tool or "", f.path))


def diff_recordings(
    baseline: Recording,
    current: Recording,
    *,
    embedder: Embedder | None = None,
    judge: Judge | None = None,
    semantic_threshold: float = description_diff.DEFAULT_SEMANTIC_THRESHOLD,
    min_calls_for_error_rate: int = behavior_diff.DEFAULT_MIN_CALLS_FOR_ERROR_RATE,
    error_rate_delta: float = behavior_diff.DEFAULT_ERROR_RATE_DELTA,
) -> Report:
    """Diff every tool seen in either recording. Q4 imports this directly."""
    all_keys = sorted(baseline.tool_keys() | current.tool_keys())
    all_names = frozenset(name for _server, name in all_keys)
    findings: list[Finding] = []

    for server, name in all_keys:
        before = baseline.latest_tool(server, name)
        after = current.latest_tool(server, name)
        other_names = all_names - {name}

        if before is None and after is not None:
            findings.append(
                Finding(
                    "INFO",
                    "TOOL_ADDED",
                    tool=name,
                    path="/",
                    message=f"tool {name!r} (server {server!r}) is new in this recording",
                    before=None,
                    after=after.tool,
                )
            )
        elif after is None and before is not None:
            findings.append(
                Finding(
                    "BREAKING",
                    "TOOL_REMOVED",
                    tool=name,
                    path="/",
                    message=f"tool {name!r} (server {server!r}) is no longer offered",
                    before=before.tool,
                    after=None,
                )
            )
        elif before is not None and after is not None:
            # Every distinct definition seen in the current recording is checked, not just the last:
            # a tool that turns malicious mid-session and reverts before the session ends would
            # otherwise pass. Identical def_hash to the baseline is the fast path (nothing to diff).
            seen_hashes: set[str] = set()
            seen_findings: set[str] = set()
            for version in current.tools[(server, name)]:
                if version.def_hash == before.def_hash or version.def_hash in seen_hashes:
                    continue
                seen_hashes.add(version.def_hash)
                version_findings = schema_diff.diff_tool(name, before.tool, version.tool)
                version_findings.extend(
                    description_diff.diff_description(
                        name,
                        before.tool.get("description", ""),
                        version.tool.get("description", ""),
                        other_tool_names=other_names,
                        embedder=embedder,
                        judge=judge,
                        semantic_threshold=semantic_threshold,
                    )
                )
                for finding in version_findings:
                    key = json.dumps([finding.rule_id, finding.path, finding.message], sort_keys=True)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        findings.append(finding)

        # Behavior can drift even when the definition hasn't changed at all, so this always runs.
        findings.extend(
            behavior_diff.diff_behavior(
                name,
                baseline.calls_for(server, name),
                current.calls_for(server, name),
                min_calls_for_error_rate=min_calls_for_error_rate,
                error_rate_delta=error_rate_delta,
                other_tool_names=other_names,
            )
        )

    return Report(baseline=baseline.path, current=current.path, findings=findings)


__all__ = ["Report", "diff_recordings"]
