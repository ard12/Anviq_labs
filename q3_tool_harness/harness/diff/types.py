"""`Finding`: the one data type every rule in this package produces.

Shape matches `$defs/finding` in `schema/recording.schema.json` (kept in sync by hand, since a
`Finding` is a report-time object, not a recording event -- it is only wire-shaped like the
schema's finding so `harness/gate.py` can drop it straight into a `policy_decision` event
without translation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["BREAKING", "SECURITY", "WARN", "INFO"]

# Highest-impact first. Used to sort report output and to compare against --fail-on.
SEVERITY_ORDER: tuple[Severity, ...] = ("SECURITY", "BREAKING", "WARN", "INFO")


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    rule_id: str
    path: str
    message: str
    tool: str | None = None
    before: Any = None
    after: Any = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "severity": self.severity,
            "rule_id": self.rule_id,
            "path": self.path,
            "message": self.message,
        }
        if self.tool is not None:
            d["tool"] = self.tool
        if self.before is not None:
            d["before"] = self.before
        if self.after is not None:
            d["after"] = self.after
        return d


__all__ = ["SEVERITY_ORDER", "Finding", "Severity"]
