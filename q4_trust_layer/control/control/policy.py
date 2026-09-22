"""The policy table: (highest finding severity, risk class) -> verdict. Data, not code.

The table lives in a JSON file (`default_policy.json` ships with the package; `--policy` points at another).
Changing what the control plane does about, say, a WARN on a destructive tool is an edit to that file.
The file is validated completely at load time, so a typo fails at startup, never in the middle of an incident.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

# Rows: "NONE" means the differ found nothing. The other four are harness severities.
SEVERITIES = ("NONE", "INFO", "WARN", "BREAKING", "SECURITY")
RISK_CLASSES = ("read_only", "side_effecting", "destructive")
VERDICTS = ("resume", "warn", "suspend", "quarantine")


class PolicyError(ValueError):
    """The policy file is missing a cell, has an unknown value, or is not valid JSON."""


def derive_risk_class(tool_def: dict[str, Any]) -> str:
    """DESIGN section 0.1 step 3 (same rule as the proxy): readOnlyHint true -> read_only; else
    destructiveHint true -> destructive; anything else, including unannotated, -> side_effecting.

    `is True` (not truthiness) on purpose: the string "false" or the number 1 must not count as a hint."""
    annotations = tool_def.get("annotations")
    if isinstance(annotations, dict):
        if annotations.get("readOnlyHint") is True:
            return "read_only"
        if annotations.get("destructiveHint") is True:
            return "destructive"
    return "side_effecting"


@dataclass(frozen=True)
class PolicyTable:
    # severity -> risk class -> verdict
    matrix: dict[str, dict[str, str]]
    # (server, tool) -> risk class chosen by an operator, beating the annotation-derived class
    risk_overrides: dict[tuple[str, str], str]

    def risk_class(self, server: str, tool: str, tool_def: dict[str, Any]) -> str:
        return self.risk_overrides.get((server, tool)) or derive_risk_class(tool_def)

    def decide(self, severity: str, risk_class: str) -> str:
        return self.matrix[severity][risk_class]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PolicyTable:
        matrix_raw = raw.get("matrix")
        if not isinstance(matrix_raw, dict):
            raise PolicyError("policy: 'matrix' must be an object")
        extra_rows = set(matrix_raw) - set(SEVERITIES)
        if extra_rows:
            raise PolicyError(f"policy: unknown severity row(s) {sorted(extra_rows)}; allowed: {list(SEVERITIES)}")
        matrix: dict[str, dict[str, str]] = {}
        for severity in SEVERITIES:
            row = matrix_raw.get(severity)
            if not isinstance(row, dict):
                raise PolicyError(f"policy: missing row {severity!r}")
            extra_cols = set(row) - set(RISK_CLASSES)
            if extra_cols:
                raise PolicyError(f"policy: row {severity!r} has unknown risk class(es) {sorted(extra_cols)}")
            matrix[severity] = {}
            for risk in RISK_CLASSES:
                verdict = row.get(risk)
                if verdict not in VERDICTS:
                    raise PolicyError(f"policy: cell [{severity}][{risk}] is {verdict!r}; allowed: {list(VERDICTS)}")
                matrix[severity][risk] = verdict

        overrides: dict[tuple[str, str], str] = {}
        for i, item in enumerate(raw.get("risk_overrides", [])):
            if not isinstance(item, dict):
                raise PolicyError(f"policy: risk_overrides[{i}] must be an object")
            server, tool, risk = item.get("server"), item.get("tool"), item.get("risk_class")
            if not (isinstance(server, str) and isinstance(tool, str) and server and tool):
                raise PolicyError(f"policy: risk_overrides[{i}] needs non-empty 'server' and 'tool'")
            if risk not in RISK_CLASSES:
                raise PolicyError(f"policy: risk_overrides[{i}].risk_class is {risk!r}; allowed: {list(RISK_CLASSES)}")
            overrides[(server, tool)] = risk
        return cls(matrix=matrix, risk_overrides=overrides)

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyTable:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy file {path} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError(f"policy file {path}: top level must be an object")
        return cls.from_dict(raw)

    @classmethod
    def default(cls) -> PolicyTable:
        text = resources.files("control").joinpath("default_policy.json").read_text(encoding="utf-8")
        return cls.from_dict(json.loads(text))
