"""The policy table: every severity x risk-class cell, risk-class derivation, and file validation."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from control.policy import RISK_CLASSES, SEVERITIES, PolicyError, PolicyTable, derive_risk_class

# DESIGN.md section 0.1, written out by hand so a wrong default_policy.json cannot pass by agreeing with itself.
EXPECTED = {
    "NONE": {"read_only": "resume", "side_effecting": "resume", "destructive": "resume"},
    "INFO": {"read_only": "resume", "side_effecting": "resume", "destructive": "resume"},
    "WARN": {"read_only": "warn", "side_effecting": "warn", "destructive": "suspend"},
    "BREAKING": {"read_only": "suspend", "side_effecting": "suspend", "destructive": "suspend"},
    "SECURITY": {"read_only": "quarantine", "side_effecting": "quarantine", "destructive": "quarantine"},
}


@pytest.mark.parametrize("severity", SEVERITIES)
@pytest.mark.parametrize("risk_class", RISK_CLASSES)
def test_default_matrix_cell(severity: str, risk_class: str) -> None:
    assert PolicyTable.default().decide(severity, risk_class) == EXPECTED[severity][risk_class]


def test_expected_table_covers_every_cell() -> None:
    assert set(EXPECTED) == set(SEVERITIES)
    assert all(set(row) == set(RISK_CLASSES) for row in EXPECTED.values())


@pytest.mark.parametrize(
    ("annotations", "expected"),
    [
        ({"readOnlyHint": True}, "read_only"),
        ({"readOnlyHint": True, "destructiveHint": False}, "read_only"),
        ({"destructiveHint": True}, "destructive"),
        ({"readOnlyHint": False, "destructiveHint": True}, "destructive"),
        ({"readOnlyHint": True, "destructiveHint": True}, "read_only"),  # readOnly is checked first (DESIGN)
        ({"readOnlyHint": False, "destructiveHint": False}, "side_effecting"),
        ({}, "side_effecting"),
        ({"readOnlyHint": "true"}, "side_effecting"),  # only a real boolean counts
        ({"readOnlyHint": 1}, "side_effecting"),
        (None, "side_effecting"),
    ],
)
def test_risk_class_from_annotations(annotations: Any, expected: str) -> None:
    tool = {"name": "t"} if annotations is None else {"name": "t", "annotations": annotations}
    assert derive_risk_class(tool) == expected


def test_unannotated_tool_is_side_effecting() -> None:
    assert derive_risk_class({"name": "t"}) == "side_effecting"
    assert derive_risk_class({"name": "t", "annotations": "nonsense"}) == "side_effecting"


def test_operator_override_beats_annotation() -> None:
    policy = PolicyTable.from_dict(
        {
            "matrix": _default_matrix(),
            "risk_overrides": [{"server": "fs", "tool": "read_file", "risk_class": "destructive"}],
        }
    )
    annotated_read_only = {"name": "read_file", "annotations": {"readOnlyHint": True}}
    assert policy.risk_class("fs", "read_file", annotated_read_only) == "destructive"
    assert policy.risk_class("other", "read_file", annotated_read_only) == "read_only"  # per (server, tool)


def _default_matrix() -> dict[str, dict[str, str]]:
    return copy.deepcopy(EXPECTED)


def test_custom_policy_file_changes_the_verdict(tmp_path: Path) -> None:
    matrix = _default_matrix()
    matrix["WARN"]["read_only"] = "suspend"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"matrix": matrix}), encoding="utf-8")
    policy = PolicyTable.from_file(path)
    assert policy.decide("WARN", "read_only") == "suspend"
    assert policy.decide("WARN", "side_effecting") == "warn"
    assert policy.risk_overrides == {}  # optional key defaults to empty


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.pop("SECURITY"),  # missing row
        lambda m: m["WARN"].pop("destructive"),  # missing cell
        lambda m: m["WARN"].update(read_only="explode"),  # unknown verdict
        lambda m: m.update(CRITICAL={}),  # unknown severity row
        lambda m: m["INFO"].update(exotic="resume"),  # unknown risk class
    ],
)
def test_invalid_policy_is_rejected(mutate: Any) -> None:
    matrix = _default_matrix()
    mutate(matrix)
    with pytest.raises(PolicyError):
        PolicyTable.from_dict({"matrix": matrix})


def test_invalid_override_and_bad_json_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        PolicyTable.from_dict({"matrix": _default_matrix(), "risk_overrides": [{"server": "fs", "tool": "x"}]})
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicyError):
        PolicyTable.from_file(bad)


def test_cli_rejects_a_bad_policy_file(tmp_path: Path) -> None:
    from control.__main__ import main

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"matrix": {}}), encoding="utf-8")
    assert main(["--policy", str(bad), "--port", "0"]) == 2  # exits before binding any socket
