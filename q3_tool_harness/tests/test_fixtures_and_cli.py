"""Every fixture gives its expected verdict and exit code, through the real CLI entry point."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from harness.cli import main
from harness.recording import load

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "fixtures"
BASE = str(FX / "baseline.jsonl")


def _check(current: str, *extra: str) -> int:
    return main(["check", "--baseline", BASE, "--current", str(FX / current), "--fail-on", "SECURITY,BREAKING", *extra])


@pytest.mark.parametrize(
    ("fixture", "expected_exit"),
    [
        ("baseline.jsonl", 0),
        ("benign.jsonl", 0),
        ("breaking.jsonl", 1),
        ("renamed.jsonl", 1),
        ("rugpull.jsonl", 1),
        ("tampered.jsonl", 2),
    ],
)
def test_fixture_exit_codes(fixture: str, expected_exit: int, capsys: pytest.CaptureFixture[str]) -> None:
    assert _check(fixture) == expected_exit


def test_tampered_as_baseline_also_exits_2() -> None:
    assert main(["check", "--baseline", str(FX / "tampered.jsonl"), "--current", BASE]) == 2


def test_missing_file_exits_2() -> None:
    assert main(["check", "--baseline", BASE, "--current", str(FX / "nope.jsonl")]) == 2


def test_misspelled_severity_does_not_disable_gate():
    assert _check("rugpull.jsonl", "--fail-on", "SECURTIY") == 2


def test_empty_recording_is_cli_input_error(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert main(["check", "--baseline", str(empty), "--current", str(empty)]) == 2


def test_fixture_expected_rules(capsys: pytest.CaptureFixture[str]) -> None:
    def rules(name: str) -> set[str]:
        _check(name, "--format", "json")
        return {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}

    assert {"PARAM_ADDED_REQUIRED", "TYPE_CHANGED"} <= rules("breaking.jsonl")
    assert "PARAM_RENAMED" in rules("renamed.jsonl")
    assert {"DESC_EXFIL_PATTERN", "DESC_SENSITIVE_PATTERN", "ANNOTATION_CHANGED"} <= rules("rugpull.jsonl")
    assert rules("benign.jsonl") == {"DESC_REWORDED", "PARAM_ADDED_OPTIONAL"}


def test_midsession_fixture_has_two_versions_of_read_file() -> None:
    rec = load(FX / "midsession.jsonl", strict=True)
    versions = rec.tools[("local", "read_file")]
    assert len(versions) == 2
    assert versions[0].def_hash != versions[1].def_hash
    # calls after the re-listing reference the new hash
    assert rec.calls[-1].def_hash == versions[1].def_hash
    assert rec.calls[0].def_hash == versions[0].def_hash


def test_accept_flow(tmp_path: Path) -> None:
    accept = tmp_path / "accept.json"
    assert _check("rugpull.jsonl") == 1
    assert (
        main(
            [
                "accept",
                "--baseline",
                BASE,
                "--current",
                str(FX / "rugpull.jsonl"),
                "-o",
                str(accept),
                "--reason",
                "approved",
            ]
        )
        == 0
    )
    assert _check("rugpull.jsonl", "--accept", str(accept)) == 0  # accepted -> pass
    # the change moves again (different findings) -> the old acceptance does not cover it
    assert _check("breaking.jsonl", "--accept", str(accept)) == 1


def test_accepted_findings_are_still_shown(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    accept = tmp_path / "accept.json"
    main(["accept", "--baseline", BASE, "--current", str(FX / "rugpull.jsonl"), "-o", str(accept)])
    capsys.readouterr()
    _check("rugpull.jsonl", "--accept", str(accept))
    out = capsys.readouterr().out
    assert "DESC_EXFIL_PATTERN" in out and "accepted" in out


def test_output_file_and_formats(tmp_path: Path) -> None:
    for fmt in ("text", "json", "sarif", "markdown"):
        out = tmp_path / f"r.{fmt}"
        assert _check("rugpull.jsonl", "--format", fmt, "--output", str(out)) == 1
        assert out.read_text(encoding="utf-8").strip()


def test_diff_command_always_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["diff", BASE, str(FX / "rugpull.jsonl")]) == 0
    assert main(["diff", BASE, str(FX / "tampered.jsonl")]) == 0
    assert "integrity" in capsys.readouterr().out.lower()


def test_replay_cli(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["replay", BASE, "--call", "read_file", '{"path": "/etc/hosts"}', "--strict"])
    assert rc == 0
    assert "127.0.0.1" in capsys.readouterr().out
    assert main(["replay", BASE, "--call", "read_file", '{"path": "/nope"}', "--strict"]) == 1
    assert main(["replay", BASE, "--call", "read_file", "not json"]) == 2


def test_record_demo(tmp_path: Path) -> None:
    out = tmp_path / "demo.jsonl"
    assert main(["record-demo", "-o", str(out)]) == 0
    assert load(out, strict=True).integrity_problems == []


def test_python_dash_m_entrypoint() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "harness",
            "check",
            "--baseline",
            BASE,
            "--current",
            str(FX / "rugpull.jsonl"),
            "--fail-on",
            "SECURITY,BREAKING",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1


def test_fixtures_are_reproducible(tmp_path: Path) -> None:
    """Re-running make_fixtures.py must reproduce the committed files byte-for-byte."""
    before = {p.name: p.read_bytes() for p in FX.glob("*.jsonl")}
    subprocess.run([sys.executable, str(FX / "make_fixtures.py")], cwd=ROOT, check=True, capture_output=True)
    after = {p.name: p.read_bytes() for p in FX.glob("*.jsonl")}
    assert before == after
