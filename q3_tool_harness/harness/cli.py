"""Command-line entry point. `harness <command>` or `python -m harness <command>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.diff.differ import diff_recordings
from harness.gate import DEFAULT_FAIL_ON, evaluate, load_accept_file, save_accept_file
from harness.recording import IntegrityError, load
from harness.replay import ReplayServer, UnrecordedCallError
from harness.report import FORMATTERS, render


def _write_output(path: str | None, text: str) -> None:
    if not text.endswith("\n"):
        text += "\n"
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _load_strict_or_exit2(path: str, label: str) -> object | int:
    """Returns the loaded Recording, or prints an error and returns the int 2 to propagate."""
    try:
        return load(path, strict=True)
    except IntegrityError as exc:
        print(f"error: {label} recording {path!r} failed integrity checks:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"error: could not load {label} recording {path!r}: {exc}", file=sys.stderr)
        return 2


def cmd_check(args: argparse.Namespace) -> int:
    baseline = _load_strict_or_exit2(args.baseline, "baseline")
    if isinstance(baseline, int):
        return baseline
    current = _load_strict_or_exit2(args.current, "current")
    if isinstance(current, int):
        return current

    fail_on = (
        frozenset(s.strip().upper() for s in args.fail_on.split(",") if s.strip()) if args.fail_on else DEFAULT_FAIL_ON
    )
    unknown = fail_on - {"SECURITY", "BREAKING", "WARN", "INFO"}
    if unknown or not fail_on:
        print(f"error: invalid --fail-on severities: {sorted(unknown)}", file=sys.stderr)
        return 2
    try:
        accept_entries = load_accept_file(args.accept) if args.accept else []
    except (OSError, ValueError) as exc:
        print(f"error: could not load accept file {args.accept!r}: {exc}", file=sys.stderr)
        return 2

    report = diff_recordings(baseline, current)  # type: ignore[arg-type]
    gate = evaluate(report, fail_on=fail_on, accept_entries=accept_entries)
    _write_output(args.output, render(args.format, report, gate))
    return 0 if gate.passed else 1


def cmd_accept(args: argparse.Namespace) -> int:
    baseline = _load_strict_or_exit2(args.baseline, "baseline")
    if isinstance(baseline, int):
        return baseline
    current = _load_strict_or_exit2(args.current, "current")
    if isinstance(current, int):
        return current

    report = diff_recordings(baseline, current)  # type: ignore[arg-type]
    save_accept_file(args.output, report.findings, reason=args.reason)
    print(f"wrote {len(report.findings)} accepted finding(s) to {args.output}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    baseline = load(args.baseline, strict=False)
    current = load(args.current, strict=False)
    problems = baseline.integrity_problems + current.integrity_problems
    report = diff_recordings(baseline, current)
    text = render(args.format, report, None)
    if problems:
        warning = "WARNING: integrity problems detected -- this diff is best-effort:\n"
        warning += "\n".join(f"  - {p}" for p in problems) + "\n\n"
        text = warning + text
    _write_output(args.output, text)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    recording = load(args.recording, strict=False)
    server = ReplayServer(recording)
    if not args.call:
        print(json.dumps(server.list_tools(), indent=2, default=str))
        return 0

    tool_name, args_json = args.call
    try:
        call_args = json.loads(args_json)
    except json.JSONDecodeError as exc:
        print(f"error: --call args must be JSON: {exc}", file=sys.stderr)
        return 2
    try:
        result = server.call(tool_name, call_args, strict=args.strict)
    except UnrecordedCallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": result.ok, "result": result.result, "error": result.error}, indent=2, default=str))
    return 0 if result.ok else 1


def cmd_record_demo(args: argparse.Namespace) -> int:
    from harness.demo import record_demo_session

    record_demo_session(args.output)
    print(f"wrote demo recording to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness", description="Record, diff, and CI-gate agent tool-use sessions.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Diff baseline vs current and pass/fail per policy. Exit 0/1/2.")
    check.add_argument("--baseline", required=True)
    check.add_argument("--current", required=True)
    check.add_argument(
        "--fail-on", default=",".join(sorted(DEFAULT_FAIL_ON)), help="Comma-separated severities that fail the gate."
    )
    check.add_argument("--accept", help="Path to an accept-file written by `harness accept`.")
    check.add_argument("--format", choices=sorted(FORMATTERS), default="text")
    check.add_argument("--output", help="Write the report here instead of stdout.")
    check.set_defaults(func=cmd_check)

    accept = sub.add_parser("accept", help="Snapshot the current findings as accepted (like snapshot-test approval).")
    accept.add_argument("--baseline", required=True)
    accept.add_argument("--current", required=True)
    accept.add_argument("-o", "--output", required=True)
    accept.add_argument("--reason", default="")
    accept.set_defaults(func=cmd_accept)

    diff = sub.add_parser("diff", help="Human-readable diff of two recordings. Always exits 0.")
    diff.add_argument("baseline")
    diff.add_argument("current")
    diff.add_argument("--format", choices=sorted(FORMATTERS), default="text")
    diff.add_argument("--output")
    diff.set_defaults(func=cmd_diff)

    replay = sub.add_parser("replay", help="Replay a recording as a fake tool server (no network).")
    replay.add_argument("recording")
    replay.add_argument("--call", nargs=2, metavar=("TOOL", "ARGS_JSON"))
    replay.add_argument("--strict", action="store_true", help="Raise on a (tool, args) pair never recorded.")
    replay.set_defaults(func=cmd_replay)

    demo = sub.add_parser("record-demo", help="Generate a sample recording from a toy agent, for README/demo use.")
    demo.add_argument("-o", "--output", default="demo.jsonl")
    demo.set_defaults(func=cmd_record_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


__all__ = ["build_parser", "main"]
