"""Cross-platform task runner (no `make` on Windows). CI calls the same commands.

    python tasks.py test        # every Python test suite that exists + go tests if Go is installed
    python tasks.py demo-q3     # drift gate on the fixtures: benign passes, rug-pull fails
    python tasks.py demo-q4     # mid-session rug-pull caught by the proxy
    python tasks.py bench       # proxy overhead p50/p99
    python tasks.py eval-q2     # semantic-cache precision/recall table
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY_SUITES = ["schema", "q1_lru_ttl", "q2_semantic_cache", "q3_tool_harness", "q4_trust_layer/control"]
GO_MODULE = ROOT / "q4_trust_layer" / "proxy"


def run(cmd: list[str], cwd: Path = ROOT) -> int:
    print(f"\n$ {' '.join(cmd)}   (in {cwd.relative_to(ROOT) or '.'})", flush=True)
    return subprocess.call(cmd, cwd=cwd)


def has_tests(d: Path) -> bool:
    return any(d.rglob("test_*.py"))


def task_test() -> int:
    rc = 0
    for suite in PY_SUITES:
        d = ROOT / suite
        if d.is_dir() and has_tests(d):
            rc |= run([sys.executable, "-m", "pytest", "-q"], cwd=d)
        else:
            print(f"-- skip {suite}: no tests yet")
    if (GO_MODULE / "go.mod").exists():
        if shutil.which("go"):
            rc |= run(["go", "test", "./..."], cwd=GO_MODULE)
        else:
            print("-- skip Go tests: `go` not on PATH (winget install GoLang.Go)")
    return rc


def task_demo_q3() -> int:
    fx = ROOT / "q3_tool_harness" / "fixtures"
    check = [sys.executable, "-m", "harness", "check", "--fail-on", "SECURITY,BREAKING"]
    benign = run(check + ["--baseline", str(fx / "baseline.jsonl"), "--current", str(fx / "benign.jsonl")],
                 cwd=ROOT / "q3_tool_harness")
    rugpull = run(check + ["--baseline", str(fx / "baseline.jsonl"), "--current", str(fx / "rugpull.jsonl")],
                  cwd=ROOT / "q3_tool_harness")
    print(f"\nbenign exit={benign} (want 0), rugpull exit={rugpull} (want 1)")
    return 0 if (benign == 0 and rugpull == 1) else 1


def task_demo_q4() -> int:
    return run([sys.executable, "demo.py"], cwd=ROOT / "q4_trust_layer")


def task_bench() -> int:
    if not shutil.which("go"):
        print("`go` not on PATH (winget install GoLang.Go)")
        return 1
    return run(["go", "run", "./cmd/loadgen"], cwd=GO_MODULE)


def task_eval_q2() -> int:
    return run([sys.executable, "eval.py"], cwd=ROOT / "q2_semantic_cache")


TASKS = {
    "test": task_test,
    "demo-q3": task_demo_q3,
    "demo-q4": task_demo_q4,
    "bench": task_bench,
    "eval-q2": task_eval_q2,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in TASKS:
        print(__doc__)
        sys.exit(2)
    sys.exit(TASKS[sys.argv[1]]())
