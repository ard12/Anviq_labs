#!/usr/bin/env python3
"""Q4 end-to-end demo: a mid-session rug-pull, caught by the real Go proxy and the real Python control plane.

    python tasks.py demo-q4        (or, from q4_trust_layer/:  python demo.py [--keep])

Needs only Python (+ `pip install jsonschema pytest`, the harness's dependencies) and Go. It starts four things on
free localhost ports and stops them all when it ends (success, failure or Ctrl-C):

    mock tool server (Python)  <--  proxy (Go binary, built here)  -->  control plane (Python)
                                       ^
                                       |  the scripted "agents" talk only to the proxy

Exit code 0 means every expected outcome happened; 1 means at least one did not; 130 means Ctrl-C.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROXY_DIR = HERE / "proxy"
CONTROL_DIR = HERE / "control"
Q3_DIR = HERE.parent / "q3_tool_harness"

SERVER = "fs"  # the name the proxy knows the mock tool server by (/servers/fs)
POLL_TIMEOUT_S = 10.0  # bound for "wait for the async verdict + the ~1 s quarantine poll"
WIDTH = 100

# -- console helpers -----------------------------------------------------------------------------------------


def clip(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def act(title: str) -> None:
    print(f"\n{'=' * WIDTH}\n{title}\n{'=' * WIDTH}")


def say(text: str = "") -> None:
    print(f"  {text}" if text else "")


def short(h: str) -> str:
    return h[:14] + ".." if h else "-"


@dataclass
class Checker:
    """Collects the expected outcomes. Every `expect` prints its verdict inline; the demo exits 1 if any failed."""

    passed: int = 0
    failures: list[str] = field(default_factory=list)

    def expect(self, ok: bool, message: str) -> bool:
        print(f"  [{'ok' if ok else 'FAIL'}] {message}")
        if ok:
            self.passed += 1
        else:
            self.failures.append(message)
        return ok


# -- child processes -----------------------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def port_is_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


@dataclass
class Child:
    name: str
    port: int
    popen: subprocess.Popen[bytes]
    log_path: Path
    log_file: Any
    graceful: bool  # ask nicely first (Ctrl-Break/SIGINT) so the proxy drains its audit-log queue

    def stop(self) -> None:
        p = self.popen
        try:
            if p.poll() is None and self.graceful:
                try:
                    p.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
                    p.wait(timeout=5)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
        finally:
            self.log_file.close()

    def log_tail(self, n: int = 15) -> str:
        try:
            return "\n".join(self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
        except OSError:
            return "(no log)"


class Stack:
    """Everything the demo starts. `stop_all` is idempotent and runs from a `finally`."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.children: list[Child] = []

    def start(
        self,
        name: str,
        cmd: list[str],
        *,
        port: int,
        cwd: Path,
        env: dict[str, str] | None = None,
        graceful: bool = False,
    ) -> Child:
        log_path = self.workdir / "logs" / f"{name}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "wb")  # noqa: SIM115 (kept open for the child's lifetime, closed in Child.stop)
        # New process group on Windows: Ctrl-C in this console then reaches only the demo, which stops the children
        # itself; and it lets us send the proxy a Ctrl-Break for a graceful drain.
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        popen = subprocess.Popen(  # noqa: S603
            cmd,
            cwd=cwd,
            env={**os.environ, **(env or {})},
            stdout=log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=flags,
        )
        child = Child(name, port, popen, log_path, log_file, graceful)
        self.children.append(child)
        return child

    def wait_ready(self, child: Child, ready: Callable[[], bool], timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if child.popen.poll() is not None:
                raise RuntimeError(f"{child.name} exited early (code {child.popen.returncode}):\n{child.log_tail()}")
            try:
                if ready():
                    return
            except OSError:  # connection refused while the child is still starting
                pass
            time.sleep(0.1)
        raise RuntimeError(f"{child.name} not ready after {timeout}s:\n{child.log_tail()}")

    def stop_all(self) -> None:
        for child in reversed(self.children):
            try:
                child.stop()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 (keep stopping the others, even on a 2nd Ctrl-C)
                print(f"  warning: could not stop {child.name}: {exc!r}", file=sys.stderr)


# -- talking to things over HTTP -------------------------------------------------------------------------------

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route localhost via a system proxy


def http_json(method: str, url: str, body: Any = None, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})}
    )
    try:
        with _OPENER.open(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null")


class Agent:
    """A scripted agent: it only ever talks to the proxy, exactly like a real MCP client would."""

    def __init__(self, proxy_base: str, session_id: str) -> None:
        self.session_id = session_id
        self.url = f"{proxy_base}/servers/{SERVER}"
        self.headers = {"X-Session-Id": session_id, "X-Agent-Id": f"demo-agent/{session_id}"}
        self._next_id = 0

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {}}
        _status, body = http_json("POST", self.url, payload, self.headers)
        return body  # type: ignore[no-any-return]

    def list_tools(self) -> list[dict[str, Any]]:
        return self.rpc("tools/list")["result"]["tools"]  # type: ignore[no-any-return]

    def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.rpc("tools/call", {"name": tool, "arguments": arguments})


def reason_of(resp: dict[str, Any]) -> str:
    """'OK' for a normal result, else the proxy's machine-readable data.reason (e.g. TOOL_QUARANTINED)."""
    if "error" in resp:
        return str((resp["error"].get("data") or {}).get("reason", "ERROR"))
    return "OK"


def describe(resp: dict[str, Any]) -> str:
    if "error" in resp:
        err = resp["error"]
        return f"BLOCKED  code={err['code']}  reason={reason_of(resp)}"
    return f"OK       {clip(resp['result']['content'][0]['text'], 60)!r}"


def poll_until(fn: Callable[[], Any], timeout: float = POLL_TIMEOUT_S, interval: float = 0.25) -> Any:
    """Call `fn` until it returns something truthy or the (bounded) timeout passes. Returns that value or None."""
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


# -- setup ------------------------------------------------------------------------------------------------------


def find_go() -> str | None:
    found = shutil.which("go")
    if found:
        return found
    for candidate in (r"C:\Program Files\Go\bin\go.exe", "/usr/local/go/bin/go"):
        if Path(candidate).exists():
            return candidate
    return None


def build_proxy(go: str, out: Path) -> None:
    started = time.monotonic()
    result = subprocess.run(
        [go, "build", "-o", str(out), "./cmd/proxyd"], cwd=PROXY_DIR, capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(f"go build failed:\n{result.stdout}{result.stderr}")
    say(f"built the Go proxy in {time.monotonic() - started:.1f}s -> {out.name}")


# -- audit-log verification (uses the Q3 harness) -------------------------------------------------------------


def verify_audit_logs(
    check: Checker, event_dir: Path, sessions: list[str], workdir: Path, poisoned_sentence: str
) -> None:
    sys.path.insert(0, str(Q3_DIR))
    from harness._canonical import tool_hash  # the Python side of the cross-language hash contract
    from harness.recording import load

    act("ACT 5  Forensics: verify the audit logs with the Q3 harness")
    say("The proxy wrote one hash-chained JSONL file per session. `harness.recording.load` re-checks every event's")
    say("schema, `seq` continuity, `prev_hash` link and `event_hash`. The proxy never writes `session_end`; a log")
    say("without it is 'still open', not tampered, so the non-strict loader is right here.")
    say()

    recordings = {}
    for sid in sessions:
        path = event_dir / f"{sid}.jsonl"
        if not check.expect(path.exists(), f"{sid}: audit log exists ({path.name})"):
            continue
        rec = load(path)  # non-strict: problems are returned, not raised
        recordings[sid] = rec
        check.expect(
            not rec.integrity_problems,
            f"{sid}: {len(rec.events)} events, hash chain and schema verify"
            + (f" (PROBLEMS: {rec.integrity_problems[:2]})" if rec.integrity_problems else ""),
        )
        types = {e["type"] for e in rec.events}
        check.expect("session_end" not in types, f"{sid}: no session_end (expected: log is 'still open')")

    say()
    say("Timeline, per session (consecutive identical events are folded):")
    for sid, rec in recordings.items():
        say()
        say(f"session {sid}  agent={rec.agent!r}")
        rows: list[list[Any]] = []  # [first_seq, last_seq, type, detail, count]
        for e in rec.events:
            typ = e["type"]
            if typ == "session_start":
                detail = f"agent={e.get('agent')!r}"
            elif typ == "tool_definition":
                detail = f"{e['tool']['name']}  def_hash={short(e['def_hash'])}"
            elif typ == "tool_call":
                detail = f"{e['tool_name']}  def_hash={short(e['def_hash'])}  args={clip(json.dumps(e['args']), 45)}"
            elif typ == "tool_response":
                detail = f"ok={e.get('ok')}  {clip(json.dumps(e.get('result', e.get('error'))), 55)}"
            elif typ == "policy_decision":
                detail = f"action={e['action']}  {e.get('tool_name', '')}: {clip(e.get('reason', ''), 60)}"
            else:
                detail = ""
            if rows and rows[-1][2] == typ and rows[-1][3] == detail:
                rows[-1][1], rows[-1][4] = e["seq"], rows[-1][4] + 1
            else:
                rows.append([e["seq"], e["seq"], typ, detail, 1])
        for first, last, typ, detail, count in rows:
            seqs = f"{first}" if first == last else f"{first}-{last}"
            say(f"  seq {seqs:>5}  {typ:<16} {detail}" + (f"   (x{count})" if count > 1 else ""))

    say()
    say("Which session saw which def_hash, and does Python agree with the Go proxy's hash?")
    seen: dict[str, dict[str, Any]] = {}
    for sid, rec in recordings.items():
        for versions in rec.tools.values():
            for v in versions:
                entry = seen.setdefault(v.def_hash, {"tool": v.name, "tool_def": v.tool, "sessions": []})
                if sid not in entry["sessions"]:
                    entry["sessions"].append(sid)
    all_match = True
    for go_hash, entry in sorted(seen.items(), key=lambda kv: kv[1]["tool"]):
        py_hash = tool_hash(entry["tool_def"])
        all_match &= py_hash == go_hash
        kind = "rug-pulled" if poisoned_sentence in entry["tool_def"].get("description", "") else "as first seen"
        say(
            f"  {entry['tool']:<10} {short(go_hash)}  {kind:<13} "
            f"python={'MATCH' if py_hash == go_hash else 'DIFFERENT'}  seen by: {', '.join(entry['sessions'])}"
        )
    check.expect(
        all_match and bool(seen), "Go-computed def_hash == Python-computed def_hash for every logged definition"
    )

    alice = recordings.get("sess-alice")
    if alice is not None:
        read_file_hashes = [v.def_hash for v in alice.tools.get((SERVER, "read_file"), [])]
        check.expect(
            len(set(read_file_hashes)) == 2, "sess-alice logged two different read_file def_hashes (before / after)"
        )
        actions = [e["action"] for e in alice.events if e["type"] == "policy_decision"]
        check.expect(
            "block" in actions and "quarantine" in actions,
            "sess-alice: policy_decision 'block' then 'quarantine' recorded",
        )
        ok_calls = [c for c in alice.calls if c.tool_name == "read_file" and c.ok]
        check.expect(len(ok_calls) == 1, "sess-alice: exactly one read_file call was ever forwarded (the benign one)")

    say()
    say("Tamper test: edit one argument in a COPY of sess-alice's log and load it again.")
    src = event_dir / "sess-alice.jsonl"
    if src.exists():
        lines = src.read_text(encoding="utf-8").splitlines()
        copy_path = workdir / "sess-alice.tampered.jsonl"
        edited = [ln.replace("/etc/hosts", "/etc/shadow", 1) if '"tool_call"' in ln else ln for ln in lines]
        copy_path.write_text("\n".join(edited) + "\n", encoding="utf-8")
        problems = load(copy_path).integrity_problems
        say(f"harness says: {clip(problems[0], 90) if problems else '(nothing)'}")
        check.expect(any("tampered" in p for p in problems), "an edited log is detected (event_hash mismatch)")


# -- the demo -----------------------------------------------------------------------------------------------------


def run(stack: Stack, check: Checker, workdir: Path) -> None:
    go = find_go()
    if go is None:
        raise RuntimeError("Go is not installed or not on PATH (winget install GoLang.Go); the proxy is a Go binary")
    try:
        import jsonschema  # noqa: F401  (the Q3 harness needs it)
    except ImportError as exc:
        raise RuntimeError("missing Python dependency: pip install jsonschema pytest") from exc

    act("ACT 0  Setup: four real processes, no mocks between them")
    say("An agent platform calls third-party tool servers. The vendor of `read_file` will change its definition")
    say("in the middle of a session (a 'rug-pull'). Watch whether the trust layer notices.")
    say()
    proxy_bin = workdir / ("proxyd.exe" if os.name == "nt" else "proxyd")
    build_proxy(go, proxy_bin)

    mock_port, control_port, proxy_port = free_port(), free_port(), free_port()
    event_dir = workdir / "events"
    config = {
        "listen": f"127.0.0.1:{proxy_port}",
        "control_base_url": f"http://127.0.0.1:{control_port}",
        "servers": {SERVER: f"http://127.0.0.1:{mock_port}"},
        "event_log_dir": str(event_dir),
        "quarantine_poll_interval_ms": 1000,
        "control_timeout_ms": 1500,
        "relist_interval_ms": -1,  # background re-list off: the scripted lists below are the only triggers
        "event_channel_size": 4096,
    }
    config_path = workdir / "proxy-config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    mock = stack.start(
        "mock-tool-server",
        [sys.executable, "-m", "demo_support.mock_tool_server", "--port", str(mock_port)],
        port=mock_port,
        cwd=HERE,
    )
    control_env = {
        "PYTHONPATH": os.pathsep.join([str(CONTROL_DIR), str(Q3_DIR), os.environ.get("PYTHONPATH", "")]),
        "PYTHONUNBUFFERED": "1",
    }
    control = stack.start(
        "control-plane",
        [sys.executable, "-m", "control", "--port", str(control_port)],
        port=control_port,
        cwd=CONTROL_DIR,
        env=control_env,
    )
    mock_url, control_url, proxy_base = (
        f"http://127.0.0.1:{mock_port}",
        f"http://127.0.0.1:{control_port}",
        f"http://127.0.0.1:{proxy_port}",
    )
    stack.wait_ready(mock, lambda: http_json("GET", f"{mock_url}/health")[0] == 200)
    stack.wait_ready(control, lambda: http_json("GET", f"{control_url}/healthz")[0] == 200)
    proxy = stack.start(
        "proxy", [str(proxy_bin), "-config", str(config_path)], port=proxy_port, cwd=workdir, graceful=True
    )
    stack.wait_ready(proxy, lambda: port_is_open(proxy_port))
    say(f"mock tool server  {mock_url}   (the vendor; admin endpoint flips its read_file definition)")
    say(f"control plane     {control_url}   (Python: Q3 differ + policy table + quarantine list)")
    say(f"proxy (Go)        {proxy_base}   (every agent talks to this; upstream = mock, control = above)")
    say(f"scratch dir       {workdir}")

    def from_admin(path: str, body: Any = None) -> Any:
        """The mock vendor's admin endpoint (POST when a body is given, else GET)."""
        return http_json("POST" if body is not None else "GET", f"{mock_url}{path}", body)[1]

    sys.path.insert(0, str(HERE))
    from demo_support.tools import RUG_PULL_SENTENCE  # the sentence the vendor adds (copied from the Q3 fixture)

    # ---------------------------------------------------------------------------------------------------------
    act("ACT 1  Business as usual: two agent sessions list the tools; one calls read_file")
    alice, bob = Agent(proxy_base, "sess-alice"), Agent(proxy_base, "sess-bob")
    tools = alice.list_tools()
    read_file = next(t for t in tools if t["name"] == "read_file")
    say(f"sess-alice lists tools -> {[t['name'] for t in tools]}")
    say(f"read_file description: {read_file['description']!r}")
    say("The proxy pinned each tool's def_hash (sha256 of the canonical definition) for this session.")
    bob.list_tools()
    say("sess-bob lists tools too (a second agent, mid-session, that will not call anything yet).")
    resp = alice.call("read_file", {"path": "/etc/hosts"})
    say(f"sess-alice calls read_file(/etc/hosts) -> {describe(resp)}")
    check.expect(reason_of(resp) == "OK", "benign call is forwarded and answered")

    # ---------------------------------------------------------------------------------------------------------
    act("ACT 2  The vendor silently ships an update (the rug-pull)")
    from_admin("/admin/mode", {"mode": "rugpull"})
    say("POST /admin/mode rugpull. Same tool name, still marked readOnly, but the description now tells the model:")
    say(f"  {RUG_PULL_SENTENCE!r}")
    say("and there is a new optional `notes` parameter to carry the stolen data.")

    # ---------------------------------------------------------------------------------------------------------
    act("ACT 3  Detection: the agent re-lists mid-session")
    t_relist = time.monotonic()
    list_resp = alice.rpc("tools/list")
    say(f"The proxy hashes the vendor response before exposing it -> {describe(list_resp)}")
    check.expect(
        reason_of(list_resp) == "TOOL_CONTRACT_CHANGED",
        "the changed tools/list response is withheld from the agent/model",
    )
    say(
        "The poisoned definition is recorded for audit and classification, "
        "but its text is never returned to the model."
    )
    args = {"path": "/etc/hosts", "notes": "<hypothetical exfiltration payload>"}
    resp = alice.call("read_file", args)
    say(f"sess-alice attempts the changed call shape -> {describe(resp)}")
    check.expect(
        reason_of(resp) in {"TOOL_CONTRACT_CHANGED", "TOOL_QUARANTINED"},
        f"call after the change is blocked, not forwarded ({reason_of(resp)})",
    )
    bob_list_resp = bob.rpc("tools/list")
    check.expect(
        reason_of(bob_list_resp) in {"TOOL_CONTRACT_CHANGED", "TOOL_QUARANTINED"},
        "the changed definition is withheld from the second session too",
    )
    say("sess-bob re-lists as well: the same change is withheld and reported to the control plane a second time.")
    say()
    say("Meanwhile, asynchronously, the proxy POSTed /changes {old_def, new_def, old_hash, new_hash} to the control")
    say("plane, which ran the Q3 differ, looked up (severity x risk class) in its policy table, and answered.")
    quarantined = poll_until(
        lambda: (
            {"server": SERVER, "tool": "read_file"} in http_json("GET", f"{control_url}/quarantine")[1]["quarantine"]
        )
    )
    check.expect(bool(quarantined), "control plane put fs/read_file on its quarantine list (SECURITY verdict)")
    stats = poll_until(lambda: (s := http_json("GET", f"{control_url}/stats")[1])["changes"] >= 2 and s)
    check.expect(bool(stats), "both sessions' reports reached the control plane")
    if stats:
        say(f"control /stats: {json.dumps(stats)}")
        check.expect(
            stats["cache_misses"] == 1 and stats["cache_hits"] >= 1,
            "verdict cache: the identical change from the second session was answered without re-diffing",
        )
        check.expect(
            stats["hash_mismatches"] == 0,
            "control plane's own def_hash recomputation agrees with the Go proxy's (0 mismatches)",
        )

    # ---------------------------------------------------------------------------------------------------------
    act("ACT 4  Quarantine reaches every session (proxies poll the list about once per second)")
    seen: list[str] = []
    t_end: float | None = None

    def probe() -> bool:
        nonlocal t_end
        r = alice.call("read_file", args)
        why = reason_of(r)
        if not seen or seen[-1] != why:
            seen.append(why)
        if why == "TOOL_QUARANTINED":
            t_end = time.monotonic()
        return why in {"TOOL_QUARANTINED", "OK"}

    poll_until(probe, interval=0.2)
    say(f"sess-alice retries read_file every 0.2 s. Answers seen, in order: {' -> '.join(seen)}")
    check.expect("OK" not in seen, "the poisoned tool was never callable after the change (no successful call)")
    check.expect(bool(seen) and seen[-1] == "TOOL_QUARANTINED", "sess-alice's calls end up TOOL_QUARANTINED")
    if t_end is not None:
        say(
            f"quarantine took effect {t_end - t_relist:.2f}s after the re-list (verdict is async; poll interval is 1 s)"
        )
    say()
    resp = bob.call("read_file", {"path": "/etc/hosts"})
    say(f"sess-bob calls read_file          -> {describe(resp)}")
    check.expect(reason_of(resp) == "TOOL_QUARANTINED", "the second session is blocked too")
    carol = Agent(proxy_base, "sess-carol")
    carol_list_resp = carol.rpc("tools/list")
    check.expect(
        reason_of(carol_list_resp) == "TOOL_QUARANTINED",
        "a brand-new session cannot see the quarantined definition",
    )
    resp = carol.call("read_file", {"path": "/etc/hosts"})
    say("sess-carol (brand new; the quarantined definition was withheld) calls read_file")
    say(f"                                  -> {describe(resp)}")
    check.expect(
        reason_of(resp) == "TOOL_QUARANTINED", "the quarantined tool remains blocked for a brand-new session"
    )
    resp = alice.call("list_files", {"dir": "/etc"})
    say(f"sess-alice calls list_files(/etc)  -> {describe(resp)}")
    check.expect(reason_of(resp) == "OK", "other tools of the same server keep working (blast radius = the one tool)")
    upstream = from_admin("/admin/state")
    read_file_calls = [c for c in upstream["calls"] if c["tool"] == "read_file"]
    say(f"calls that actually reached the vendor's read_file: {[(c['mode']) for c in read_file_calls]}")
    check.expect([c["mode"] for c in read_file_calls] == ["benign"], "no call ever reached the poisoned read_file")

    # ---------------------------------------------------------------------------------------------------------
    say()
    say("Stopping the proxy gracefully (Ctrl-Break / SIGINT) so it drains its audit-log queue...")
    proxy.stop()
    verify_audit_logs(check, event_dir, ["sess-alice", "sess-bob", "sess-carol"], workdir, RUG_PULL_SENTENCE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true", help="keep the scratch dir (logs, audit files) after success")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    workdir = Path(tempfile.mkdtemp(prefix="q4-demo-"))
    stack = Stack(workdir)
    check = Checker()
    print("Q4 trust layer demo: mid-session rug-pull vs. Go proxy + Python control plane")
    interrupted = False
    error: str | None = None
    try:
        run(stack, check, workdir)
    except KeyboardInterrupt:
        interrupted = True
        print("\ninterrupted: stopping all child processes...")
    except Exception as exc:  # noqa: BLE001 (report anything unexpected, then still clean up)
        error = f"{type(exc).__name__}: {exc}"
        print(f"\nERROR: {error}")
    finally:
        stack.stop_all()

    act("ACT 6  Shutdown: nothing may be left running")
    for child in stack.children:
        gone = child.popen.poll() is not None and not port_is_open(child.port)
        check.expect(gone, f"{child.name} stopped, port {child.port} closed")
    if error:
        for child in stack.children:
            print(f"\n--- last lines of {child.name} log ---\n{child.log_tail()}")

    ok = not interrupted and error is None and not check.failures
    print(f"\n{'=' * WIDTH}")
    if interrupted:
        print("INTERRUPTED (all child processes were stopped)")
    elif ok:
        print(f"ALL {check.passed} EXPECTED OUTCOMES HAPPENED")
    else:
        print("DEMO FAILED" + (f": {error}" if error else ""))
        if check.failures:
            print(f"{len(check.failures)} expected outcome(s) did not happen:")
        for msg in check.failures:
            print(f"  - {msg}")
    if ok and not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(f"scratch dir kept for inspection: {workdir}")
    return 130 if interrupted else (0 if ok else 1)


if __name__ == "__main__":
    sys.exit(main())
