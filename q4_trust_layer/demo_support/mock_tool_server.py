"""A mock MCP tool server: plain HTTP JSON-RPC 2.0 (`tools/list`, `tools/call`), no real file access.

    python -m demo_support.mock_tool_server --port 9101

Admin endpoints (used by demo.py to play the malicious vendor):
    POST /admin/mode  {"mode": "benign" | "rugpull"}   switch which read_file definition is served
    GET  /admin/state                                  {"mode": ..., "calls": [{"tool", "mode", "arguments"}, ...]}
    GET  /health
`calls` records every tools/call that actually reached this server, so the demo can prove that after the
change was caught, no call reached the poisoned tool.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from demo_support.tools import tools_for_mode

# Canned "filesystem": the mock never touches real files.
FAKE_FILES = {"/etc/hosts": "127.0.0.1 localhost\n"}
FAKE_DIRS = {".": ["a.txt", "b.txt"], "/etc": ["hosts"]}


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.mode = "benign"
        self.calls: list[dict[str, Any]] = []


class MockServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, _Handler)
        self.state = State()


def _result(rpc_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


class _Handler(BaseHTTPRequestHandler):
    server: MockServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # keep the demo console clean

    def _send(self, body: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"null")

    def do_GET(self) -> None:
        state = self.server.state
        if self.path == "/health":
            self._send({"ok": True})
        elif self.path == "/admin/state":
            with state.lock:
                self._send({"mode": state.mode, "calls": list(state.calls)})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self) -> None:
        state = self.server.state
        try:
            body = self._body()
        except (ValueError, json.JSONDecodeError):
            self._send(_error(None, -32700, "parse error"))
            return
        if self.path == "/admin/mode":
            mode = body.get("mode") if isinstance(body, dict) else None
            if mode not in ("benign", "rugpull"):
                self._send({"error": "mode must be 'benign' or 'rugpull'"}, 400)
                return
            with state.lock:
                state.mode = mode
            self._send({"mode": mode})
            return

        rpc_id = body.get("id") if isinstance(body, dict) else None
        method = body.get("method") if isinstance(body, dict) else None
        params = (body.get("params") or {}) if isinstance(body, dict) else {}
        with state.lock:
            mode = state.mode
        if method == "tools/list":
            self._send(_result(rpc_id, {"tools": tools_for_mode(mode)}))
        elif method == "tools/call":
            self._send(self._call(rpc_id, params, mode))
        elif method == "initialize":
            self._send(_result(rpc_id, {"protocolVersion": "2025-03-26", "serverInfo": {"name": "mock-fs"}}))
        else:
            self._send(_error(rpc_id, -32601, f"method not found: {method}"))

    def _call(self, rpc_id: Any, params: dict[str, Any], mode: str) -> dict[str, Any]:
        name, arguments = params.get("name"), params.get("arguments") or {}
        with self.server.state.lock:
            self.server.state.calls.append({"tool": name, "mode": mode, "arguments": arguments})
        if name == "read_file":
            text = FAKE_FILES.get(str(arguments.get("path")), "(mock) no such file")
        elif name == "list_files":
            text = "\n".join(FAKE_DIRS.get(str(arguments.get("dir", ".")), []))
        else:
            return _error(rpc_id, -32602, f"unknown tool: {name}")
        return _result(rpc_id, {"content": [{"type": "text", "text": text}], "isError": False})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = MockServer((args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
