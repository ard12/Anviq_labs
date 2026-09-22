"""Thin HTTP transport over `ControlService` (stdlib `http.server`, no framework).

Routes (DESIGN section 0):  POST /changes   GET /quarantine   POST /baselines/approve
Extras:                     GET /healthz    GET /stats
Every body is JSON. Errors are `{"error": "..."}` with a non-2xx status (the proxy treats any non-200 from
/changes as "control plane unreachable" and applies its fail-open / fail-closed rule).

One thread per request (`ThreadingHTTPServer`): the proxy calls /changes concurrently and the differ is
pure Python, so simple threads are enough for v1 (see DECISIONS Q4-control-08 for what scaling would take).
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from control.service import BadRequest, ControlService, parse_change_request

log = logging.getLogger("control")

MAX_BODY_BYTES = 8 * 1024 * 1024  # two tool definitions plus findings are tiny; this only stops abuse


class ControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True  # a stuck request must not keep the process alive at shutdown
    allow_reuse_address = True
    request_queue_size = 128  # default backlog is 5; many sessions can report the same change at once

    def __init__(self, address: tuple[str, int], service: ControlService) -> None:
        super().__init__(address, _Handler)
        self.service = service


class _Handler(BaseHTTPRequestHandler):
    server: ControlHTTPServer  # narrowed from BaseServer, for type checkers
    server_version = "q4-control/0.1"

    # -- plumbing ----------------------------------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 (name fixed by the base class)
        log.debug("%s - %s", self.address_string(), format % args)

    def _send(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise BadRequest("invalid Content-Length") from exc
        if length > MAX_BODY_BYTES:
            raise BadRequest(f"body larger than {MAX_BODY_BYTES} bytes")
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BadRequest(f"body is not valid JSON: {exc}") from exc

    def _dispatch(self, routes: dict[str, Any]) -> None:
        handler = routes.get(self.path.split("?", 1)[0])
        if handler is None:
            self._send(404, {"error": f"no such route: {self.path}"})
            return
        try:
            status, body = handler()
        except BadRequest as exc:
            self._send(400, {"error": str(exc)})
        except Exception:  # noqa: BLE001 (last resort: a bug must become a 500, not a dropped connection)
            log.exception("unhandled error serving %s %s", self.command, self.path)
            self._send(500, {"error": "internal error (see control-plane log)"})
        else:
            self._send(status, body)

    # -- routes ------------------------------------------------------------------------------------

    def do_GET(self) -> None:
        svc = self.server.service
        self._dispatch(
            {
                "/quarantine": lambda: (200, {"quarantine": svc.quarantine_list()}),
                "/healthz": lambda: (200, {"ok": True}),
                "/stats": lambda: (200, svc.stats()),
            }
        )

    def do_POST(self) -> None:
        svc = self.server.service
        self._dispatch(
            {
                "/changes": lambda: (200, svc.evaluate_change(parse_change_request(self._read_json()))),
                "/baselines/approve": lambda: (200, svc.approve(self._read_json())),
            }
        )

    # A known path with the wrong method is 405, not 404.
    def _method_not_allowed(self) -> None:
        self._send(405, {"error": f"{self.command} not allowed on {self.path}"})

    do_PUT = do_DELETE = do_PATCH = _method_not_allowed


def make_server(service: ControlService, host: str = "127.0.0.1", port: int = 0) -> ControlHTTPServer:
    """Bind (port 0 = pick a free port; read it back from `server.server_address[1]`). Caller runs
    `serve_forever()` (usually in a thread) and `shutdown()` + `server_close()` to stop."""
    return ControlHTTPServer((host, port), service)
