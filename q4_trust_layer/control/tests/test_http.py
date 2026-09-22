"""Round trips against a real ControlHTTPServer on an ephemeral localhost port (no mocks)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from control.http_api import ControlHTTPServer, make_server
from control.service import ControlService

ChangeBody = Callable[..., dict[str, Any]]


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def request(self, method: str, path: str, body: Any = None, *, raw: bytes | None = None) -> tuple[int, Any]:
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def get(self, path: str) -> tuple[int, Any]:
        return self.request("GET", path)

    def post(self, path: str, body: Any = None, *, raw: bytes | None = None) -> tuple[int, Any]:
        return self.request("POST", path, body, raw=raw)


@pytest.fixture
def server() -> Iterator[ControlHTTPServer]:
    srv = make_server(ControlService(), "127.0.0.1", 0)  # port 0 = the OS picks a free port
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


@pytest.fixture
def client(server: ControlHTTPServer) -> Client:
    return Client(f"http://127.0.0.1:{server.server_address[1]}")


def test_healthz_and_empty_quarantine(client: Client) -> None:
    assert client.get("/healthz") == (200, {"ok": True})
    assert client.get("/quarantine") == (200, {"quarantine": []})


def test_rug_pull_round_trip_and_quarantine_list(
    client: Client, read_file: dict[str, Any], rug_pull: dict[str, Any], change_body: ChangeBody
) -> None:
    status, body = client.post("/changes", change_body(read_file, rug_pull))
    assert status == 200
    assert body["verdict"] == "quarantine"
    assert body["reason"].startswith("SECURITY DESC_EXFIL_PATTERN at /description")
    assert body["findings"][0]["severity"] == "SECURITY"
    assert client.get("/quarantine") == (200, {"quarantine": [{"server": "fs", "tool": "read_file"}]})


def test_second_identical_report_is_a_cache_hit(
    client: Client, read_file: dict[str, Any], rug_pull: dict[str, Any], change_body: ChangeBody
) -> None:
    client.post("/changes", change_body(read_file, rug_pull, session_id="a"))
    _, second = client.post("/changes", change_body(read_file, rug_pull, session_id="b"))
    assert second["cache_hit"] is True
    _, stats = client.get("/stats")
    assert (stats["cache_hits"], stats["cache_misses"], stats["quarantined"]) == (1, 1, 1)


def test_concurrent_reports_over_http(
    client: Client, read_file: dict[str, Any], rug_pull: dict[str, Any], change_body: ChangeBody
) -> None:
    results: list[tuple[int, Any]] = []
    body = change_body(read_file, rug_pull)
    threads = [threading.Thread(target=lambda: results.append(client.post("/changes", body))) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert len(results) == 20
    assert all(status == 200 and payload["verdict"] == "quarantine" for status, payload in results)
    stats = client.get("/stats")[1]
    assert stats["cache_misses"] == 1
    assert stats["cache_hits"] == 19


def test_approve_flow_over_http(
    client: Client, read_file: dict[str, Any], rug_pull: dict[str, Any], change_body: ChangeBody
) -> None:
    body = change_body(read_file, rug_pull)
    client.post("/changes", body)
    approve = {
        "server": "fs",
        "tool": "read_file",
        "def_hash": body["new_hash"],
        "approved_by": "alice@example.com",
        "reason": "reviewed vendor changelog",
    }
    status, resp = client.post("/baselines/approve", approve)
    assert status == 200
    assert resp == {"server": "fs", "tool": "read_file", "approved_hash": body["new_hash"], "cleared_quarantine": True}
    assert client.get("/quarantine") == (200, {"quarantine": []})
    status, again = client.post("/changes", body)
    assert (status, again["verdict"], again["reason"]) == (200, "resume", "matches approved baseline")


def test_hash_mismatch_is_visible_in_the_http_response(
    client: Client, read_file: dict[str, Any], rug_pull: dict[str, Any], change_body: ChangeBody
) -> None:
    status, body = client.post("/changes", change_body(read_file, rug_pull, old_hash="sha256:" + "f" * 64))
    assert status == 200
    assert body["hash_mismatch"][0]["field"] == "old_hash"
    assert "HASH_MISMATCH" in body["reason"]
    assert client.get("/stats")[1]["hash_mismatches"] == 1


def test_errors_are_json_with_the_right_status(client: Client) -> None:
    assert client.post("/changes", raw=b"{not json")[0] == 400
    assert client.post("/changes", {"server": "fs"})[0] == 400
    assert client.post("/baselines/approve", {"server": "fs", "tool": "t", "def_hash": "nope"})[0] == 400
    status, body = client.get("/nope")
    assert status == 404
    assert "error" in body
    assert client.request("PUT", "/changes", {})[0] == 405
