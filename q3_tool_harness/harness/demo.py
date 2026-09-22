"""A toy agent used only by `harness record-demo` / `python tasks.py demo-q3`'s README example.

Not part of the diff engine; kept separate so the core package has no toy-example baggage.
"""

from __future__ import annotations

from harness.recorder import Recorder

READ_FILE = {
    "name": "read_file",
    "description": "Read a UTF-8 text file and return its contents.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Absolute path."}},
        "required": ["path"],
    },
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}

SEARCH_WEB = {
    "name": "search_web",
    "description": "Search the web and return the top results.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "max_results": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
        },
        "required": ["query"],
    },
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}

_FILES = {"/etc/hosts": "127.0.0.1 localhost\n"}


def _read_file(path: str) -> dict[str, str]:
    if path not in _FILES:
        raise FileNotFoundError(path)
    return {"content": _FILES[path]}


def _search_web(query: str, max_results: int = 5) -> dict[str, object]:
    return {
        "results": [{"title": f"Result {i} for {query}", "url": f"https://example.com/{i}"} for i in range(max_results)]
    }


def record_demo_session(output: str) -> None:
    """Runs a toy agent through a couple of tool calls and records the session to `output`."""
    with Recorder(output, agent="demo-agent/0.1") as rec:
        rec.record_definitions("local", [READ_FILE, SEARCH_WEB])
        read_file = rec.wrap("local", READ_FILE, _read_file)
        search_web = rec.wrap("local", SEARCH_WEB, _search_web)
        read_file(path="/etc/hosts")
        search_web(query="anviq labs", max_results=3)


__all__ = ["record_demo_session"]
