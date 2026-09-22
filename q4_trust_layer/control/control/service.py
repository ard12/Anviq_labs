"""The control plane's logic, with no HTTP in it (http_api.py is the thin transport on top).

State (all in memory in v1, lost on restart; see DECISIONS Q4-control-08):
  * verdict cache      (old_hash, new_hash) -> the diff result, computed once even if 1,000 sessions report it
  * quarantine set     {(server, tool)}
  * approved baselines {(server, tool)} -> the hash an operator approved

One lock guards all of it. It is never held while the differ runs (the differ is the slow part), so
concurrent requests for *different* changes diff in parallel.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from control.differ import compute_hash, diff_definitions, highest_severity, sort_findings
from control.policy import PolicyTable
from harness.diff.types import Finding

log = logging.getLogger("control")

DiffFn = Callable[[str, dict[str, Any], dict[str, Any]], list[Finding]]

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DEFAULT_CACHE_SIZE = 4096


class BadRequest(ValueError):
    """The caller sent something malformed. The HTTP layer turns this into a 400."""


@dataclass(frozen=True)
class ChangeRequest:
    server: str
    tool: str
    session_id: str  # informational only; the verdict never depends on it (DESIGN section 0.1)
    old_hash: str
    new_hash: str
    old_def: dict[str, Any]
    new_def: dict[str, Any]


def _require_str(payload: dict[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or (not value and not allow_empty):
        raise BadRequest(f"'{key}' must be a non-empty string")
    return value


def parse_change_request(payload: Any) -> ChangeRequest:
    if not isinstance(payload, dict):
        raise BadRequest("body must be a JSON object")
    old_def, new_def = payload.get("old_def"), payload.get("new_def")
    if not isinstance(old_def, dict) or not isinstance(new_def, dict):
        raise BadRequest("'old_def' and 'new_def' must be JSON objects (the raw MCP tool definitions)")
    return ChangeRequest(
        server=_require_str(payload, "server"),
        tool=_require_str(payload, "tool"),
        session_id=_require_str(payload, "session_id", allow_empty=True) if "session_id" in payload else "",
        old_hash=_require_str(payload, "old_hash"),
        new_hash=_require_str(payload, "new_hash"),
        old_def=old_def,
        new_def=new_def,
    )


@dataclass(frozen=True)
class _Analysis:
    """What the differ concluded about one (old, new) pair. Immutable, so it is safe to share between threads."""

    findings: tuple[Finding, ...]  # worst first
    severity: str  # 'SECURITY' | 'BREAKING' | 'WARN' | 'INFO' | 'NONE'


def _analyse(diff_fn: DiffFn, tool: str, old_def: dict[str, Any], new_def: dict[str, Any]) -> _Analysis:
    findings = sort_findings(diff_fn(tool, old_def, new_def))
    return _Analysis(findings=tuple(findings), severity=highest_severity(findings))


def _reason(analysis: _Analysis, risk_class: str) -> str:
    if not analysis.findings:
        return f"no differences found; risk_class={risk_class}"
    top = analysis.findings[0]
    more = len(analysis.findings) - 1
    suffix = f" (+{more} more finding{'s' if more != 1 else ''})" if more else ""
    return f"{top.severity} {top.rule_id} at {top.path}{suffix}; risk_class={risk_class}"


class ControlService:
    def __init__(
        self,
        policy: PolicyTable | None = None,
        *,
        diff_fn: DiffFn = diff_definitions,
        cache_size: int = DEFAULT_CACHE_SIZE,
    ) -> None:
        self._policy = policy or PolicyTable.default()
        self._diff_fn = diff_fn  # injectable so tests can count how often the differ really runs
        self._cache_size = cache_size
        self._lock = threading.Lock()
        # Values are Futures so that concurrent identical requests share ONE diff ("single flight").
        self._cache: OrderedDict[tuple[str, str], Future[_Analysis]] = OrderedDict()
        self._quarantine: set[tuple[str, str]] = set()
        self._approved: dict[tuple[str, str], dict[str, str]] = {}
        self._stats = {"changes": 0, "cache_hits": 0, "cache_misses": 0, "hash_mismatches": 0, "approved_hits": 0}

    # -- POST /changes ---------------------------------------------------------------------------

    def evaluate_change(self, req: ChangeRequest) -> dict[str, Any]:
        try:
            old_hash, new_hash = compute_hash(req.old_def), compute_hash(req.new_def)
        except (KeyError, TypeError, ValueError) as exc:
            raise BadRequest(f"cannot hash a definition (is 'name' present, are numbers portable?): {exc!r}") from exc
        mismatches = self._check_hashes(req, old_hash, new_hash)

        with self._lock:
            self._stats["changes"] += 1
            if mismatches:
                self._stats["hash_mismatches"] += 1
            if self._is_approved(req, new_hash):  # DESIGN step 5: an approved hash wins over any findings
                self._stats["approved_hits"] += 1
                return self._body("resume", "matches approved baseline", (), None, None, False, mismatches)

        analysis, cache_hit = self._cached_analysis((old_hash, new_hash), req)
        risk_class = self._policy.risk_class(req.server, req.tool, req.new_def)
        verdict = self._policy.decide(analysis.severity, risk_class)
        # Quarantine is applied per request, not cached: the same (old, new) pair can arrive from another
        # server name, and the operator may have approved and cleared it since a cached answer was made.
        with self._lock:
            if self._is_approved(req, new_hash):
                # An operator approved this hash while the diff was running (or waiting on another thread's diff).
                # Re-check under the lock so a late quarantine cannot undo the approval.
                self._stats["approved_hits"] += 1
                return self._body("resume", "matches approved baseline", (), None, None, False, mismatches)
            if verdict == "quarantine":
                self._quarantine.add((req.server, req.tool))
        log.info(
            "change server=%s tool=%s session=%s %s -> %s severity=%s risk=%s verdict=%s cache_hit=%s",
            req.server,
            req.tool,
            req.session_id,
            old_hash[:15],
            new_hash[:15],
            analysis.severity,
            risk_class,
            verdict,
            cache_hit,
        )
        return self._body(
            verdict,
            _reason(analysis, risk_class),
            analysis.findings,
            analysis.severity,
            risk_class,
            cache_hit,
            mismatches,
        )

    def _is_approved(self, req: ChangeRequest, new_hash: str) -> bool:
        """Caller holds the lock."""
        approved = self._approved.get((req.server, req.tool))
        return approved is not None and approved["approved_hash"] == new_hash

    def _check_hashes(self, req: ChangeRequest, old_hash: str, new_hash: str) -> list[dict[str, str]]:
        """The live cross-language parity check (DESIGN section 0.1): does our hash equal the proxy's?
        We trust our own value from here on, but a disagreement is never swallowed."""
        mismatches = [
            {"field": field, "proxy": theirs, "control": ours}
            for field, theirs, ours in (("old_hash", req.old_hash, old_hash), ("new_hash", req.new_hash, new_hash))
            if theirs != ours
        ]
        for m in mismatches:
            log.error(
                "HASH MISMATCH (Go/Python canonical hashing disagree) server=%s tool=%s %s: proxy=%s control=%s",
                req.server,
                req.tool,
                m["field"],
                m["proxy"],
                m["control"],
            )
        return mismatches

    def _cached_analysis(self, key: tuple[str, str], req: ChangeRequest) -> tuple[_Analysis, bool]:
        """Return (analysis, cache_hit). The first caller for a key runs the differ; anyone who arrives for the
        same key meanwhile, or later, gets the same result without running it."""
        with self._lock:
            future = self._cache.get(key)
            owner = future is None
            if owner:
                future = Future()
                self._cache[key] = future
                self._stats["cache_misses"] += 1
                while len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)  # evict least recently used
            else:
                self._cache.move_to_end(key)
                self._stats["cache_hits"] += 1
        assert future is not None
        if owner:
            try:
                future.set_result(_analyse(self._diff_fn, req.tool, req.old_def, req.new_def))
            except BaseException as exc:
                with self._lock:
                    self._cache.pop(key, None)  # never cache a failure
                future.set_exception(exc)
                raise
        return future.result(), not owner

    @staticmethod
    def _body(
        verdict: str,
        reason: str,
        findings: tuple[Finding, ...],
        severity: str | None,
        risk_class: str | None,
        cache_hit: bool,
        mismatches: list[dict[str, str]],
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "verdict": verdict,
            "reason": reason,
            "findings": [f.to_dict() for f in findings],
            # Extras beyond DESIGN section 0.1 (the proxy ignores unknown fields): useful for humans and the demo.
            "severity": severity,
            "risk_class": risk_class,
            "cache_hit": cache_hit,
        }
        if mismatches:
            body["hash_mismatch"] = mismatches
            fields = ", ".join(m["field"] for m in mismatches)
            body["reason"] = f"HASH_MISMATCH ({fields}): proxy and control disagree on def_hash; {reason}"
        return body

    # -- GET /quarantine -------------------------------------------------------------------------

    def quarantine_list(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"server": s, "tool": t} for s, t in sorted(self._quarantine)]

    # -- POST /baselines/approve -----------------------------------------------------------------

    def approve(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise BadRequest("body must be a JSON object")
        server, tool = _require_str(payload, "server"), _require_str(payload, "tool")
        def_hash = _require_str(payload, "def_hash")
        if not _HASH_RE.match(def_hash):
            raise BadRequest("'def_hash' must look like 'sha256:' followed by 64 lowercase hex characters")
        approved_by = payload.get("approved_by", "")
        reason = payload.get("reason", "")
        if not isinstance(approved_by, str) or not isinstance(reason, str):
            raise BadRequest("'approved_by' and 'reason' must be strings when present")

        with self._lock:
            self._approved[(server, tool)] = {
                "approved_hash": def_hash,
                "approved_by": approved_by,
                "reason": reason,
                "at": datetime.now(UTC).isoformat(timespec="seconds"),
            }
            cleared = (server, tool) in self._quarantine
            self._quarantine.discard((server, tool))
        log.warning(
            "BASELINE APPROVED server=%s tool=%s hash=%s by=%r reason=%r cleared_quarantine=%s",
            server,
            tool,
            def_hash,
            approved_by,
            reason,
            cleared,
        )
        return {"server": server, "tool": tool, "approved_hash": def_hash, "cleared_quarantine": cleared}

    # -- GET /stats (not in DESIGN section 0; for the demo and operators) ---------------------------

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {**self._stats, "quarantined": len(self._quarantine), "cache_entries": len(self._cache)}
