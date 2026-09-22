"""Reference canonicalization + hashing for tool definitions and recording events.

This file is the cross-language contract. Python (q3 harness, q4 control) and Go
(q4 proxy) must produce byte-identical canonical forms, verified by
`golden_vectors.json`. Stdlib only, so it can be vendored anywhere.

Canonical form = RFC 8785 (JSON Canonicalization Scheme, "JCS"):
  * object keys sorted by UTF-16 code units, no insignificant whitespace
  * strings escaped the way ECMAScript JSON.stringify does
  * numbers serialized the way ECMAScript Number.prototype.toString does

Tool-definition hashing applies a *minimal* normalization first (drop `$comment`,
sort + dedupe `required`). Anything smarter (resolving $ref, deciding a
description edit is cosmetic) belongs in the differ, off the hot path, so the Go
proxy never has to reimplement it.
"""

from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

HASH_PREFIX = "sha256:"

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        elif 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError("lone surrogate is not valid in canonical JSON")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(n: int | float) -> str:
    if isinstance(n, bool):  # bool is a subclass of int
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        if abs(n) > 2**53:
            raise ValueError("integer outside IEEE-754 safe range; not portable across languages")
        return str(n)
    if not math.isfinite(n):
        raise ValueError("NaN/Infinity are not valid JSON")
    if n == 0:
        return "0"  # also covers -0.0
    # repr() yields the shortest round-tripping digits, same as ECMAScript.
    sign, digits, exp = Decimal(repr(n)).normalize().as_tuple()
    ds = "".join(map(str, digits))
    k = len(ds)
    e = exp + k  # value = 0.ds * 10^e  (ECMAScript's "n")
    neg = "-" if sign else ""
    if k <= e <= 21:
        body = ds + "0" * (e - k)
    elif 0 < e <= 21:
        body = ds[:e] + "." + ds[e:]
    elif -6 < e <= 0:
        body = "0." + "0" * (-e) + ds
    else:
        mant = ds[0] + ("." + ds[1:] if k > 1 else "")
        x = e - 1
        body = f"{mant}e{'+' if x > 0 else '-'}{abs(x)}"
    return neg + body


def canonical_json(value: Any) -> str:
    """Serialize `value` per RFC 8785."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _encode_number(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"object keys must be strings, got {type(k).__name__}")
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_encode_string(k) + ":" + canonical_json(v) for k, v in items) + "}"
    raise TypeError(f"not JSON-serializable: {type(value).__name__}")


def sha256_hex(value: Any) -> str:
    return HASH_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_schema(node: Any) -> Any:
    if isinstance(node, dict):
        out = {k: _normalize_schema(v) for k, v in node.items() if k != "$comment"}
        req = out.get("required")
        if isinstance(req, list) and all(isinstance(r, str) for r in req):
            out["required"] = sorted(set(req), key=lambda s: s.encode("utf-16-be"))
        return out
    if isinstance(node, list):
        return [_normalize_schema(v) for v in node]
    return node


def normalize_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """Project a tool definition onto the fields that define its contract.

    Description IS included: a changed description is exactly what a rug-pull
    looks like, so it must change the hash. Whether the change *matters* is the
    differ's job.
    """
    out: dict[str, Any] = {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "inputSchema": _normalize_schema(tool.get("inputSchema", {})),
    }
    for optional in ("outputSchema", "annotations"):
        if optional in tool:
            out[optional] = _normalize_schema(tool[optional])
    return out


def tool_hash(tool: dict[str, Any]) -> str:
    return sha256_hex(normalize_tool(tool))


def event_hash(event: dict[str, Any]) -> str:
    """Hash of an event for the per-session hash chain (excludes its own hash)."""
    return sha256_hex({k: v for k, v in event.items() if k != "event_hash"})
