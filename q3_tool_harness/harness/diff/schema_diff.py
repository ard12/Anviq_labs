"""Recursive JSON-Schema comparison between two versions of the same tool's `inputSchema`
(and, with the same machinery, `outputSchema`), plus tool-level `annotations`.

Local `$ref`s (`"$ref": "#/..."`) are resolved before comparing; **remote** `$ref`s (anything
not starting with `#`) are left unresolved and compared structurally as opaque objects -- see
DECISIONS.md ("local-$ref only").
"""

from __future__ import annotations

import difflib
from typing import Any
from urllib.parse import unquote

from harness.diff.types import Finding

RENAME_CONFIDENCE_THRESHOLD = 0.5
RENAME_NAME_SIM_FLOOR = 0.3
RENAME_DESC_SIM_FLOOR = 0.5

_MISSING = object()


# -- local $ref resolution --------------------------------------------------------------------


def _json_pointer_get(root: Any, pointer: str) -> Any:
    if pointer in ("#", "#/"):
        return root
    if not pointer.startswith("#/"):
        return None
    node = root
    for raw_part in pointer[2:].split("/"):
        part = unquote(raw_part).replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.lstrip("-").isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def resolve_local_refs(node: Any, root: Any, *, _seen: frozenset[str] = frozenset()) -> Any:
    """Expand every local `$ref` in `node` against `root`. Remote refs and unresolvable
    pointers are left as-is. Cycle-safe: a `$ref` already being expanded resolves to `{}`."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#"):
            if ref in _seen:
                return {}
            target = _json_pointer_get(root, ref)
            if target is None:
                return node
            resolved = resolve_local_refs(target, root, _seen=_seen | {ref})
            resolved = resolved if isinstance(resolved, dict) else {}
            merged = {**resolved, **{k: v for k, v in node.items() if k != "$ref"}}
            return merged
        return {k: resolve_local_refs(v, root, _seen=_seen) for k, v in node.items()}
    if isinstance(node, list):
        return [resolve_local_refs(v, root, _seen=_seen) for v in node]
    return node


# -- helpers ------------------------------------------------------------------------------------


def _type_set(schema: dict[str, Any]) -> frozenset[str]:
    t = schema.get("type")
    if isinstance(t, str):
        return frozenset({t})
    if isinstance(t, list):
        return frozenset(x for x in t if isinstance(x, str))
    if "properties" in schema:
        return frozenset({"object"})
    if "items" in schema:
        return frozenset({"array"})
    return frozenset()


def _classify_type_change(before: frozenset[str], after: frozenset[str]) -> tuple[str, str] | None:
    if before == after:
        return None
    if before == {"integer"} and after == {"number"}:
        return ("WARN", "widened (integer accepts a subset of number)")
    if before < after:
        return ("WARN", "widened (type union gained options)")
    return ("BREAKING", "narrowed or replaced")


def _hashable(v: Any) -> Any:
    if isinstance(v, (dict, list)):
        return repr(v)
    return v


# -- rename heuristic -----------------------------------------------------------------------


def _rename_confidence(
    old_name: str, new_name: str, old_schema: dict[str, Any], new_schema: dict[str, Any]
) -> float | None:
    old_types = _type_set(old_schema)
    new_types = _type_set(new_schema)
    if old_types and new_types and old_types != new_types:
        return None  # hard gate: a rename does not also change type

    name_sim = difflib.SequenceMatcher(None, old_name.lower(), new_name.lower()).ratio()
    old_desc = str(old_schema.get("description") or "")
    new_desc = str(new_schema.get("description") or "")
    if old_desc or new_desc:
        desc_sim = difflib.SequenceMatcher(None, old_desc.lower(), new_desc.lower()).ratio()
        confidence = 0.6 * name_sim + 0.4 * desc_sim
    else:
        desc_sim = None
        confidence = name_sim

    if name_sim < RENAME_NAME_SIM_FLOOR and (desc_sim is None or desc_sim < RENAME_DESC_SIM_FLOOR):
        return None
    return confidence


def _match_renames(
    removed: list[str],
    added: list[str],
    before_props: dict[str, dict[str, Any]],
    after_props: dict[str, dict[str, Any]],
) -> tuple[list[tuple[str, str, float]], list[str], list[str]]:
    if not removed or not added:
        return [], list(removed), list(added)

    candidates: list[tuple[float, str, str]] = []
    for old in removed:
        for new in added:
            conf = _rename_confidence(old, new, before_props[old], after_props[new])
            if conf is not None and conf >= RENAME_CONFIDENCE_THRESHOLD:
                candidates.append((conf, old, new))
    candidates.sort(key=lambda c: -c[0])

    used_old: set[str] = set()
    used_new: set[str] = set()
    pairs: list[tuple[str, str, float]] = []
    for conf, old, new in candidates:
        if old in used_old or new in used_new:
            continue
        pairs.append((old, new, conf))
        used_old.add(old)
        used_new.add(new)

    leftover_removed = [n for n in removed if n not in used_old]
    leftover_added = [n for n in added if n not in used_new]
    return pairs, leftover_removed, leftover_added


# -- node-level diff (recurses through object properties / array items) --------------------------


def _diff_type(tool: str, pointer: str, before: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    classification = _classify_type_change(_type_set(before), _type_set(after))
    if classification is None:
        return []
    severity, kind = classification
    return [
        Finding(
            severity,
            "TYPE_CHANGED",
            tool=tool,
            path=f"{pointer}/type",
            message=f"type {kind}: {sorted(_type_set(before)) or 'any'} -> {sorted(_type_set(after)) or 'any'}",
            before=sorted(_type_set(before)),
            after=sorted(_type_set(after)),
        )
    ]


def _diff_enum(tool: str, pointer: str, before: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    b_enum, a_enum = before.get("enum"), after.get("enum")
    if b_enum is None and a_enum is None:
        return []
    b_set = {_hashable(v) for v in (b_enum or [])}
    a_set = {_hashable(v) for v in (a_enum or [])}
    findings: list[Finding] = []
    removed, added = b_set - a_set, a_set - b_set
    if removed:
        findings.append(
            Finding(
                "BREAKING",
                "ENUM_VALUE_REMOVED",
                tool=tool,
                path=f"{pointer}/enum",
                message=f"enum values removed, callers using them will now be rejected: {sorted(removed, key=str)}",
                before=b_enum,
                after=a_enum,
            )
        )
    if added:
        findings.append(
            Finding(
                "INFO",
                "ENUM_VALUE_ADDED",
                tool=tool,
                path=f"{pointer}/enum",
                message=f"enum values added: {sorted(added, key=str)}",
                before=b_enum,
                after=a_enum,
            )
        )
    return findings


def _diff_constraints(tool: str, pointer: str, before: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for key in ("maximum", "maxLength", "exclusiveMaximum"):
        b, a = before.get(key), after.get(key)
        if a is not None and isinstance(a, (int, float)) and (b is None or a < b):
            findings.append(
                Finding(
                    "WARN",
                    "CONSTRAINT_TIGHTENED",
                    tool=tool,
                    path=f"{pointer}/{key}",
                    message=f"{key} tightened from {b} to {a}",
                    before=b,
                    after=a,
                )
            )
    for key in ("minimum", "minLength", "exclusiveMinimum"):
        b, a = before.get(key), after.get(key)
        if a is not None and isinstance(a, (int, float)) and (b is None or a > b):
            findings.append(
                Finding(
                    "WARN",
                    "CONSTRAINT_TIGHTENED",
                    tool=tool,
                    path=f"{pointer}/{key}",
                    message=f"{key} tightened from {b} to {a}",
                    before=b,
                    after=a,
                )
            )
    for key in ("pattern", "format"):
        b, a = before.get(key), after.get(key)
        if a is not None and a != b:
            verb = "added" if b is None else "changed"
            findings.append(
                Finding(
                    "WARN",
                    "CONSTRAINT_TIGHTENED",
                    tool=tool,
                    path=f"{pointer}/{key}",
                    message=f"{key} {verb}: {b!r} -> {a!r} (treated as tightening; loosening isn't distinguished)",
                    before=b,
                    after=a,
                )
            )
    return findings


def _diff_default(tool: str, pointer: str, before: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    b = before.get("default", _MISSING)
    a = after.get("default", _MISSING)
    if a is _MISSING and b is _MISSING:
        return []
    if a == b:
        return []
    return [
        Finding(
            "WARN",
            "DEFAULT_CHANGED",
            tool=tool,
            path=f"{pointer}/default",
            message=f"default changed from {(None if b is _MISSING else b)!r} to {(None if a is _MISSING else a)!r}",
            before=None if b is _MISSING else b,
            after=None if a is _MISSING else a,
        )
    ]


def _diff_additional_properties(
    tool: str, pointer: str, before: dict[str, Any], after: dict[str, Any]
) -> list[Finding]:
    b = before.get("additionalProperties", True)
    a = after.get("additionalProperties", True)
    b_allows = b is True or isinstance(b, dict)
    a_allows = a is True or isinstance(a, dict)
    if b_allows and a is False:
        return [
            Finding(
                "BREAKING",
                "ADDITIONAL_PROPERTIES_RESTRICTED",
                tool=tool,
                path=f"{pointer}/additionalProperties",
                message="additionalProperties changed from allowed to false; extra fields will now be rejected",
                before=b,
                after=a,
            )
        ]
    _ = a_allows  # loosening (false -> true) is intentionally not flagged; see limitations
    return []


def _diff_properties(tool: str, pointer: str, before: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    b_props: dict[str, dict[str, Any]] = {
        k: v for k, v in (before.get("properties") or {}).items() if isinstance(v, dict)
    }
    a_props: dict[str, dict[str, Any]] = {
        k: v for k, v in (after.get("properties") or {}).items() if isinstance(v, dict)
    }
    b_required = set(before.get("required") or [])
    a_required = set(after.get("required") or [])

    removed_names = [n for n in b_props if n not in a_props]
    added_names = [n for n in a_props if n not in b_props]
    common_names = [n for n in b_props if n in a_props]

    findings: list[Finding] = []
    renamed_pairs, leftover_removed, leftover_added = _match_renames(removed_names, added_names, b_props, a_props)

    for old_name, new_name, confidence in renamed_pairs:
        findings.append(
            Finding(
                "BREAKING",
                "PARAM_RENAMED",
                tool=tool,
                path=f"{pointer}/properties/{new_name}",
                message=(
                    f"parameter {old_name!r} looks renamed to {new_name!r} (confidence={confidence:.2f}); "
                    f"callers still sending {old_name!r} will break"
                ),
                before={"name": old_name, **b_props[old_name]},
                after={"name": new_name, **a_props[new_name]},
            )
        )

    for name in leftover_removed:
        findings.append(
            Finding(
                "BREAKING",
                "PARAM_REMOVED",
                tool=tool,
                path=f"{pointer}/properties/{name}",
                message=f"parameter {name!r} was removed",
                before=b_props[name],
                after=None,
            )
        )

    for name in leftover_added:
        is_required = name in a_required
        findings.append(
            Finding(
                "BREAKING" if is_required else "INFO",
                "PARAM_ADDED_REQUIRED" if is_required else "PARAM_ADDED_OPTIONAL",
                tool=tool,
                path=f"{pointer}/properties/{name}",
                message=f"{'required' if is_required else 'optional'} parameter {name!r} was added",
                before=None,
                after=a_props[name],
            )
        )

    for name in common_names:
        was_required, is_required = name in b_required, name in a_required
        if is_required and not was_required:
            findings.append(
                Finding(
                    "BREAKING",
                    "REQUIRED_ADDED",
                    tool=tool,
                    path=f"{pointer}/properties/{name}",
                    message=f"parameter {name!r} became required",
                    before=False,
                    after=True,
                )
            )
        elif was_required and not is_required:
            findings.append(
                Finding(
                    "INFO",
                    "REQUIRED_REMOVED",
                    tool=tool,
                    path=f"{pointer}/properties/{name}",
                    message=f"parameter {name!r} is no longer required",
                    before=True,
                    after=False,
                )
            )
        findings.extend(_diff_node(tool, f"{pointer}/properties/{name}", b_props[name], a_props[name]))

    return findings


def _diff_node(tool: str, pointer: str, before: Any, after: Any) -> list[Finding]:
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}

    findings = [
        *_diff_type(tool, pointer, before, after),
        *_diff_enum(tool, pointer, before, after),
        *_diff_constraints(tool, pointer, before, after),
        *_diff_default(tool, pointer, before, after),
    ]

    before_types, after_types = _type_set(before), _type_set(after)
    if "object" in before_types or "object" in after_types or "properties" in before or "properties" in after:
        findings.extend(_diff_properties(tool, pointer, before, after))
        findings.extend(_diff_additional_properties(tool, pointer, before, after))
    if "array" in before_types or "array" in after_types or "items" in before or "items" in after:
        b_items, a_items = before.get("items"), after.get("items")
        if isinstance(b_items, dict) or isinstance(a_items, dict):
            findings.extend(_diff_node(tool, f"{pointer}/items", b_items, a_items))

    return findings


def diff_json_schema(
    tool: str, pointer: str, before_schema: dict[str, Any], after_schema: dict[str, Any]
) -> list[Finding]:
    """Diff two JSON Schema documents (already local-$ref-resolved) rooted at `pointer`."""
    return _diff_node(tool, pointer, before_schema, after_schema)


def _diff_annotations(tool: str, before_ann: dict[str, Any], after_ann: dict[str, Any]) -> list[Finding]:
    before_ann, after_ann = before_ann or {}, after_ann or {}
    findings: list[Finding] = []
    for key in sorted(set(before_ann) | set(after_ann)):
        b, a = before_ann.get(key), after_ann.get(key)
        if b == a:
            continue
        path = f"/annotations/{key}"
        if key == "readOnlyHint" and b is True and a is False:
            findings.append(
                Finding(
                    "SECURITY",
                    "ANNOTATION_CHANGED",
                    tool=tool,
                    path=path,
                    message="readOnlyHint flipped true -> false: a tool advertised as read-only can now mutate state",
                    before=b,
                    after=a,
                )
            )
        elif key == "destructiveHint" and b is False and a is True:
            findings.append(
                Finding(
                    "SECURITY",
                    "ANNOTATION_CHANGED",
                    tool=tool,
                    path=path,
                    message="destructiveHint flipped false -> true: a non-destructive tool can now do damage",
                    before=b,
                    after=a,
                )
            )
        else:
            findings.append(
                Finding(
                    "INFO",
                    "ANNOTATION_CHANGED",
                    tool=tool,
                    path=path,
                    message=f"annotation {key!r} changed from {b!r} to {a!r}",
                    before=b,
                    after=a,
                )
            )
    return findings


def diff_tool(tool_name: str, before_tool: dict[str, Any], after_tool: dict[str, Any]) -> list[Finding]:
    """Full structural diff of one tool definition: inputSchema, outputSchema, annotations.

    Does not diff `description` (see `description_diff.py`) or tool presence (`TOOL_ADDED` /
    `TOOL_REMOVED`, handled by `differ.py` since that's about a *pair* of recordings, not one
    tool's before/after)."""
    before_input = resolve_local_refs(before_tool.get("inputSchema") or {}, before_tool.get("inputSchema") or {})
    after_input = resolve_local_refs(after_tool.get("inputSchema") or {}, after_tool.get("inputSchema") or {})
    findings = diff_json_schema(tool_name, "/inputSchema", before_input, after_input)

    if "outputSchema" in before_tool or "outputSchema" in after_tool:
        before_output = resolve_local_refs(before_tool.get("outputSchema") or {}, before_tool.get("outputSchema") or {})
        after_output = resolve_local_refs(after_tool.get("outputSchema") or {}, after_tool.get("outputSchema") or {})
        findings.extend(diff_json_schema(tool_name, "/outputSchema", before_output, after_output))

    findings.extend(
        _diff_annotations(tool_name, before_tool.get("annotations") or {}, after_tool.get("annotations") or {})
    )
    return findings


__all__ = ["diff_json_schema", "diff_tool", "resolve_local_refs"]
