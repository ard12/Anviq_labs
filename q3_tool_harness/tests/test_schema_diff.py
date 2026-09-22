"""One positive + one negative test per schema_diff rule_id, plus the rename false-positive test
the brief calls out explicitly."""

from __future__ import annotations

from harness.diff.schema_diff import diff_tool


def _tool(**input_schema_kwargs) -> dict:
    return {
        "name": "t",
        "description": "d",
        "inputSchema": {"type": "object", "properties": {}, "required": [], **input_schema_kwargs},
    }


def _rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


def _find(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# -- PARAM_ADDED_REQUIRED / PARAM_ADDED_OPTIONAL / PARAM_REMOVED -------------------------------


def test_param_added_required_positive():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}, "b": {"type": "string"}}, required=["a", "b"])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "PARAM_ADDED_REQUIRED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"
    assert hits[0].path == "/inputSchema/properties/b"


def test_param_added_required_negative_when_optional():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}, "b": {"type": "string"}}, required=["a"])
    findings = diff_tool("t", before, after)
    assert _find(findings, "PARAM_ADDED_REQUIRED") == []


def test_param_added_optional_positive():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}, "b": {"type": "string"}}, required=["a"])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "PARAM_ADDED_OPTIONAL")
    assert len(hits) == 1
    assert hits[0].severity == "INFO"


def test_param_added_optional_negative_when_no_new_param():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}}, required=["a"])
    findings = diff_tool("t", before, after)
    assert _find(findings, "PARAM_ADDED_OPTIONAL") == []


def test_param_removed_positive():
    before = _tool(properties={"a": {"type": "string"}, "b": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "string"}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "PARAM_REMOVED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"


def test_param_removed_negative_when_untouched():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "string"}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "PARAM_REMOVED") == []


# -- PARAM_RENAMED -------------------------------------------------------------------------------


def test_param_renamed_positive():
    before = _tool(properties={"path": {"type": "string", "description": "Absolute path."}}, required=["path"])
    after = _tool(properties={"file_path": {"type": "string", "description": "Absolute path."}}, required=["file_path"])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "PARAM_RENAMED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"
    assert hits[0].path == "/inputSchema/properties/file_path"
    assert _find(findings, "PARAM_REMOVED") == []
    assert _find(findings, "PARAM_ADDED_REQUIRED") == []


def test_param_renamed_negative_unrelated_params_not_merged():
    """Removing `priority` and adding an unrelated, differently-typed `recipient` must NOT be
    reported as a rename -- they should show up as a plain removal + a plain addition."""
    before = _tool(
        properties={"priority": {"type": "number", "description": "Send priority, 0-10."}},
        required=[],
    )
    after = _tool(
        properties={"recipient": {"type": "string", "description": "Email address to notify."}},
        required=["recipient"],
    )
    findings = diff_tool("t", before, after)
    assert _find(findings, "PARAM_RENAMED") == []
    assert len(_find(findings, "PARAM_REMOVED")) == 1
    assert len(_find(findings, "PARAM_ADDED_REQUIRED")) == 1


def test_param_renamed_negative_same_type_but_unrelated_names():
    """Same type on both sides isn't enough on its own: names/descriptions must also be similar."""
    before = _tool(properties={"priority": {"type": "number"}}, required=[])
    after = _tool(properties={"timeout_ms": {"type": "number"}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "PARAM_RENAMED") == []


# -- TYPE_CHANGED ---------------------------------------------------------------------------------


def test_type_changed_narrowing_is_breaking():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "number"}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "TYPE_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"


def test_type_changed_widening_integer_to_number_is_warn():
    before = _tool(properties={"a": {"type": "integer"}}, required=[])
    after = _tool(properties={"a": {"type": "number"}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "TYPE_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "WARN"


def test_type_changed_widening_union_is_warn():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": ["string", "null"]}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "TYPE_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "WARN"


def test_type_unchanged_is_negative():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "string"}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "TYPE_CHANGED") == []


# -- ENUM_VALUE_REMOVED / ENUM_VALUE_ADDED --------------------------------------------------------


def test_enum_value_removed_positive():
    before = _tool(properties={"a": {"type": "string", "enum": ["x", "y"]}}, required=[])
    after = _tool(properties={"a": {"type": "string", "enum": ["x"]}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "ENUM_VALUE_REMOVED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"


def test_enum_value_removed_negative_when_only_added():
    before = _tool(properties={"a": {"type": "string", "enum": ["x"]}}, required=[])
    after = _tool(properties={"a": {"type": "string", "enum": ["x", "y"]}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "ENUM_VALUE_REMOVED") == []


def test_enum_value_added_positive():
    before = _tool(properties={"a": {"type": "string", "enum": ["x"]}}, required=[])
    after = _tool(properties={"a": {"type": "string", "enum": ["x", "y"]}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "ENUM_VALUE_ADDED")
    assert len(hits) == 1
    assert hits[0].severity == "INFO"


def test_enum_value_added_negative_when_unchanged():
    before = _tool(properties={"a": {"type": "string", "enum": ["x"]}}, required=[])
    after = _tool(properties={"a": {"type": "string", "enum": ["x"]}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "ENUM_VALUE_ADDED") == []


# -- REQUIRED_ADDED / REQUIRED_REMOVED ------------------------------------------------------------


def test_required_added_positive():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "string"}}, required=["a"])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "REQUIRED_ADDED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"


def test_required_added_negative_when_already_required():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}}, required=["a"])
    findings = diff_tool("t", before, after)
    assert _find(findings, "REQUIRED_ADDED") == []


def test_required_removed_positive():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "REQUIRED_REMOVED")
    assert len(hits) == 1
    assert hits[0].severity == "INFO"


def test_required_removed_negative_when_still_required():
    before = _tool(properties={"a": {"type": "string"}}, required=["a"])
    after = _tool(properties={"a": {"type": "string"}}, required=["a"])
    findings = diff_tool("t", before, after)
    assert _find(findings, "REQUIRED_REMOVED") == []


# -- CONSTRAINT_TIGHTENED --------------------------------------------------------------------------


def test_constraint_tightened_max_length_positive():
    before = _tool(properties={"a": {"type": "string", "maxLength": 100}}, required=[])
    after = _tool(properties={"a": {"type": "string", "maxLength": 10}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "CONSTRAINT_TIGHTENED")
    assert len(hits) == 1
    assert hits[0].severity == "WARN"


def test_constraint_tightened_minimum_positive():
    before = _tool(properties={"a": {"type": "number", "minimum": 0}}, required=[])
    after = _tool(properties={"a": {"type": "number", "minimum": 5}}, required=[])
    findings = diff_tool("t", before, after)
    assert len(_find(findings, "CONSTRAINT_TIGHTENED")) == 1


def test_constraint_tightened_pattern_positive():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "string", "pattern": "^[a-z]+$"}}, required=[])
    findings = diff_tool("t", before, after)
    assert len(_find(findings, "CONSTRAINT_TIGHTENED")) == 1


def test_constraint_tightened_negative_when_loosened():
    before = _tool(properties={"a": {"type": "string", "maxLength": 10}}, required=[])
    after = _tool(properties={"a": {"type": "string", "maxLength": 100}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "CONSTRAINT_TIGHTENED") == []


# -- DEFAULT_CHANGED --------------------------------------------------------------------------------


def test_default_changed_positive():
    before = _tool(properties={"a": {"type": "string", "default": "x"}}, required=[])
    after = _tool(properties={"a": {"type": "string", "default": "y"}}, required=[])
    findings = diff_tool("t", before, after)
    hits = _find(findings, "DEFAULT_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "WARN"


def test_default_changed_negative_when_same():
    before = _tool(properties={"a": {"type": "string", "default": "x"}}, required=[])
    after = _tool(properties={"a": {"type": "string", "default": "x"}}, required=[])
    findings = diff_tool("t", before, after)
    assert _find(findings, "DEFAULT_CHANGED") == []


# -- ADDITIONAL_PROPERTIES_RESTRICTED ----------------------------------------------------------------


def test_additional_properties_restricted_positive():
    before = _tool(properties={"a": {"type": "string"}}, required=[])
    after = _tool(properties={"a": {"type": "string"}}, required=[], additionalProperties=False)
    findings = diff_tool("t", before, after)
    hits = _find(findings, "ADDITIONAL_PROPERTIES_RESTRICTED")
    assert len(hits) == 1
    assert hits[0].severity == "BREAKING"


def test_additional_properties_restricted_negative_when_relaxed():
    before = _tool(properties={"a": {"type": "string"}}, required=[], additionalProperties=False)
    after = _tool(properties={"a": {"type": "string"}}, required=[], additionalProperties=True)
    findings = diff_tool("t", before, after)
    assert _find(findings, "ADDITIONAL_PROPERTIES_RESTRICTED") == []


# -- nested recursion -------------------------------------------------------------------------------


def test_nested_object_property_change_has_correct_pointer():
    before = _tool(properties={"opts": {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}})
    after = _tool(properties={"opts": {"type": "object", "properties": {}, "required": []}})
    findings = diff_tool("t", before, after)
    hits = _find(findings, "PARAM_REMOVED")
    assert len(hits) == 1
    assert hits[0].path == "/inputSchema/properties/opts/properties/x"


def test_nested_array_items_change_has_correct_pointer():
    before = _tool(properties={"tags": {"type": "array", "items": {"type": "string"}}})
    after = _tool(properties={"tags": {"type": "array", "items": {"type": "number"}}})
    findings = diff_tool("t", before, after)
    hits = _find(findings, "TYPE_CHANGED")
    assert any(h.path == "/inputSchema/properties/tags/items/type" for h in hits)


# -- ANNOTATION_CHANGED --------------------------------------------------------------------------------


def test_annotation_changed_readonly_flip_is_security():
    before = {**_tool(), "annotations": {"readOnlyHint": True}}
    after = {**_tool(), "annotations": {"readOnlyHint": False}}
    findings = diff_tool("t", before, after)
    hits = _find(findings, "ANNOTATION_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "SECURITY"


def test_annotation_changed_destructive_flip_is_security():
    before = {**_tool(), "annotations": {"destructiveHint": False}}
    after = {**_tool(), "annotations": {"destructiveHint": True}}
    findings = diff_tool("t", before, after)
    hits = _find(findings, "ANNOTATION_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "SECURITY"


def test_annotation_changed_negative_when_unchanged():
    before = {**_tool(), "annotations": {"readOnlyHint": True, "destructiveHint": False}}
    after = {**_tool(), "annotations": {"readOnlyHint": True, "destructiveHint": False}}
    findings = diff_tool("t", before, after)
    assert _find(findings, "ANNOTATION_CHANGED") == []


def test_annotation_changed_other_key_is_info_not_security():
    before = {**_tool(), "annotations": {"idempotentHint": False}}
    after = {**_tool(), "annotations": {"idempotentHint": True}}
    findings = diff_tool("t", before, after)
    hits = _find(findings, "ANNOTATION_CHANGED")
    assert len(hits) == 1
    assert hits[0].severity == "INFO"
