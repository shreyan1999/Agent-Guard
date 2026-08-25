"""The schema contract the condition builder is written against.

The builder never hardcodes a grammar: it renders clauses from each operator's
``template`` and reads them back with its ``pattern``. These tests hold both
ends of that contract, so the editor cannot emit something the policy engine
rejects, and cannot fail to re-open a condition it wrote itself.

The frontend keeps a copy of this schema as a test fixture. The last test in
this file compares that fixture against the live endpoint, so the two cannot
drift apart silently.
"""

import json
import re
from pathlib import Path

import pytest

# One representative value per operator kind.
SAMPLE = {
    "single": ("action.type", "drop"),
    "list": ("action.type", "'drop','delete'"),
    "number": ("agent.trust_score", "0.5"),
    "none": ("input_text.has_pii", ""),
}


@pytest.fixture
def schema(client):
    return client.get("/policies/schema").json()


def render(op):
    field, value = SAMPLE[op["value"]]
    return op["template"].format(field=field, value=value)


# ── Every operator must survive the full loop ────────────────────────────────

def test_every_operator_renders_a_condition_the_linter_accepts(schema, app_module):
    for op in schema["operators"]:
        condition = render(op)
        assert app_module._lint_condition(condition) == [], \
            f"operator {op['id']!r} renders {condition!r}, which the linter rejects"


def test_every_operator_can_read_its_own_output(schema):
    for op in schema["operators"]:
        condition = render(op)
        assert re.match(op["pattern"], condition), \
            f"operator {op['id']!r} cannot parse its own output {condition!r}"


def test_patterns_are_unambiguous(schema):
    """Exactly one operator may claim any rendered clause."""
    for op in schema["operators"]:
        condition = render(op)
        matches = [o["id"] for o in schema["operators"] if re.match(o["pattern"], condition)]
        assert matches == [op["id"]], f"{condition!r} matched {matches}"


def test_comparison_operators_do_not_shadow_each_other(schema):
    """`>` must not swallow `>=`, and `<` must not swallow `<=`."""
    by_id = {o["id"]: o for o in schema["operators"]}
    for op_id, text in [
        ("gt", "agent.trust_score > 0.5"), ("gte", "agent.trust_score >= 0.5"),
        ("lt", "agent.trust_score < 0.5"), ("lte", "agent.trust_score <= 0.5"),
    ]:
        matches = [i for i, o in by_id.items() if re.match(o["pattern"], text)]
        assert matches == [op_id], f"{text!r} matched {matches}"


def test_patterns_read_the_shipped_default_policy(schema, app_module):
    """The builder must be able to open the policy the project ships with."""
    for rule in app_module.DEFAULT_POLICY["rules"]:
        condition = rule["condition"]
        assert any(re.match(o["pattern"], condition) for o in schema["operators"]), \
            f"builder cannot represent shipped condition {condition!r}"


def test_a_rendered_condition_actually_enforces(client, schema):
    """End to end: a clause the builder could emit must reach a real denial."""
    client.post("/policies", json={
        "name": "built", "default_action": "allow",
        "rules": [{"name": "no-drop", "condition": "action.type == 'drop'",
                   "action": "deny"}],
    })
    denied = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "built",
        "action": "drop", "agent_id": "data-agent",
    }).json()
    assert denied["allowed"] is False
    assert denied["rule"] == "no-drop"


# ── Value safety ─────────────────────────────────────────────────────────────

def test_schema_declares_the_characters_that_break_any_clause(schema):
    forbidden = schema["value_forbidden"]
    assert "'" in forbidden["characters"]
    assert '"' in forbidden["characters"]
    assert " and " in forbidden["substrings"]
    assert " or " in forbidden["substrings"]


def test_bracket_is_forbidden_only_for_the_list_operator(schema, app_module):
    """`]` truncates an `in` list, but a quoted `==` value carries it fine."""
    assert "]" not in schema["value_forbidden"]["characters"]
    assert "]" in schema["value_forbidden"]["by_operator"]["in"]["characters"]

    assert app_module._lint_condition("action.type == 'a]b'") == []
    assert app_module._lint_condition('action.type in ["a]b"]') != []


@pytest.mark.parametrize("value", ["it's", 'say "hi"', "read and write", "read or write"])
def test_forbidden_values_would_produce_a_dead_rule(app_module, value):
    """Why the builder blocks these: AGT accepts them and they never match."""
    condition = f"action.type == '{value}'"
    assert app_module._lint_condition(condition) != [], \
        f"expected {condition!r} to be unparsable"


# ── Field coverage ───────────────────────────────────────────────────────────

def test_every_field_has_a_usable_operator(schema):
    by_type = {}
    for op in schema["operators"]:
        for t in op["types"]:
            by_type.setdefault(t, []).append(op["id"])
    for field in schema["fields"]:
        assert by_type.get(field["type"]), \
            f"field {field['path']!r} has type {field['type']!r} with no operator"


def test_value_kinds_are_ones_the_builder_understands(schema):
    for op in schema["operators"]:
        assert op["value"] in {"single", "list", "number", "none"}, op["id"]


# ── Frontend fixture drift ───────────────────────────────────────────────────

def test_frontend_fixture_matches_the_live_schema(schema, frontend_src):
    """The builder's unit tests must not run against a stale grammar."""
    source = (frontend_src / "panels" / "policy" / "conditionModel.test.mjs").read_text(
        encoding="utf-8")

    live_ids = [o["id"] for o in schema["operators"]]
    for op_id in live_ids:
        assert f"id: '{op_id}'" in source, \
            f"frontend fixture is missing operator {op_id!r}"

    fixture_ids = re.findall(r"\{ id: '(\w+)'", source)
    assert fixture_ids == live_ids, \
        f"frontend fixture operators {fixture_ids} do not match backend {live_ids}"

    for op in schema["operators"]:
        assert op["template"] in source, \
            f"frontend fixture has a different template for {op['id']!r}"
