"""A condition can name a field that does not exist, and nothing said so.

The linter checked the *shape* of a clause — `field == 'value'` — and never the
field. So `action == 'export'`, which is how anyone would first write it, passed
validation, saved, reported `enabled: true`, and matched nothing. The real field
is `action.type`, and it is the first entry in the platform's own
`/policies/schema`. One dot between a rule that enforces something and a rule
that is decoration.

Two design points the tests below pin, because both are easy to get wrong in the
other direction.

**It warns; it does not block.** `_lint_rules` is a hard gate — a policy failing
it is refused at `POST /policies`. An unparsable atom deserves that because AGT
*cannot* evaluate it. An unrecognised field does not: `/tools/call` forwards its
`kwargs` into the policy context verbatim, so a caller can legitimately supply a
field no schema here lists. Refusing those would trade a silent no-op for a
wrongly rejected policy, which is worse.

**One list, not two.** The field table now lives in `_POLICY_FIELDS` and both
`/policies/schema` and the linter read it. A second copy would drift, and a
linter that disagrees with the editor's own field picker is the same class of
bug wearing a different hat.
"""

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def save(client, name, condition, **extra):
    return client.post("/policies", json={
        "name": name, "description": "x", "default_action": "allow",
        "conflict_strategy": "deny_overrides",
        "rules": [{"name": "r", "condition": condition, "action": "deny",
                   "priority": 15, **extra}]})


def warnings_for(client, name, condition, **extra):
    return save(client, name, condition, **extra).json().get("warnings", [])


# ── the near miss ─────────────────────────────────────────────────────────────

def test_a_field_that_does_not_exist_is_reported():
    unknown = main._unknown_fields("action == 'export'")
    assert [u["path"] for u in unknown] == ["action"]


def test_it_says_what_was_probably_meant():
    """`action` is one dot from `action.type`. A prefix match is the case worth
    catching, so it is preferred over edit distance."""
    assert main._unknown_fields("action == 'export'")[0]["did_you_mean"] \
        == ["action.type"]


def test_the_correct_form_is_silent():
    assert main._unknown_fields("action.type == 'export'") == []


@pytest.mark.parametrize("field", [f["path"] for f in main._POLICY_FIELDS])
def test_every_documented_field_passes_its_own_check(field):
    """A linter that flags the fields the editor offers is worse than none."""
    assert main._unknown_fields(f"{field} == 'x'") == []


def test_the_schema_and_the_linter_read_the_same_list():
    """The endpoint's docstring has always claimed this. Now it is true."""
    from starlette.testclient import TestClient as TC
    main.reset_state()
    served = [f["path"] for f in TC(main.app).get("/policies/schema").json()["fields"]]
    assert served == [f["path"] for f in main._POLICY_FIELDS]
    assert set(served) == set(main._POLICY_FIELD_PATHS)


# ── every clause form, and both joiners ──────────────────────────────────────

@pytest.mark.parametrize("condition,expected", [
    ("agent.nope == 'x'", ["agent.nope"]),
    ("agent.nope != 'x'", ["agent.nope"]),
    ("agent.nope in ['a','b']", ["agent.nope"]),
    ("agent.nope > 3", ["agent.nope"]),
    ("agent.nope", ["agent.nope"]),
])
def test_it_reads_the_field_out_of_every_clause_form(condition, expected):
    assert [u["path"] for u in main._unknown_fields(condition)] == expected


def test_it_checks_both_sides_of_a_joiner():
    unknown = main._unknown_fields(
        "agent.trust_score > 0.5 and tool.nope == 'x'")
    assert [u["path"] for u in unknown] == ["tool.nope"]


def test_a_field_named_twice_is_reported_once():
    unknown = main._unknown_fields("a.b == 'x' or a.b == 'y'")
    assert [u["path"] for u in unknown] == ["a.b"]


def test_an_unparsable_atom_is_left_to_the_other_check():
    """The two checks answer different questions and must not double-report."""
    condition = "agent.trust_score =~ /x/"
    assert main._lint_condition(condition) == [condition]


# ── advisory, not a gate ─────────────────────────────────────────────────────

def test_a_policy_with_an_unknown_field_still_saves(client):
    """The load-bearing constraint. `kwargs` are forwarded into the policy
    context verbatim, so an unrecognised field may be one the caller supplies —
    refusing it would be a worse failure than the one being fixed."""
    assert save(client, "typo", "action == 'export'").status_code == 200


def test_the_warning_comes_back_with_the_saved_policy(client):
    found = warnings_for(client, "typo", "action == 'export'")
    assert len(found) == 1
    assert found[0]["kind"] == "unknown_field"
    assert found[0]["unknown_field"] == "action"
    assert "action.type" in found[0]["effect"]


def test_a_caller_supplied_field_is_warned_about_not_refused(client):
    """`arguments.amount` is plausible for an MCP call and AGT would resolve
    it. The warning has to admit that rather than claim the rule is dead."""
    r = save(client, "kwargs-rule", "arguments.amount > 1000")
    assert r.status_code == 200
    effect = r.json()["warnings"][0]["effect"]
    assert "unless the caller supplies it" in effect


def test_a_correct_policy_warns_about_nothing(client):
    assert warnings_for(client, "fine", "action.type == 'export'") == []


def test_an_unparsable_condition_is_still_refused(client):
    """The existing hard gate must not have been softened by any of this."""
    assert save(client, "broken", "agent.trust_score =~ /x/").status_code == 400


def test_validate_reports_it_without_calling_the_policy_invalid(client):
    """`valid` tracks the blocking check. An unknown field is a warning, so the
    draft is still valid — saying otherwise would make the two indistinguishable."""
    body = client.post("/policies/validate", json={
        "name": "draft", "description": "x", "default_action": "allow",
        "rules": [{"name": "r", "condition": "action == 'export'",
                   "action": "deny"}]}).json()
    assert body["valid"] is True
    assert any(w.get("kind") == "unknown_field" for w in body["warnings"])


# ── the shape the UI reads ───────────────────────────────────────────────────

def test_every_warning_carries_the_keys_the_panel_reads(client):
    """PolicyPanel maps over these without guarding each key."""
    found = warnings_for(client, "mixed", "action == 'export'",
                         stage="post_tool", enabled=False)
    assert len(found) >= 3                      # unknown field, stage, disabled
    for warning in found:
        assert {"rule", "condition", "kind", "unparsable", "effect"} <= set(warning)
        assert isinstance(warning["unparsable"], list)
        assert warning["effect"]


def test_the_kinds_are_distinguishable(client):
    kinds = {w["kind"] for w in warnings_for(
        client, "mixed2", "action == 'export'", stage="post_tool", enabled=False)}
    assert kinds == {"unknown_field", "stage", "disabled"}


def test_the_shipped_policies_are_clean(client):
    """If the default policy tripped its own linter, the check is wrong."""
    for name in main._policies.names():
        for rule in main._policies.read(name).get("rules", []):
            assert main._unknown_fields(rule.get("condition", "")) == [], \
                f"{name}/{rule.get('name')}"
