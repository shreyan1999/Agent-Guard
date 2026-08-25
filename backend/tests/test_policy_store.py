"""Phase 0: file-backed policy store, inheritance, and the editor's API.

`extends` only works if every policy sits in one directory under a stable
filename — AGT refuses a parent that resolves outside the child's directory.
These tests pin that down, along with the three ways a rule can silently fail
to fire.
"""

import pytest
import yaml

from policy_store import PolicyStore, PolicyError


BASE = {
    "default_action": "allow",
    "rules": [{"name": "block-drop", "condition": "action.type == 'drop'",
               "action": "deny", "priority": 10}],
}


def make(client, name, **doc):
    body = {"name": name, "default_action": "allow", "rules": [], **doc}
    return client.post("/policies", json=body)


# ── Persistence ──────────────────────────────────────────────────────────────

def test_policies_are_written_as_yaml_files(client, policy_dir):
    assert make(client, "on-disk", **BASE).status_code == 200
    path = policy_dir / "on-disk.yaml"
    assert path.is_file()
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["name"] == "on-disk"
    assert doc["rules"][0]["name"] == "block-drop"


def test_default_policy_is_seeded_once_and_reused(client, policy_dir, app_module):
    """A restart must not clobber a policy the operator edited."""
    written = (policy_dir / "default-policy.yaml").read_text(encoding="utf-8")
    app_module.seed_state()          # simulate a second startup
    assert (policy_dir / "default-policy.yaml").read_text(encoding="utf-8") == written


def test_policy_survives_a_teardown_that_is_not_a_test_reset(client, policy_dir, app_module):
    make(client, "keeper", **BASE)
    app_module.teardown_state()      # what shutdown does
    assert (policy_dir / "keeper.yaml").is_file()


# ── Name safety ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", [
    "../escape", "nested/name", "back\\slash", "", ".", "..", "with space",
])
def test_unsafe_policy_names_are_rejected(client, name):
    r = client.post("/policies", json={"name": name, "default_action": "allow", "rules": []})
    assert r.status_code == 400


def test_store_rejects_traversal_directly(tmp_path):
    store = PolicyStore(tmp_path)
    with pytest.raises(PolicyError):
        store.path("../../etc/passwd")


# ── extends ──────────────────────────────────────────────────────────────────

def test_child_inherits_parent_rules(client):
    make(client, "base", **BASE)
    make(client, "child", extends=["base"],
         rules=[{"name": "own", "condition": "input_text.has_pii", "action": "deny"}])

    resolved = client.get("/policies/child/resolved").json()
    names = {r["name"]: r for r in resolved["rules"]}
    assert set(names) == {"block-drop", "own"}
    assert names["block-drop"]["inherited"] is True
    assert names["block-drop"]["origin"] == "base"
    assert names["own"]["inherited"] is False
    assert resolved["chain"] == ["base", "child"]


def test_inherited_rules_are_enforced(client):
    """Inheritance must reach the enforcement path, not just the view."""
    make(client, "base", **BASE)
    make(client, "child", extends=["base"])

    denied = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "child",
        "action": "drop", "agent_id": "data-agent",
    }).json()
    assert denied["allowed"] is False
    assert denied["rule"] == "block-drop"


def test_child_cannot_weaken_a_parent_deny(client):
    """AGT drops the rule and only logs; /resolved has to surface it."""
    make(client, "base", **BASE)
    make(client, "child", extends=["base"],
         rules=[{"name": "block-drop", "condition": "action.type == 'drop'",
                 "action": "allow", "priority": 99}])

    resolved = client.get("/policies/child/resolved").json()
    assert [r["action"] for r in resolved["rules"] if r["name"] == "block-drop"] == ["deny"]

    dropped = resolved["dropped_rules"]
    assert len(dropped) == 1
    assert dropped[0]["name"] == "block-drop"
    assert "additive-only" in dropped[0]["reason"]

    # And the weakening genuinely does not take effect.
    call = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "child",
        "action": "drop", "agent_id": "data-agent",
    }).json()
    assert call["allowed"] is False


def test_extending_a_missing_policy_is_rejected(client):
    r = make(client, "orphan", extends=["nope"])
    assert r.status_code == 400
    assert "nope" in r.json()["detail"]["error"]


def test_self_extension_is_rejected(client):
    assert make(client, "loop", extends=["loop"]).status_code == 400


def test_circular_extends_is_rejected(client):
    make(client, "a", **BASE)
    make(client, "b", extends=["a"])
    # Point a at b, closing the loop.
    r = client.put("/policies/a", json={
        "name": "a", "default_action": "allow", "extends": ["b"], "rules": [],
    })
    assert r.status_code == 400


def test_deleting_a_parent_is_refused_while_children_exist(client):
    make(client, "base", **BASE)
    make(client, "child", extends=["base"])

    r = client.delete("/policies/base")
    assert r.status_code == 409
    assert "child" in r.json()["detail"]

    assert client.delete("/policies/child").status_code == 200
    assert client.delete("/policies/base").status_code == 200


def test_dependents_are_reported_on_the_policy(client):
    make(client, "base", **BASE)
    make(client, "child", extends=["base"])
    assert client.get("/policies/base").json()["dependents"] == ["child"]


# ── Editing ──────────────────────────────────────────────────────────────────

def test_a_policy_can_be_edited(client):
    make(client, "editable", **BASE)
    r = client.put("/policies/editable", json={
        "name": "editable", "default_action": "deny",
        "rules": [{"name": "allow-read", "condition": "action.type == 'read'",
                   "action": "allow"}],
    })
    assert r.status_code == 200
    doc = client.get("/policies/editable").json()
    assert doc["default_action"] == "deny"
    assert [r["name"] for r in doc["rules"]] == ["allow-read"]


def test_editing_evicts_cached_callables(client, app_module):
    """A stale GovernedCallable would keep enforcing the old rules."""
    make(client, "mutable", default_action="allow", rules=[])
    client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "mutable",
        "action": "drop", "agent_id": "data-agent"})
    assert any(k[1] == "mutable" for k in app_module._governed_tools)

    client.put("/policies/mutable", json={
        "name": "mutable", "default_action": "allow",
        "rules": [{"name": "no-drop", "condition": "action.type == 'drop'",
                   "action": "deny"}]})

    after = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "mutable",
        "action": "drop", "agent_id": "data-agent"}).json()
    assert after["allowed"] is False
    assert after["rule"] == "no-drop"


def test_editing_a_missing_policy_is_404(client):
    r = client.put("/policies/ghost", json={
        "name": "ghost", "default_action": "allow", "rules": []})
    assert r.status_code == 404


# ── Conflict strategy and scope ──────────────────────────────────────────────

def test_conflict_strategy_reaches_the_engine(client):
    """allow_overrides must let an allow rule beat a deny rule."""
    rules = [
        {"name": "deny-drop", "condition": "action.type == 'drop'",
         "action": "deny", "priority": 10},
        {"name": "allow-drop", "condition": "action.type == 'drop'",
         "action": "allow", "priority": 1},
    ]
    make(client, "strict", conflict_strategy="deny_overrides", rules=rules)
    make(client, "lenient", conflict_strategy="allow_overrides", rules=rules)

    def verdict(policy):
        return client.post("/tools/call", json={
            "tool_name": "db_query", "policy_name": policy,
            "action": "drop", "agent_id": "data-agent"}).json()["allowed"]

    assert verdict("strict") is False
    assert verdict("lenient") is True


@pytest.mark.parametrize("bad", ["nonsense", "DENY_OVERRIDES", ""])
def test_unknown_conflict_strategy_is_rejected(client, bad):
    assert make(client, "bad-strategy", conflict_strategy=bad).status_code == 400


@pytest.mark.parametrize("bad", ["everywhere", "Global", ""])
def test_unknown_scope_is_rejected(client, bad):
    assert make(client, "bad-scope", scope=bad).status_code == 400


def test_valid_scopes_round_trip(client):
    for scope in ("global", "organization", "tenant", "agent"):
        name = f"scoped-{scope}"
        assert make(client, name, scope=scope).status_code == 200
        assert client.get(f"/policies/{name}").json()["scope"] == scope


# ── Full rule model ──────────────────────────────────────────────────────────

def test_all_rule_fields_round_trip(client):
    rule = {
        "name": "full", "condition": "action.type == 'send_email'",
        "action": "require_approval", "description": "Needs a human",
        "priority": 42, "stage": "pre_tool", "limit": "100/hour",
        "approvers": ["security@example.com"], "enabled": True,
    }
    assert make(client, "complete", rules=[rule]).status_code == 200
    stored = client.get("/policies/complete").json()["rules"][0]
    for key, value in rule.items():
        assert stored[key] == value, key


def test_non_pre_tool_stage_is_warned_about(client):
    """The second silent-dead-rule class: govern() only evaluates pre_tool."""
    make(client, "staged", rules=[{
        "name": "post-rule", "condition": "action.type == 'drop'",
        "action": "deny", "stage": "post_tool"}])
    warnings = client.get("/policies/staged").json()["warnings"]
    assert any("never fires" in w["effect"] for w in warnings)


def test_disabled_rule_is_warned_about(client):
    make(client, "off", rules=[{
        "name": "sleeping", "condition": "action.type == 'drop'",
        "action": "deny", "enabled": False}])
    warnings = client.get("/policies/off").json()["warnings"]
    assert any("disabled" in w["effect"].lower() for w in warnings)


# ── Validate and YAML ────────────────────────────────────────────────────────

def test_validate_does_not_save(client):
    r = client.post("/policies/validate", json={
        "name": "ephemeral", "default_action": "allow",
        "rules": [{"name": "r", "condition": "action.type == 'drop'", "action": "deny"}]})
    assert r.status_code == 200
    assert r.json()["valid"] is True
    assert client.get("/policies/ephemeral").status_code == 404


def test_validate_reports_dead_rules_without_saving(client):
    r = client.post("/policies/validate", json={
        "name": "draft", "default_action": "allow",
        "rules": [{"name": "bad", "condition": 'x matches "y"', "action": "deny"}]})
    body = r.json()
    assert body["valid"] is False
    assert body["warnings"][0]["rule"] == "bad"
    assert client.get("/policies/draft").status_code == 404


def test_nothing_is_written_when_creation_is_rejected(client, policy_dir):
    client.post("/policies", json={
        "name": "rejected", "default_action": "allow",
        "rules": [{"name": "bad", "condition": 'x matches "y"', "action": "deny"}]})
    assert not (policy_dir / "rejected.yaml").exists()


def test_yaml_endpoint_returns_the_file_verbatim(client, policy_dir):
    make(client, "readable", **BASE)
    body = client.get("/policies/readable/yaml").json()
    assert body["yaml"] == (policy_dir / "readable.yaml").read_text(encoding="utf-8")
    assert yaml.safe_load(body["yaml"])["name"] == "readable"


def test_yaml_extends_are_stored_as_filenames(client, policy_dir):
    """AGT resolves parents by filename; the API speaks policy names."""
    make(client, "base", **BASE)
    make(client, "child", extends=["base"])
    on_disk = yaml.safe_load((policy_dir / "child.yaml").read_text(encoding="utf-8"))
    assert on_disk["extends"] == ["base.yaml"]
    assert client.get("/policies/child").json()["extends"] == ["base"]


# ── Schema ───────────────────────────────────────────────────────────────────

def test_schema_lists_only_operators_the_linter_accepts(client, app_module):
    """Drift guard: the editor must not offer something the backend rejects."""
    schema = client.get("/policies/schema").json()
    for op in schema["operators"]:
        field = "agent.trust_score" if "number" in op["types"] else "action.type"
        value = "0.5" if "number" in op["types"] else "x"
        if op["id"] == "in":
            value = "'x'"
        if op["id"] == "truthy":
            field = "input_text.has_pii"
        condition = op["template"].format(field=field, value=value)
        assert app_module._lint_condition(condition) == [], \
            f"schema offers {op['id']!r} but the linter rejects {condition!r}"


def test_schema_strategies_and_scopes_match_the_store(client):
    from policy_store import CONFLICT_STRATEGIES, POLICY_SCOPES
    schema = client.get("/policies/schema").json()
    assert schema["conflict_strategies"] == list(CONFLICT_STRATEGIES)
    assert schema["scopes"] == list(POLICY_SCOPES)


def test_schema_declares_the_only_enforced_stage(client):
    schema = client.get("/policies/schema").json()
    assert schema["enforced_stage"] == "pre_tool"
    assert "pre_tool" in schema["stages"]


def test_schema_fields_resolve_against_a_real_context(client):
    """Every advertised field must be reachable in an evaluation context."""
    schema = client.get("/policies/schema").json()
    context = client.post("/policies/evaluate", json={
        "policy_name": "default-policy", "agent_id": "data-agent",
        "action": "read", "input_text": "bob@example.com",
    }).json()["context"]

    for field in schema["fields"]:
        if field["path"].startswith("sql."):
            continue                       # only present for sql-bearing contexts
        root = field["path"].split(".")[0]
        assert root in context, f"schema advertises {field['path']} but {root} is absent"
