"""Policy evaluation, grammar linting and context enrichment.

The headline test here is the agreement sweep: the Policy panel and the
enforcement path must never return different verdicts for the same policy and
input. They once did, and it made the dashboard report a control that was not
actually enforcing.
"""

import pytest

# (action, input_text) pairs spanning allow, each deny rule, and the boundary.
CASES = [
    ("read", "SELECT name FROM users"),
    ("read", "User SSN: 123-45-6789"),
    ("read", "reach me at bob@example.com"),
    ("read", "card 4111 1111 1111 1111"),
    ("read", ""),
    ("drop", "DROP TABLE users"),
    ("delete", "remove everything"),
    ("send_email", "hello team"),
    ("truncate", "truncate logs"),
]


def panel_verdict(client, action, input_text, agent_id="data-agent"):
    r = client.post("/policies/evaluate", json={
        "policy_name": "default-policy", "agent_id": agent_id,
        "action": action, "input_text": input_text,
    })
    assert r.status_code == 200, r.text
    d = r.json()
    return d["allowed"], d["rule_name"]


def runtime_verdict(client, action, input_text, agent_id="data-agent"):
    r = client.post("/tools/call", json={
        "tool_name": "db_query", "action": action,
        "input_text": input_text, "agent_id": agent_id,
    })
    assert r.status_code == 200, r.text
    d = r.json()
    return d["allowed"], d.get("rule")


# ── F-01 regression ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("action,input_text", CASES)
def test_panel_and_runtime_agree(client, action, input_text):
    """Both paths must return the same verdict *and* the same matched rule."""
    assert panel_verdict(client, action, input_text) == \
           runtime_verdict(client, action, input_text)


def test_the_original_split_brain_case(client):
    """The exact input that once produced panel=DENY, runtime=ALLOW."""
    text = "User SSN: 123-45-6789"
    assert panel_verdict(client, "read", text) == (False, "block-pii")
    assert runtime_verdict(client, "read", text) == (False, "block-pii")


def test_evaluate_names_the_engine_and_its_scope(client):
    r = client.post("/policies/evaluate", json={
        "policy_name": "default-policy", "action": "read", "input_text": "",
    })
    d = r.json()
    assert d["evaluated_by"] == "agentmesh.governance.PolicyEngine"
    # The panel evaluates the policy gate only; the others run before it.
    assert d["gate"] == "policy"
    assert set(d["other_gates"]) == {"lifecycle", "trust", "ring"}


# ── Context enrichment via AGT's FacetRegistry ───────────────────────────────

def test_pii_facets_are_present_in_the_evaluated_context(client):
    r = client.post("/policies/evaluate", json={
        "policy_name": "default-policy", "action": "read",
        "input_text": "SSN 123-45-6789 and bob@example.com",
    })
    facets = r.json()["context"]["input_text"]
    assert facets["has_pii"] is True
    assert set(facets["pii_types"]) == {"US SSN", "Email address"}


def test_clean_text_has_no_pii_facet(client):
    r = client.post("/policies/evaluate", json={
        "policy_name": "default-policy", "action": "read",
        "input_text": "SELECT name FROM users",
    })
    assert r.json()["context"]["input_text"]["has_pii"] is False


def test_credential_facet_drives_a_custom_rule(client):
    """A rule written against the enrichment must enforce end to end."""
    r = client.post("/policies", json={
        "name": "no-creds", "default_action": "allow",
        "rules": [{"name": "block-creds", "condition": "input_text.has_credentials",
                   "action": "deny", "description": "Credentials in input"}],
    })
    assert r.status_code == 200, r.text

    denied = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "no-creds", "action": "read",
        "input_text": "AKIAIOSFODNN7EXAMPLE", "agent_id": "data-agent",
    }).json()
    assert denied["allowed"] is False
    assert denied["rule"] == "block-creds"

    allowed = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "no-creds", "action": "read",
        "input_text": "nothing secret here", "agent_id": "data-agent",
    }).json()
    assert allowed["allowed"] is True


# ── Grammar linting ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("condition", [
    'input_text matches "[0-9]{3}"',      # no regex operator in AGT
    'input_text contains "SSN"',          # no substring operator
    'action.type startswith "del"',       # not a comparison AGT implements
])
def test_unparsable_conditions_are_rejected(client, condition):
    """Regression for F-06: these used to be stored and silently enforce nothing."""
    r = client.post("/policies", json={
        "name": "bad-policy", "default_action": "allow",
        "rules": [{"name": "dead-rule", "condition": condition, "action": "deny"}],
    })
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["warnings"][0]["rule"] == "dead-rule"
    assert condition in detail["warnings"][0]["unparsable"]
    assert client.get("/policies/bad-policy").status_code == 404


@pytest.mark.parametrize("condition", [
    "action.type == 'drop'",
    "action.type != 'read'",
    'action.type in ["drop","delete"]',
    "agent.trust_score < 0.8",
    "agent.trust_score >= 0.95",
    "input_text.has_pii",
    'agent.trust_score < 0.8 and action.type == "send_email"',
    'action.type == "drop" or action.type == "delete"',
])
def test_supported_grammar_is_accepted(client, condition):
    r = client.post("/policies", json={
        "name": "good-policy", "default_action": "allow",
        "rules": [{"name": "r", "condition": condition, "action": "deny"}],
    })
    assert r.status_code == 200, r.text


def test_bundled_default_policy_is_lint_clean(client):
    """Every shipped rule must be one AGT can actually evaluate."""
    policies = {p["name"]: p for p in client.get("/policies").json()}
    assert policies["default-policy"]["warnings"] == []


def test_lint_warnings_are_surfaced_on_listing(client, policy_dir):
    """A policy file that predates linting still reports its dead rules.

    Written straight to disk, because the API now refuses to create one.
    """
    (policy_dir / "legacy.yaml").write_text(
        "apiVersion: governance.toolkit/v1\n"
        "name: legacy\n"
        "default_action: allow\n"
        "rules:\n"
        "  - name: dead\n"
        "    condition: 'x matches \"y\"'\n"
        "    action: deny\n",
        encoding="utf-8",
    )
    listed = {p["name"]: p for p in client.get("/policies").json()}
    assert listed["legacy"]["warnings"][0]["rule"] == "dead"


# ── Policy lifecycle ─────────────────────────────────────────────────────────

def test_default_policy_cannot_be_deleted(client):
    assert client.delete("/policies/default-policy").status_code == 400


def test_deleting_a_policy_evicts_its_cached_callables(client, app_module):
    client.post("/policies", json={"name": "temp", "default_action": "allow", "rules": []})
    client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "temp",
        "action": "read", "agent_id": "research-agent",
    })
    assert any(k[1] == "temp" for k in app_module._governed_tools)

    client.delete("/policies/temp")
    assert not any(k[1] == "temp" for k in app_module._governed_tools)
