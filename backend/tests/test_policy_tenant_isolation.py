"""Per-tenant policy isolation.

A policy created through the API is owned by its author's tenant. Only that
tenant (or a global admin) may list, read, edit or enforce it; another tenant
cannot see it and cannot govern its agents with it. The seeded default-policy
has no owner and stays shared. This only bites when auth (and therefore
tenants) is enabled — the single-tenant playground is unchanged.
"""

import os
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main

KEYS = (
    "op-tok:otto:acme:operator, "
    "admin-tok:root:acme:admin, "
    "globex-op:gwen:globex:operator"
)


@pytest.fixture
def auth_client():
    main.reset_state()
    os.environ["AGT_API_KEYS"] = KEYS
    main.reload_auth()
    try:
        yield TestClient(main.app)
    finally:
        os.environ.pop("AGT_API_KEYS", None)
        main.reload_auth()
        main.teardown_state(clear_policies=True)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _mk_policy(client, token, name):
    return client.post("/policies", headers=_auth(token), json={
        "name": name, "default_action": "allow",
        "rules": [{"name": "no-drop", "condition": "action.type == 'drop'",
                   "action": "deny", "priority": 10}],
    })


def _names(client, token):
    return {p["name"] for p in client.get("/policies", headers=_auth(token)).json()}


# ── Ownership and visibility ─────────────────────────────────────────────────

def test_created_policy_is_owned_by_author_tenant(auth_client):
    r = _mk_policy(auth_client, "op-tok", "acme-pol")
    assert r.status_code == 200
    assert r.json()["owner_tenant"] == "acme"


def test_owner_tenant_sees_its_own_policy(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    assert "acme-pol" in _names(auth_client, "op-tok")


def test_other_tenant_cannot_see_the_policy_in_the_list(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    globex = _names(auth_client, "globex-op")
    assert "acme-pol" not in globex
    assert "default-policy" in globex          # the shared default stays visible


def test_other_tenant_gets_403_reading_the_policy(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    assert auth_client.get("/policies/acme-pol", headers=_auth("globex-op")).status_code == 403
    assert auth_client.get("/policies/acme-pol/yaml", headers=_auth("globex-op")).status_code == 403


def test_other_tenant_cannot_edit_the_policy(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    r = auth_client.put("/policies/acme-pol", headers=_auth("globex-op"), json={
        "default_action": "deny", "rules": [],
    })
    assert r.status_code == 403


def test_admin_sees_every_tenants_policy(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    _mk_policy(auth_client, "globex-op", "globex-pol")
    admin = _names(auth_client, "admin-tok")
    assert {"acme-pol", "globex-pol", "default-policy"} <= admin


def test_default_policy_is_shared_across_tenants(auth_client):
    assert "default-policy" in _names(auth_client, "op-tok")
    assert "default-policy" in _names(auth_client, "globex-op")


# ── Enforcement ──────────────────────────────────────────────────────────────

def _register(client, token, agent_id):
    return client.post("/agents", headers=_auth(token), json={
        "id": agent_id, "name": agent_id, "trust_score": 0.8,
    })


def test_owner_tenant_agent_may_use_the_policy(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    _register(auth_client, "op-tok", "acme-agent")
    r = auth_client.post("/tools/call", headers=_auth("op-tok"), json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "acme-agent", "policy_name": "acme-pol",
    }).json()
    assert r["allowed"] is True


def test_foreign_tenant_agent_is_denied_the_policy(auth_client):
    _mk_policy(auth_client, "op-tok", "acme-pol")
    _register(auth_client, "globex-op", "globex-agent")
    r = auth_client.post("/tools/call", headers=_auth("globex-op"), json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "globex-agent", "policy_name": "acme-pol",
    }).json()
    assert r["allowed"] is False
    assert r["denied_by"] == "policy"
    assert r["rule"] == "policy:tenant_isolation"


def test_shared_default_policy_is_usable_by_any_tenant(auth_client):
    _register(auth_client, "globex-op", "globex-agent")
    r = auth_client.post("/tools/call", headers=_auth("globex-op"), json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "globex-agent", "policy_name": "default-policy",
    }).json()
    assert r["allowed"] is True


# ── Durability ───────────────────────────────────────────────────────────────

def test_policy_ownership_survives_a_restart(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="agt-polown-"))
    monkeypatch.setenv("AGT_STATE_DIR", str(d))
    monkeypatch.setenv("AGT_API_KEYS", KEYS)
    main.reset_state()
    main.reload_auth()
    try:
        client = TestClient(main.app)
        _mk_policy(client, "op-tok", "acme-pol")
        assert (d / "policy_owners.json").exists()

        # A real restart preserves policies on disk (teardown_state + seed_state);
        # reset_state is the test-only wipe, so it is not a restart here.
        main.teardown_state()
        main.seed_state()
        assert main._policy_tenant.get("acme-pol") == "acme"
        # Enforcement still isolates after the restart.
        _register(TestClient(main.app), "globex-op", "globex-agent")
        r = TestClient(main.app).post("/tools/call", headers=_auth("globex-op"), json={
            "tool_name": "db_query", "action": "read",
            "agent_id": "globex-agent", "policy_name": "acme-pol",
        }).json()
        assert r["allowed"] is False
        assert r["rule"] == "policy:tenant_isolation"
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        monkeypatch.delenv("AGT_API_KEYS", raising=False)
        main.reload_auth()
        main.reset_state()
