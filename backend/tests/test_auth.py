"""Authentication, role hierarchy and tenant isolation.

These tests enable auth explicitly by setting AGT_API_KEYS and reloading the
provider; the rest of the suite runs with auth disabled (the shipped default),
so every other test still calls the API without a token.
"""

import os

import pytest
from starlette.testclient import TestClient

import main
from auth import AuthProvider, AuthError, Principal, ANONYMOUS


# token : subject : tenant : roles
KEYS = (
    "viewer-tok:vera:acme:viewer, "
    "op-tok:otto:acme:operator, "
    "admin-tok:root:acme:admin, "
    "globex-op:gwen:globex:operator"
)


@pytest.fixture
def auth_client():
    """A freshly-seeded app with API-key auth switched on."""
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


def _make_agent(client, token, agent_id, trust=0.8):
    return client.post("/agents", headers=_auth(token), json={
        "id": agent_id, "name": agent_id, "trust_score": trust,
    })


# ── Authentication ──────────────────────────────────────────────────────────

def test_missing_token_is_rejected(auth_client):
    assert auth_client.get("/agents").status_code == 401


def test_invalid_token_is_rejected(auth_client):
    assert auth_client.get("/agents", headers=_auth("nope")).status_code == 401


def test_valid_token_is_accepted(auth_client):
    assert auth_client.get("/agents", headers=_auth("viewer-tok")).status_code == 200


def test_health_stays_public_under_auth(auth_client):
    assert auth_client.get("/health").status_code == 200


def test_openapi_stays_public_under_auth(auth_client):
    assert auth_client.get("/openapi.json").status_code == 200


# ── Role hierarchy (RBAC) ───────────────────────────────────────────────────

def test_viewer_can_read(auth_client):
    assert auth_client.get("/policies", headers=_auth("viewer-tok")).status_code == 200


def test_viewer_cannot_create_agent(auth_client):
    r = _make_agent(auth_client, "viewer-tok", "viewer-made")
    assert r.status_code == 403


def test_operator_can_create_agent(auth_client):
    r = _make_agent(auth_client, "op-tok", "acme-svc")
    assert r.status_code == 200
    assert r.json()["id"] == "acme-svc"


def test_operator_cannot_delete_agent(auth_client):
    _make_agent(auth_client, "op-tok", "acme-svc")
    r = auth_client.delete("/agents/acme-svc", headers=_auth("op-tok"))
    assert r.status_code == 403


def test_admin_can_delete_agent(auth_client):
    _make_agent(auth_client, "op-tok", "acme-svc")
    r = auth_client.delete("/agents/acme-svc", headers=_auth("admin-tok"))
    assert r.status_code == 200


# ── Tenant isolation ────────────────────────────────────────────────────────

def test_list_is_scoped_to_the_callers_tenant(auth_client):
    _make_agent(auth_client, "op-tok", "acme-svc")       # tenant acme
    _make_agent(auth_client, "globex-op", "globex-svc")  # tenant globex

    acme = {a["id"] for a in auth_client.get("/agents", headers=_auth("op-tok")).json()}
    assert "acme-svc" in acme
    assert "globex-svc" not in acme
    # Demo agents seeded into the "default" tenant are invisible too.
    assert "research-agent" not in acme


def test_admin_sees_every_tenant(auth_client):
    _make_agent(auth_client, "op-tok", "acme-svc")
    _make_agent(auth_client, "globex-op", "globex-svc")

    seen = {a["id"] for a in auth_client.get("/agents", headers=_auth("admin-tok")).json()}
    assert {"acme-svc", "globex-svc", "research-agent"} <= seen


def test_cross_tenant_mutation_is_forbidden(auth_client):
    _make_agent(auth_client, "op-tok", "acme-svc")
    # A globex operator may not move an acme agent's trust score.
    r = auth_client.post("/trust/update?agent_id=acme-svc&score=0.1",
                         headers=_auth("globex-op"))
    assert r.status_code == 403


def test_same_tenant_mutation_is_allowed(auth_client):
    _make_agent(auth_client, "op-tok", "acme-svc")
    r = auth_client.post("/trust/update?agent_id=acme-svc&score=0.5",
                         headers=_auth("op-tok"))
    assert r.status_code == 200
    assert r.json()["trust_score"] == 0.5


# ── Provider unit behaviour ─────────────────────────────────────────────────

def test_role_hierarchy_is_inclusive():
    admin = Principal("root", "acme", frozenset({"admin"}))
    assert admin.has_role("viewer") and admin.has_role("operator") and admin.has_role("admin")
    viewer = Principal("v", "acme", frozenset({"viewer"}))
    assert viewer.has_role("viewer")
    assert not viewer.has_role("operator")


def test_disabled_provider_has_no_keys(monkeypatch):
    monkeypatch.delenv("AGT_API_KEYS", raising=False)
    monkeypatch.delenv("AGT_API_KEYS_FILE", raising=False)
    provider = AuthProvider()
    assert provider.enabled is False
    assert provider.authenticate("anything") is None


def test_malformed_key_entry_is_rejected(monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "missing-fields:only:two")
    with pytest.raises(AuthError):
        AuthProvider()


def test_unknown_role_is_rejected(monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tok:sub:tenant:superuser")
    with pytest.raises(AuthError):
        AuthProvider()


def test_anonymous_is_admin_in_default_tenant():
    assert ANONYMOUS.is_admin
    assert ANONYMOUS.tenant == "default"
