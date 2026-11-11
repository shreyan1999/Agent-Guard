"""Agent admission as a governed transition, not an application check.

``AGT_REQUIRE_APPROVAL`` turns registration into a request. The refusal lives in
AGT's own state machine — activating a ``PENDING_APPROVAL`` agent raises
``LifecycleError`` — so there is no application-side check that could be
forgotten around it, which is the same argument the kill switch makes.

Also covers the lifecycle audit trail the panel now renders: both ends of every
transition, and scoped to the caller's tenant like every other agent read.
"""

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def approval(monkeypatch):
    """A freshly-seeded app with the approval gate on."""
    monkeypatch.setenv("AGT_REQUIRE_APPROVAL", "1")
    main.reset_state()
    yield TestClient(main.app)
    monkeypatch.delenv("AGT_REQUIRE_APPROVAL", raising=False)
    main.reset_state()


def _register(client, agent_id, **kw):
    return client.post("/agents", json={
        "id": agent_id, "name": agent_id, "owner": "t@example.com", **kw})


def _states(client):
    return {a["name"]: a["status"] for a in client.get("/agents").json()}


# ── The shipped default is unchanged ─────────────────────────────────────────

def test_registration_is_immediate_by_default(client):
    assert _register(client, "instant").json()["status"] == "active"
    assert client.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": "instant"}).json()["allowed"] is True


def test_the_control_is_reported_in_the_self_assessment(client):
    ctrls = client.get("/compliance/owasp").json()["runtime_controls"]
    assert ctrls["registration_approval_required"] is False


# ── With the gate on ─────────────────────────────────────────────────────────

def test_seeded_demo_agents_are_still_active(approval):
    """The gate governs agents a caller registers, not the platform's fixtures."""
    assert set(_states(approval).values()) == {"active"}


def test_a_new_agent_lands_pending(approval):
    assert _register(approval, "newbie").json()["status"] == "pending_approval"
    assert _states(approval)["newbie"] == "pending_approval"


def test_a_pending_agent_cannot_call_anything(approval):
    """Denied at the lifecycle gate, before trust or policy — the same gate the
    kill switch uses, for the same reason."""
    _register(approval, "newbie")
    res = approval.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": "newbie"}).json()
    assert res["allowed"] is False
    assert res["denied_by"] == "lifecycle"
    assert res["rule"] == "lifecycle:pending_approval"


def test_approval_admits_the_agent(approval):
    _register(approval, "newbie")
    assert approval.post("/agents/newbie/approve").json()["status"] == "active"
    assert approval.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": "newbie"}).json()["allowed"] is True


def test_rejection_decommissions_and_records_the_reason(approval):
    _register(approval, "denied")
    r = approval.post("/agents/denied/reject?reason=unapproved+purpose").json()
    assert r["status"] == "rejected" and r["reason"] == "unapproved purpose"
    # Decommissioning is a transition, not a delete: AGT keeps the record.
    assert _states(approval)["denied"] == "decommissioned"
    assert "denied" not in main._agent_ids
    assert main._identity.did("denied") is None


def test_a_rejected_agent_cannot_call(approval):
    _register(approval, "denied")
    approval.post("/agents/denied/reject")
    res = approval.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": "denied"}).json()
    assert res["allowed"] is False


def test_approving_a_non_pending_agent_is_refused(approval):
    """AGT's state machine owns the transition, so the refusal is its own."""
    _register(approval, "newbie")
    approval.post("/agents/newbie/approve")
    again = approval.post("/agents/newbie/approve")
    assert again.status_code == 409


def test_approval_is_audited_with_the_approver(approval):
    _register(approval, "newbie")
    approval.post("/agents/newbie/approve")
    events = approval.get("/audit?limit=100").json()["events"]
    assert any(e["event_type"] == "agent.approved" for e in events)


def test_approval_requires_admin(approval, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokOp:op:acme:operator,tokAd:ad:acme:admin")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        op, admin = {"Authorization": "Bearer tokOp"}, {"Authorization": "Bearer tokAd"}
        c.post("/agents", json={"id": "gated", "name": "gated",
                                "owner": "t@e.com"}, headers=op)
        assert c.post("/agents/gated/approve", headers=op).status_code == 403
        assert c.post("/agents/gated/approve", headers=admin).status_code == 200
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()


def test_the_gate_is_reported_when_enabled(approval):
    ctrls = approval.get("/compliance/owasp").json()["runtime_controls"]
    assert ctrls["registration_approval_required"] is True


# ── The lifecycle trail the panel renders ────────────────────────────────────

def test_the_trail_names_both_ends_of_each_transition(client):
    _register(client, "traced")
    client.post("/sre/kill/traced")
    client.post("/sre/resume/traced")

    body = client.get("/agents/traced/lifecycle").json()
    moves = [(e["previous_state"], e["new_state"], e["event_type"], e["actor"])
             for e in body["events"]]
    assert (None, "provisioned", "requested", "dashboard") in moves
    assert ("provisioned", "active", "activated", "dashboard") in moves
    assert ("active", "suspended", "suspended", "operator") in moves
    assert ("suspended", "active", "resumed", "operator") in moves


def test_the_trail_carries_the_suspension_reason(client):
    _register(client, "traced")
    client.post("/sre/kill/traced")
    events = client.get("/agents/traced/lifecycle").json()["events"]
    suspended = next(e for e in events if e["event_type"] == "suspended")
    assert suspended["details"].get("reason")


def test_the_trail_is_tenant_scoped(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokA:ana:acme:admin,tokB:bob:globex:operator")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        A, B = {"Authorization": "Bearer tokA"}, {"Authorization": "Bearer tokB"}
        c.post("/agents", json={"id": "acme-trail", "name": "acme-trail",
                                "owner": "a@b.c"}, headers=A)
        assert c.get("/agents/acme-trail/lifecycle", headers=A).status_code == 200
        assert c.get("/agents/acme-trail/lifecycle", headers=B).status_code == 403
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()


def test_the_trail_survives_a_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("AGT_STATE_DIR", str(tmp_path))
    main.reset_state()
    c = TestClient(main.app)
    _register(c, "durable")
    c.post("/sre/kill/durable")
    before = len(c.get("/agents/durable/lifecycle").json()["events"])

    main.teardown_state()
    main.seed_state()
    c = TestClient(main.app)

    body = c.get("/agents/durable/lifecycle").json()
    assert body["state"] == "suspended", "the kill switch did not survive"
    assert len(body["events"]) == before

    main.teardown_state(clear_policies=True)
    monkeypatch.delenv("AGT_STATE_DIR")
    main.reset_state()


# ── Item 1 wiring: fields the card now shows ─────────────────────────────────

def test_the_agent_view_exposes_owner_and_capabilities(client):
    _register(client, "shown", capabilities=["db:read", "notes:write"])
    agent = {a["name"]: a for a in client.get("/agents").json()}["shown"]
    assert agent["owner"] == "t@example.com"
    assert agent["capabilities"] == ["db:read", "notes:write"]
