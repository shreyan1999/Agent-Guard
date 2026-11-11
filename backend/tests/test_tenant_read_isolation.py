"""Read endpoints are scoped to the caller's tenant.

`/agents` and `/policies` have always filtered by tenant. The endpoints that
summarise or replay the same state did not: `/stats` returned every tenant's
agents from the very list `/agents` filters, `/audit` and `/traces` returned
every tenant's decisions, and `/policies/evaluate` would probe a policy the
caller could not read. Each was a way round the filter beside it.

The rule these tests pin, in the three shapes it takes:

* a **per-entry read** (a listing, a proof, one trace, one receipt) is filtered
  to the caller's tenant;
* a **whole-chain export** is admin-only rather than filtered — the audit chain
  and the receipt ledger are only evidence while they are complete, and handing
  a tenant a subset that cannot verify against its own root would be handing it
  something that looks like proof and is not;
* an **integrity property** of the one shared chain — `merkle_root`,
  `chain_valid` — stays platform-wide, because it discloses no entry content
  and a per-tenant root would verify against nothing.

Entries belonging to no tenant (a compliance report, a chain reset) stay
readable by everyone: they are platform events, not somebody's traffic.
"""

import os
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main

KEYS = (
    "acme-op:otto:acme:operator, "
    "acme-admin:root:acme:admin, "
    "globex-op:gwen:globex:operator"
)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


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


def _register(client, token, agent_id, trust=0.8):
    return client.post("/agents", headers=_auth(token), json={
        "id": agent_id, "name": agent_id, "trust_score": trust,
    })


def _call(client, token, agent_id, action="read"):
    return client.post("/tools/call", headers=_auth(token), json={
        "tool_name": "db_query", "action": action, "agent_id": agent_id,
    })


@pytest.fixture
def two_tenants(auth_client):
    """One agent per tenant, each having made one governed call."""
    _register(auth_client, "acme-op", "acme-agent")
    _register(auth_client, "globex-op", "globex-agent")
    _call(auth_client, "acme-op", "acme-agent")
    _call(auth_client, "globex-op", "globex-agent")
    return auth_client


def _agents_in(client, token):
    events = client.get("/audit", headers=_auth(token)).json()["events"]
    return {e["agent_id"] for e in events}


# -- /audit -------------------------------------------------------------------

def test_audit_listing_is_scoped_to_the_tenant(two_tenants):
    seen = _agents_in(two_tenants, "acme-op")
    assert "acme-agent" in seen
    assert "globex-agent" not in seen


def test_each_tenant_sees_only_its_own_side(two_tenants):
    seen = _agents_in(two_tenants, "globex-op")
    assert "globex-agent" in seen
    assert "acme-agent" not in seen


def test_admin_sees_every_tenants_entries(two_tenants):
    assert {"acme-agent", "globex-agent"} <= _agents_in(two_tenants, "acme-admin")


def test_total_counts_only_the_visible_entries(two_tenants):
    acme = two_tenants.get("/audit", headers=_auth("acme-op")).json()
    admin = two_tenants.get("/audit", headers=_auth("acme-admin")).json()
    assert acme["total"] == len(acme["events"])
    assert acme["total"] < admin["total"], \
        "a tenant's total leaked the size of the whole chain"


def test_merkle_root_stays_the_chains_own(two_tenants):
    """Deliberate: an integrity property, not a per-tenant view."""
    acme = two_tenants.get("/audit", headers=_auth("acme-op")).json()
    admin = two_tenants.get("/audit", headers=_auth("acme-admin")).json()
    assert acme["merkle_root"] == admin["merkle_root"]


def test_limit_still_fills_a_page_after_filtering(two_tenants):
    """The filter runs before the limit, so a page is not silently short."""
    for _ in range(6):
        _call(two_tenants, "globex-op", "globex-agent")
    for _ in range(6):
        _call(two_tenants, "acme-op", "acme-agent")
    page = two_tenants.get("/audit?limit=5", headers=_auth("acme-op")).json()
    assert len(page["events"]) == 5
    assert all(e["agent_id"] == "acme-agent" for e in page["events"])


def test_platform_entries_are_readable_by_every_tenant(two_tenants):
    """An entry belonging to no agent is a platform event, not someone's traffic."""
    two_tenants.get("/compliance/report?framework=soc2", headers=_auth("acme-op"))
    for token in ("acme-op", "globex-op"):
        events = two_tenants.get("/audit?event_type=compliance.report",
                                 headers=_auth(token)).json()["events"]
        assert events, f"{token} lost sight of a platform-wide entry"


def test_agent_removal_entry_keeps_its_tenant(two_tenants):
    """The removal drops the tenant binding, so the entry is stamped first."""
    two_tenants.delete("/agents/acme-agent", headers=_auth("acme-admin"))
    events = two_tenants.get("/audit?event_type=agent.decommissioned",
                             headers=_auth("globex-op")).json()["events"]
    assert not events, "the one entry naming a removed agent leaked its existence"


# -- /audit/proof -------------------------------------------------------------

def _own_entry_id(client, token, agent):
    events = client.get("/audit", headers=_auth(token)).json()["events"]
    return next(e["id"] for e in events if e["agent_id"] == agent)


def test_proof_is_served_for_your_own_entry(two_tenants):
    entry_id = _own_entry_id(two_tenants, "acme-op", "acme-agent")
    r = two_tenants.get(f"/audit/proof/{entry_id}", headers=_auth("acme-op"))
    assert r.status_code == 200


def test_proof_404s_for_another_tenants_entry(two_tenants):
    """A proof embeds the entry, so it cannot be looser than the listing."""
    entry_id = _own_entry_id(two_tenants, "acme-admin", "globex-agent")
    r = two_tenants.get(f"/audit/proof/{entry_id}", headers=_auth("acme-op"))
    assert r.status_code == 404, "the proof handed back what the listing withheld"


# -- Exports ------------------------------------------------------------------

def test_chain_export_is_admin_only(two_tenants):
    assert two_tenants.get("/audit/export",
                           headers=_auth("acme-op")).status_code == 403
    assert two_tenants.get("/audit/export",
                           headers=_auth("acme-admin")).status_code == 200


def test_receipt_ledger_export_is_admin_only(two_tenants):
    assert two_tenants.get("/mcp/receipts/export",
                           headers=_auth("acme-op")).status_code == 403
    assert two_tenants.get("/mcp/receipts/export",
                           headers=_auth("acme-admin")).status_code == 200


def test_accountability_export_is_scoped(two_tenants):
    records = two_tenants.get("/audit/export/accountability",
                              headers=_auth("acme-op")).json()["records"]
    assert records
    blob = str(records)
    assert "globex-agent" not in blob


# -- /stats -------------------------------------------------------------------

def test_stats_agents_match_the_agents_endpoint(two_tenants):
    """The bug: /stats returned the very list /agents filters."""
    stats = two_tenants.get("/stats", headers=_auth("acme-op")).json()
    listed = two_tenants.get("/agents", headers=_auth("acme-op")).json()
    seen = {a["id"] for a in stats["agents"]}
    assert seen == {a["id"] for a in listed}
    assert "globex-agent" not in seen


def test_stats_counts_follow_the_scope(two_tenants):
    stats = two_tenants.get("/stats", headers=_auth("acme-op")).json()
    assert stats["total_agents"] == 1
    assert stats["active_agents"] == 1
    assert stats["lifecycle"]["total_agents"] == 1
    assert stats["lifecycle"]["by_state"] == {"active": 1}


def test_stats_audit_counters_follow_the_scope(two_tenants):
    acme = two_tenants.get("/stats", headers=_auth("acme-op")).json()
    admin = two_tenants.get("/stats", headers=_auth("acme-admin")).json()
    assert acme["audit_events"] < admin["audit_events"]


def test_stats_policy_count_follows_visibility(two_tenants):
    two_tenants.post("/policies", headers=_auth("globex-op"), json={
        "name": "globex-only", "default_action": "allow", "rules": []})
    acme = two_tenants.get("/stats", headers=_auth("acme-op")).json()
    listed = two_tenants.get("/policies", headers=_auth("acme-op")).json()
    assert acme["total_policies"] == len(listed)


def test_admin_stats_span_every_tenant(two_tenants):
    stats = two_tenants.get("/stats", headers=_auth("acme-admin")).json()
    assert {"acme-agent", "globex-agent"} <= {a["id"] for a in stats["agents"]}


def test_stats_chain_integrity_stays_platform_wide(two_tenants):
    acme = two_tenants.get("/stats", headers=_auth("acme-op")).json()
    admin = two_tenants.get("/stats", headers=_auth("acme-admin")).json()
    assert acme["merkle_root"] == admin["merkle_root"]
    assert acme["chain_valid"] is True
    assert admin["chain_valid"] is True


# -- /policies/evaluate -------------------------------------------------------

def test_evaluate_refuses_another_tenants_policy(two_tenants):
    """Reading the policy is 403; probing it a question at a time must be too."""
    two_tenants.post("/policies", headers=_auth("globex-op"), json={
        "name": "globex-only", "default_action": "allow",
        "rules": [{"name": "no-drop", "condition": "action.type == 'drop'",
                   "action": "deny", "priority": 10}]})
    assert two_tenants.get("/policies/globex-only",
                           headers=_auth("acme-op")).status_code == 403
    r = two_tenants.post("/policies/evaluate", headers=_auth("acme-op"), json={
        "policy_name": "globex-only", "action": "drop", "agent_id": "acme-agent"})
    assert r.status_code == 403


def test_evaluate_still_serves_your_own_and_the_shared_policy(two_tenants):
    two_tenants.post("/policies", headers=_auth("acme-op"), json={
        "name": "acme-only", "default_action": "allow", "rules": []})
    for name in ("acme-only", "default-policy"):
        r = two_tenants.post("/policies/evaluate", headers=_auth("acme-op"), json={
            "policy_name": name, "action": "read", "agent_id": "acme-agent"})
        assert r.status_code == 200, f"{name} should be evaluable: {r.text}"


# -- /traces (durable mode only) ----------------------------------------------

@pytest.fixture
def traced_tenants():
    """Tracing needs a state dir, and durable mode seeds no demo agents."""
    d = Path(tempfile.mkdtemp(prefix="agt-tenant-traces-"))
    os.environ["AGT_API_KEYS"] = KEYS
    os.environ["AGT_STATE_DIR"] = str(d)
    main.reload_auth()
    main.reset_state()
    client = TestClient(main.app)
    _register(client, "acme-op", "acme-agent")
    _register(client, "globex-op", "globex-agent")
    _call(client, "acme-op", "acme-agent")
    _call(client, "globex-op", "globex-agent")
    try:
        yield client
    finally:
        os.environ.pop("AGT_API_KEYS", None)
        os.environ.pop("AGT_STATE_DIR", None)
        main.reload_auth()
        main.teardown_state(clear_policies=True)


def _traced_agents(client, token):
    body = client.get("/traces", headers=_auth(token)).json()
    assert body["enabled"] is True, "fixture did not enable tracing"
    return {t["agent_id"] for t in body["traces"]}


def test_trace_listing_is_scoped_to_the_tenant(traced_tenants):
    assert _traced_agents(traced_tenants, "acme-op") == {"acme-agent"}
    assert _traced_agents(traced_tenants, "globex-op") == {"globex-agent"}


def test_admin_sees_every_tenants_traces(traced_tenants):
    seen = _traced_agents(traced_tenants, "acme-admin")
    assert {"acme-agent", "globex-agent"} <= seen


def test_single_trace_404s_across_tenants(traced_tenants):
    traces = traced_tenants.get("/traces",
                                headers=_auth("acme-admin")).json()["traces"]
    theirs = next(t["trace_id"] for t in traces if t["agent_id"] == "globex-agent")
    assert traced_tenants.get(f"/traces/{theirs}",
                              headers=_auth("acme-op")).status_code == 404
    assert traced_tenants.get(f"/traces/{theirs}",
                              headers=_auth("globex-op")).status_code == 200


def test_diff_needs_both_sides_readable(traced_tenants):
    """One readable side does not buy the other."""
    traces = traced_tenants.get("/traces",
                                headers=_auth("acme-admin")).json()["traces"]
    mine = next(t["trace_id"] for t in traces if t["agent_id"] == "acme-agent")
    theirs = next(t["trace_id"] for t in traces if t["agent_id"] == "globex-agent")
    r = traced_tenants.get(f"/traces/diff?a={mine}&b={theirs}",
                           headers=_auth("acme-op"))
    assert r.status_code == 404
    assert traced_tenants.get(f"/traces/diff?a={mine}&b={theirs}",
                              headers=_auth("acme-admin")).status_code == 200
