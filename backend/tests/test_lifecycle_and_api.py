"""Agent lifecycle, trust, and the rest of the API surface."""

import pytest


# ── Lifecycle registry ───────────────────────────────────────────────────────

def test_seeded_agents_are_managed_by_agt(client):
    agents = {a["id"]: a for a in client.get("/agents").json()}
    assert set(agents) == {"research-agent", "data-agent", "email-agent", "untrusted-agent"}
    for a in agents.values():
        assert a["agent_id"].startswith("agent:")   # minted by LifecycleManager
        assert a["state"] == "active"
        assert a["owner"]


def test_agents_resolve_by_name_or_by_agt_id(client):
    agent = client.get("/agents").json()[0]
    by_name = client.get(f"/agents/{agent['id']}/lifecycle").json()
    by_id = client.get(f"/agents/{agent['agent_id']}/lifecycle").json()
    assert by_name["agent_id"] == by_id["agent_id"] == agent["agent_id"]


def test_lifecycle_trail_records_actor_and_reason(client):
    client.post("/sre/kill/data-agent")
    client.post("/sre/resume/data-agent")
    events = client.get("/agents/data-agent/lifecycle").json()["events"]
    kinds = [e["event_type"] for e in events]
    assert kinds == ["requested", "activated", "suspended", "resumed"]

    suspended = next(e for e in events if e["event_type"] == "suspended")
    assert suspended["actor"] == "operator"
    assert suspended["details"]["reason"] == "Kill switch activated"


def test_registering_an_agent_requires_an_owner(client):
    r = client.post("/agents", json={
        "id": "no-owner", "name": "no-owner", "trust_score": 0.7, "owner": "",
    })
    assert r.status_code == 400


def test_registered_agent_can_immediately_execute(client):
    r = client.post("/agents", json={
        "id": "qa-agent", "name": "qa-agent",
        "trust_score": 0.7, "owner": "qa@localhost",
    })
    assert r.status_code == 200
    assert r.json()["state"] == "active"

    call = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "qa-agent",
    }).json()
    assert call["allowed"] is True


def test_duplicate_registration_is_rejected(client):
    body = {"id": "dupe", "name": "dupe", "trust_score": 0.7, "owner": "a@b.c"}
    assert client.post("/agents", json=body).status_code == 200
    assert client.post("/agents", json=body).status_code == 400


def test_removal_decommissions_rather_than_deletes(client):
    """AGT keeps the record and its trail; the agent just cannot act."""
    r = client.delete("/agents/email-agent")
    assert r.status_code == 200
    assert r.json()["state"] == "decommissioned"

    denied = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "email-agent",
    }).json()
    assert denied["allowed"] is False
    assert denied["denied_by"] == "lifecycle"


def test_kill_switch_on_unknown_agent_is_404(client):
    assert client.post("/sre/kill/nobody").status_code == 404


# ── Trust ────────────────────────────────────────────────────────────────────

def test_trust_panel_and_enforcement_share_a_threshold(client):
    """Regression: the panel used 0.6 while nothing enforced at all."""
    min_trust = client.post("/trust/evaluate", json={
        "agent_id": "probe", "trust_score": 0.9,
    }).json()["min_trust"]

    for score, expected in [(min_trust - 0.01, False), (min_trust, True)]:
        panel = client.post("/trust/evaluate", json={
            "agent_id": "untrusted-agent", "trust_score": score,
        }).json()["allowed"]
        client.post("/trust/update", params={"agent_id": "untrusted-agent", "score": score})
        runtime = client.post("/tools/call", json={
            "tool_name": "db_query", "action": "read", "agent_id": "untrusted-agent",
        }).json()["allowed"]
        assert panel is runtime is expected, f"disagreement at trust={score}"


def test_trust_evaluate_reports_that_it_is_enforced(client):
    d = client.post("/trust/evaluate", json={"agent_id": "x", "trust_score": 0.9}).json()
    assert d["enforced"] is True


def test_trust_update_reports_the_resulting_ring(client):
    low = client.post("/trust/update", params={"agent_id": "research-agent", "score": 0.2}).json()
    assert low["ring"] == "RING_3_SANDBOX"
    high = client.post("/trust/update", params={"agent_id": "research-agent", "score": 0.9}).json()
    assert high["ring"] == "RING_2_STANDARD"


def test_trust_update_on_unknown_agent_is_404(client):
    r = client.post("/trust/update", params={"agent_id": "nobody", "score": 0.5})
    assert r.status_code == 404


@pytest.mark.parametrize("score,clamped", [(-5.0, 0.0), (99.0, 1.0)])
def test_trust_scores_are_clamped(client, score, clamped):
    d = client.post("/trust/update", params={"agent_id": "data-agent", "score": score}).json()
    assert d["trust_score"] == clamped


# ── Stats and health ─────────────────────────────────────────────────────────

def test_stats_reports_chain_state_and_lifecycle_summary(client):
    d = client.get("/stats").json()
    assert d["chain_valid"] is True
    assert d["total_agents"] == 4
    assert d["active_agents"] == 4
    assert d["lifecycle"]["by_state"]["active"] == 4


def test_stats_counts_denials(client):
    before = client.get("/stats").json()["denials"]
    client.post("/tools/call", json={
        "tool_name": "db_query", "action": "drop", "agent_id": "data-agent",
    })
    assert client.get("/stats").json()["denials"] == before + 1


def test_call_and_denial_counters_track_per_agent(client):
    client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent"})
    client.post("/tools/call", json={
        "tool_name": "db_query", "action": "drop", "agent_id": "research-agent"})
    agent = next(a for a in client.get("/agents").json() if a["id"] == "research-agent")
    assert agent["calls"] == 1
    assert agent["denials"] == 1


def test_governed_tools_are_counted_by_distinct_tool(client):
    """Callables are cached per (tool, policy, agent, ring); the count is tools."""
    d = client.get("/stats").json()
    assert d["total_governed_tools"] == 4
    assert sorted(client.get("/tools").json()["tools"]) == [
        "db_query", "send_email", "web_search", "write_file",
    ]


# ── Endpoint contract ────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/health", "/stats", "/policies", "/tools", "/trust", "/agents",
    "/sre/slos", "/audit", "/audit/verify", "/audit/export", "/compliance/owasp",
])
def test_read_endpoints_respond(client, path):
    assert client.get(path).status_code == 200


def test_unknown_policy_on_tool_call_is_400(client):
    r = client.post("/tools/call", json={
        "tool_name": "db_query", "policy_name": "nope",
        "action": "read", "agent_id": "research-agent",
    })
    assert r.status_code == 400


def test_owasp_report_is_labelled_as_reference_not_assessment(client):
    """Guards against the coverage list drifting back into a self-assessment."""
    d = client.get("/compliance/owasp").json()
    assert "coverage" in d and d["coverage"]
    # Statuses must be honest enforcement states, never a blanket "covered".
    statuses = {c["status"] for c in d["coverage"]}
    assert statuses <= {"enforced", "partial", "not_implemented"}
    assert "covered" not in statuses


# ── SRE: real agent_sre SLOs, no simulated arithmetic ────────────────────────

def test_slos_are_real_agent_sre_objectives(client):
    """/sre/slos returns genuine agent_sre SLO documents, not fabricated fields."""
    slos = client.get("/sre/slos").json()
    assert slos, "seeded agents should have SLOs"
    slo = slos[0]
    # Shape produced by agent_sre.SLO.to_dict(), not the old fake record.
    assert "error_budget" in slo and "indicators" in slo
    assert slo["status"] in {"unknown", "healthy", "warning", "critical", "exhausted"}
    names = {i["name"] for i in slo["indicators"]}
    assert {"task_success_rate", "policy_compliance", "response_latency_p95"} <= names


def test_tool_calls_feed_the_real_slo(client):
    """A governed call records a real measurement into the agent's SLO."""
    before = next(s for s in client.get("/sre/slos").json()
                  if s["name"].startswith("research-agent"))
    before_count = before["indicators"][0]["measurement_count"]

    client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent",
    })

    after = next(s for s in client.get("/sre/slos").json()
                 if s["name"].startswith("research-agent"))
    assert after["indicators"][0]["measurement_count"] == before_count + 1


def test_slo_signal_updates_error_budget(client):
    """A failure signal burns real error budget via agent_sre."""
    client.post("/sre/slos", json={
        "agent_id": "data-agent", "slo_name": "data-reliability", "target": 0.99,
    })
    first = client.post("/sre/signal/data-agent", params={"success": False}).json()
    assert first["error_budget"]["consumed"] > 0.0
