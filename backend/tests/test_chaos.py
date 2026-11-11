"""Adversarial evaluation: attack the gates, report what held.

The value of this feature is that it is allowed to fail, so most of these tests
pin the *honesty* of the run rather than a good score:

* the attacks go through the real `/tools/call` path, proved by changing the
  policy and watching the verdicts change;
* a breach is reported as a breach;
* the attacker is registered and trusted, so a vector that is blocked is
  blocked by a gate worth testing rather than by "who are you";
* every verdict names its gate, because *blocked by ring enforcement* and
  *blocked because the agent was unknown* are different facts;
* attack traffic never lands in a real agent's SLO or reputation.
"""

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def _run(client, **kw):
    return client.post("/sre/chaos/run", json=kw).json()


def _by_name(report):
    return {r["vector"]: r for r in report["results"]}


# ── The run itself ───────────────────────────────────────────────────────────

def test_a_run_fires_every_vector(client):
    r = _run(client)
    assert r["total"] == 12                      # 8 from AGT, 4 local
    assert len(r["results"]) == 12
    assert r["held"] + r["breached"] == r["total"]
    assert 0.0 <= r["resilience_score"] <= 1.0


def test_the_vector_sets_can_be_selected(client):
    assert _run(client, include_local=False)["total"] == 8
    assert _run(client, include_builtin=False)["total"] == 4


def test_vectors_can_be_listed_without_firing(client):
    body = client.get("/sre/chaos/vectors").json()
    assert body["builtin"] == 8 and body["local"] == 4
    assert {v["source"] for v in body["vectors"]} == {"agt", "local"}
    # Listing must not generate governed traffic.
    assert client.get("/audit?limit=100&event_type=chaos.run").json()["events"] == []


def test_an_unknown_policy_is_refused(client):
    assert client.post("/sre/chaos/run", json={"policy_name": "nope"}).status_code == 400


def test_a_run_is_admin_only(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokOp:op:acme:operator,tokAd:ad:acme:admin")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        assert c.post("/sre/chaos/run", json={},
                      headers={"Authorization": "Bearer tokOp"}).status_code == 403
        assert c.post("/sre/chaos/run", json={},
                      headers={"Authorization": "Bearer tokAd"}).status_code == 200
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()


# ── The attacks really traverse the gates ────────────────────────────────────

def test_each_local_vector_is_stopped_by_the_gate_it_targets(client):
    """These four exist to prove all five gates are reachable, not to flatter
    the score — each names the gate it expects to meet."""
    results = _by_name(_run(client))
    assert results["local:pii_exfiltration"]["denied_by"] == "policy"
    assert results["local:pii_exfiltration"]["rule"] == "block-pii"
    assert results["local:destructive_action"]["rule"] == "block-destructive"
    assert results["local:ring_network_escape"]["denied_by"] == "ring"
    assert results["local:unregistered_caller"]["denied_by"] == "lifecycle"


def test_a_deny_all_policy_makes_every_vector_hold(client):
    """The strongest evidence that the run uses the real PolicyEngine: change
    the policy, and every verdict changes with it."""
    client.post("/policies", json={
        "name": "deny-everything",
        "rules": [{"name": "deny-all", "condition": "agent.trust_score > 0",
                   "action": "deny", "priority": 10}],
    })
    r = _run(client, policy_name="deny-everything")
    assert r["breached"] == 0
    assert r["held"] == r["total"]
    assert r["grade"] == "A"
    assert r["resilience_score"] == 1.0


def test_the_default_policy_does_not_block_everything(client):
    """A run that always scored A would be worthless. The shipped policy has
    real gaps, and the report is expected to say so."""
    r = _run(client)
    assert r["breached"] > 0, "an adversarial run that cannot fail proves nothing"
    assert r["grade"] != "A"
    assert any(not v["held"] for v in r["results"])


def test_a_weak_attacker_dies_at_the_trust_gate(client):
    """Which is why the default attacker is strong: a run at low trust reports
    on the trust gate and nothing behind it."""
    r = _run(client, attacker_trust=0.05)
    gates = {v["denied_by"] for v in r["results"] if v["held"]}
    assert "trust" in gates


def test_the_report_names_a_gate_for_every_block(client):
    for v in _run(client)["results"]:
        if v["held"]:
            assert v["denied_by"], f"{v['vector']} was blocked by nothing in particular"
            assert v["rule"] is not None


def test_agt_recommendations_are_returned(client):
    r = _run(client)
    assert r["recommendations"]
    assert any("injection" in rec.lower() or "allowlist" in rec.lower()
               or "override" in rec.lower() or "identity" in rec.lower()
               for rec in r["recommendations"])


# ── Attack traffic is quarantined ────────────────────────────────────────────

def test_the_throwaway_attackers_are_purged(client):
    _run(client)
    leftover = [n for n in main._agent_ids if n.startswith("chaos-")]
    assert leftover == [], f"chaos agents survived the run: {leftover}"
    assert [s for s in main._slo.all() if s["agent_id"].startswith("chaos-")] == []
    assert [n for n in main._call_stats if n.startswith("chaos-")] == []


def test_a_run_does_not_touch_a_real_agents_numbers(client):
    """An adversarial run that burned a production agent's error budget would be
    the same dishonesty as the demo buttons writing untagged measurements."""
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    before = dict(main._call_stats.get("research-agent", {}))
    before_slo = main._slo.view("research-agent")["error_budget"]["remaining_percent"]

    _run(client)

    assert dict(main._call_stats.get("research-agent", {})) == before
    assert main._slo.view("research-agent")["error_budget"]["remaining_percent"] == before_slo


def test_the_attackers_are_purged_even_when_the_run_fails(client, monkeypatch):
    """The provisioning is wrapped in try/finally for a reason."""
    def boom(*a, **kw):
        raise RuntimeError("evaluator exploded")
    monkeypatch.setattr(main.chaos_runner, "run", boom)
    with pytest.raises(RuntimeError):
        client.post("/sre/chaos/run", json={})
    assert [n for n in main._agent_ids if n.startswith("chaos-")] == []


# ── Evidence the run happened ────────────────────────────────────────────────

def test_a_run_is_audited(client):
    r = _run(client)
    events = client.get("/audit?limit=100").json()["events"]
    entry = next(e for e in events if e["event_type"] == "chaos.run")
    assert entry["details"]["run_id"] == r["run_id"]
    assert entry["details"]["held"] == r["held"]
    assert entry["allowed"] is (r["breached"] == 0)


def test_breaches_raise_an_alert(client):
    r = _run(client)
    assert r["breached"] > 0
    chaos = [a for a in client.get("/sre/alerts").json()["alerts"]
             if a["source"] == "chaos"]
    assert chaos and chaos[0]["severity"] == "critical"


def test_a_clean_run_raises_no_alert(client):
    client.post("/policies", json={
        "name": "deny-everything",
        "rules": [{"name": "deny-all", "condition": "agent.trust_score > 0",
                   "action": "deny", "priority": 10}],
    })
    client.delete("/sre/alerts")
    r = _run(client, policy_name="deny-everything")
    assert r["breached"] == 0
    assert [a for a in client.get("/sre/alerts").json()["alerts"]
            if a["source"] == "chaos"] == []


def test_adversarial_evaluation_is_reported_in_the_self_assessment(client):
    ctrls = client.get("/compliance/owasp").json()["runtime_controls"]
    assert ctrls["adversarial_evaluation"] is True


# ── The Compliance tab reads the run as evidence ─────────────────────────────

def test_the_self_assessment_is_unevidenced_before_any_run(client):
    """A claim with no evidence must not look like one whose evidence came back
    clean, so both the summary and every row report nothing rather than zero."""
    body = client.get("/compliance/owasp").json()
    assert body["adversarial"] is None
    assert all(row["adversarial"] is None for row in body["coverage"])


def test_a_run_attaches_evidence_to_the_risks_it_exercised(client):
    r = _run(client)
    body = client.get("/compliance/owasp").json()

    assert body["adversarial"]["grade"] == r["grade"]
    assert body["adversarial"]["held"] == r["held"]
    assert body["adversarial"]["run_id"] == r["run_id"]

    rows = {c["id"]: c for c in body["coverage"]}
    for risk in ("ASI-01", "ASI-02", "ASI-03", "ASI-07", "ASI-09"):
        ev = rows[risk]["adversarial"]
        assert ev is not None, f"{risk} has vectors but no evidence"
        assert ev["tested"] == ev["held"] + ev["breached"]
        assert ev["vectors"]


def test_risks_with_no_vectors_stay_unexercised(client):
    """Six of the ten risks have no attack vectors. Reporting them as clean
    would be the report flattering the platform."""
    _run(client)
    rows = {c["id"]: c for c in client.get("/compliance/owasp").json()["coverage"]}
    for risk in ("ASI-04", "ASI-05", "ASI-06", "ASI-08", "ASI-10"):
        assert rows[risk]["adversarial"] is None, f"{risk} was never attacked"


def test_evidence_can_contradict_a_claim(client):
    """The finding the pairing exists for: a risk whose status says `enforced`
    while an attack against it got through."""
    _run(client)
    rows = {c["id"]: c for c in client.get("/compliance/owasp").json()["coverage"]}
    asi02 = rows["ASI-02"]
    assert asi02["status"] == "enforced"
    assert asi02["adversarial"]["breached"] > 0, (
        "ASI-02 claims enforced and every tool-abuse vector was blocked — if the "
        "policy genuinely improved, this test should be updated, not deleted")


def test_the_last_run_is_readable_without_firing_another(client):
    assert client.get("/sre/chaos/last").json()["run"] is None
    r = _run(client)
    last = client.get("/sre/chaos/last").json()["run"]
    assert last["run_id"] == r["run_id"]
    assert last["ran_at"] > 0
    # Reading it must not generate a second run.
    assert client.get("/sre/chaos/last").json()["run"]["run_id"] == r["run_id"]


def test_evidence_follows_the_policy_that_was_attacked(client):
    """Re-running under a stricter policy replaces the evidence, so the panel
    never shows a grade earned under a policy that is no longer in force."""
    _run(client)
    assert client.get("/compliance/owasp").json()["adversarial"]["breached"] > 0

    client.post("/policies", json={
        "name": "deny-everything",
        "rules": [{"name": "deny-all", "condition": "agent.trust_score > 0",
                   "action": "deny", "priority": 10}],
    })
    _run(client, policy_name="deny-everything")
    body = client.get("/compliance/owasp").json()
    assert body["adversarial"]["breached"] == 0
    assert body["adversarial"]["policy"] == "deny-everything"
    rows = {c["id"]: c for c in body["coverage"]}
    assert rows["ASI-02"]["adversarial"]["breached"] == 0
