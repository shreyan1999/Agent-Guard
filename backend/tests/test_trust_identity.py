"""The Trust & Identity tab: what a score buys, and what an identity proves.

Three things the tab could not previously say, each now backed by an AGT
primitive rather than by the panel's own arithmetic:

* **What a score buys.** The trust gate threshold and the execution-ring
  boundary are different numbers, and the panel used to show a hardcoded third
  one. Both real values now come from the API, and the level bands are cut at
  the ring boundary so a badge cannot disagree with the sandbox an agent is in.
* **Where a score comes from.** ``nexus.ReputationEngine`` computes trust from
  the agent's own governed-call record and the strength of its identity, so the
  number can be *earned* rather than only dragged.
* **What an identity proves.** ``agentmesh.trust.cards.TrustedAgentCard`` is
  signed at mint time with a key the platform then discards — checkable forever,
  forgeable never, and broken by any edit.
"""

import pytest
from agentmesh.identity import AgentIdentity
from starlette.testclient import TestClient

import main
import reputation


def _sign(private_jwk, nonce):
    return AgentIdentity.from_jwk(private_jwk).sign(nonce.encode("utf-8"))


def _register(client, agent_id, **kw):
    body = {"id": agent_id, "name": agent_id, "owner": "t@example.com", **kw}
    return client.post("/agents", json=body).json()


def _attest(client, agent_id, issued):
    challenge = client.post("/identity/challenge", json={"agent_id": agent_id}).json()
    return client.post("/identity/attest", json={
        "agent_id": agent_id, "nonce": challenge["nonce"],
        "signature": _sign(issued["identity"]["private_jwk"], challenge["nonce"]),
    }).json()


def _by_id(body):
    return {a["agent_id"]: a for a in body["agents"]}


# ── 1. What a score buys ─────────────────────────────────────────────────────

def test_the_real_thresholds_are_reported(client):
    """The panel used to show a hardcoded 0.6 while the gate denied at 0.3."""
    body = client.get("/trust").json()
    assert body["min_trust"] == main.MIN_TRUST == 0.3
    assert body["ring_threshold"] == 0.6


def test_every_agent_reports_the_ring_its_score_buys(client):
    agents = _by_id(client.get("/trust").json())
    assert agents["research-agent"]["ring"] == "RING_2_STANDARD"     # 0.92
    assert agents["email-agent"]["ring"] == "RING_3_SANDBOX"         # 0.55
    assert "no network" in agents["email-agent"]["ring_grants"]
    assert "network" in agents["research-agent"]["ring_grants"]


def test_the_level_band_cannot_disagree_with_the_ring(client):
    """0.55 used to read `medium` while sitting in the sandbox. The bands are
    now cut at the ring boundary, so the badge and the ring agree."""
    for a in client.get("/trust").json()["agents"]:
        sandboxed = a["ring"] == "RING_3_SANDBOX"
        assert (a["level"] == "low") == sandboxed, a


def test_the_gate_verdict_is_reported_separately_from_the_band(client):
    agents = _by_id(client.get("/trust").json())
    # 0.55 is below the ring boundary but above the gate threshold: both true
    # at once, which is exactly the distinction the tab never drew.
    assert agents["email-agent"]["level"] == "low"
    assert agents["email-agent"]["passes_trust_gate"] is True
    assert agents["untrusted-agent"]["passes_trust_gate"] is False   # 0.18


def test_trust_is_tenant_scoped(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokA:ana:acme:admin,tokB:bob:globex:operator")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        A, B = {"Authorization": "Bearer tokA"}, {"Authorization": "Bearer tokB"}
        c.post("/agents", json={"id": "acme-only", "name": "acme-only",
                                "owner": "a@b.c", "trust_score": 0.9}, headers=A)
        seen = {a["agent_id"] for a in c.get("/trust", headers=B).json()["agents"]}
        assert "acme-only" not in seen, "another tenant's agent is visible"
        assert "acme-only" in {a["agent_id"] for a in c.get("/trust", headers=A).json()["agents"]}
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()


# ── 2. Where a score comes from (nexus.ReputationEngine) ─────────────────────

def test_reputation_is_computed_from_the_agents_own_calls(client):
    for _ in range(8):
        client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    rep = _by_id(client.get("/trust").json())["research-agent"]["reputation"]
    assert rep["successful_tasks"] == 8
    assert rep["failed_tasks"] == 0
    assert rep["evidenced"] is True


def test_denials_drag_reputation_below_a_clean_record(client):
    for _ in range(10):
        client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    for _ in range(10):
        client.post("/tools/call", json={"tool_name": "db_query", "action": "drop",
                                         "agent_id": "data-agent"})
    agents = _by_id(client.get("/trust").json())
    clean = agents["research-agent"]["reputation"]
    failing = agents["data-agent"]["reputation"]
    assert failing["failed_tasks"] == 10 and clean["failed_tasks"] == 0
    assert failing["behavioural_modifier"] < clean["behavioural_modifier"]
    assert failing["score"] < clean["score"]


def test_an_agent_with_no_calls_is_marked_unevidenced(client):
    """A base-score-only number must not read as a behavioural verdict."""
    rep = _by_id(client.get("/trust").json())["untrusted-agent"]["reputation"]
    assert rep["evidenced"] is False
    assert rep["successful_tasks"] == 0 and rep["failed_tasks"] == 0


def test_attestation_promotes_the_verification_level(client):
    """Every rung above `registered` is a cryptographic act, not a setting."""
    issued = _register(client, "climber", trust_score=0.8)
    before = _by_id(client.get("/trust").json())["climber"]["reputation"]
    assert before["verification_level"] == "registered"

    assert _attest(client, "climber", issued)["verified"] is True
    after = _by_id(client.get("/trust").json())["climber"]["reputation"]
    # Attested *and* carrying a card whose signature still verifies.
    assert after["verification_level"] == "verified_partner"
    assert after["base_score"] > before["base_score"]
    assert after["score"] > before["score"]


def test_verification_level_ladder_is_earned():
    lvl = reputation.verification_level
    assert lvl(has_identity=False, attested=False, card_valid=False) == "unknown"
    assert lvl(has_identity=True, attested=False, card_valid=False) == "registered"
    assert lvl(has_identity=True, attested=True, card_valid=False) == "verified"
    assert lvl(has_identity=True, attested=True, card_valid=True) == "verified_partner"


def test_promoting_reputation_changes_what_is_enforced(client):
    """Promotion is an operator action: a score that moved on its own, changing
    an agent's ring with nobody watching, would be worse than a stale one."""
    _register(client, "promoted", trust_score=0.9)
    for _ in range(12):
        client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "promoted"})

    r = client.post("/trust/promote/promoted").json()
    assert r["previous"] == 0.9
    assert r["trust_score"] == r["reputation"]["score_normalised"]
    assert main._trust_scores["promoted"] == r["trust_score"]
    # And the enforced number is the one the gate now reads.
    assert _by_id(client.get("/trust").json())["promoted"]["trust_score"] == r["trust_score"]


def test_promotion_is_refused_when_there_is_no_evidence(client):
    _register(client, "idle", trust_score=0.7)
    r = client.post("/trust/promote/idle")
    assert r.status_code == 409
    assert "no governed calls" in r.json()["detail"]
    assert main._trust_scores["idle"] == 0.7      # untouched


def test_promotion_is_audited(client):
    _register(client, "audited", trust_score=0.9)
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "audited"})
    client.post("/trust/promote/audited")
    events = client.get("/audit?limit=100").json()["events"]
    assert any(e["event_type"] == "trust.reputation.promoted" for e in events)


# ── 3. What an identity proves (TrustedAgentCard) ────────────────────────────

def test_every_agent_gets_a_signed_card_that_verifies(client):
    _register(client, "carded", trust_score=0.8)
    body = client.get("/agents/carded/card").json()
    assert body["card"]["signature_valid"] is True
    assert body["card"]["agent_did"].startswith("did:mesh:")
    assert body["card"]["card_signature"]
    assert body["attested"] is False


def test_a_tampered_card_stops_verifying(client):
    """The card is checked on every read, never cached as a claim."""
    _register(client, "tampered", trust_score=0.8)
    assert client.get("/agents/tampered/card").json()["card"]["signature_valid"] is True

    main._identity._cards["tampered"]["name"] = "SomethingElse"
    assert client.get("/agents/tampered/card").json()["card"]["signature_valid"] is False


def test_the_card_records_attestation(client):
    issued = _register(client, "prover", trust_score=0.8)
    _attest(client, "prover", issued)
    body = client.get("/agents/prover/card").json()
    assert body["attested"] is True
    assert body["attested_at"] is not None
    assert body["verification_level"] == "verified_partner"


def test_the_platform_cannot_forge_a_card(client):
    """The private key is issued once and never stored, so the platform holds
    only public material — it can verify a card and never sign a new one."""
    _register(client, "unforgeable", trust_score=0.8)
    stored = main._identity.get("unforgeable")
    from agentmesh.trust.cards import TrustedAgentCard
    with pytest.raises(Exception):
        TrustedAgentCard.from_identity(stored)


def test_cards_and_attestation_survive_a_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("AGT_STATE_DIR", str(tmp_path))
    main.reset_state()
    c = TestClient(main.app)
    issued = _register(c, "durable", trust_score=0.8)
    _attest(c, "durable", issued)
    before = c.get("/agents/durable/card").json()

    main.teardown_state()                     # simulated restart
    main.seed_state()
    c = TestClient(main.app)

    after = c.get("/agents/durable/card").json()
    assert after["card"]["signature_valid"] is True
    assert after["card"]["agent_did"] == before["card"]["agent_did"]
    assert after["attested"] is True, "attestation did not survive the restart"

    main.teardown_state(clear_policies=True)
    monkeypatch.delenv("AGT_STATE_DIR")
    main.reset_state()


def test_a_card_is_scoped_to_its_tenant(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokA:ana:acme:admin,tokB:bob:globex:operator")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        A, B = {"Authorization": "Bearer tokA"}, {"Authorization": "Bearer tokB"}
        c.post("/agents", json={"id": "acme-card", "name": "acme-card",
                                "owner": "a@b.c", "trust_score": 0.9}, headers=A)
        assert c.get("/agents/acme-card/card", headers=A).status_code == 200
        assert c.get("/agents/acme-card/card", headers=B).status_code == 403
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()
