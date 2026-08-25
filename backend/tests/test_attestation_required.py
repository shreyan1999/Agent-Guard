"""Mandatory attestation: AGT_REQUIRE_ATTESTATION turns the optional
challenge-response into a hard gate on POST /tools/call.

With the flag unset (the default) an unattested call is still honoured and
merely flagged ``identity_verified: false`` — the backward-compatible
playground behaviour. With the flag set, a call must carry a signature that
verifies against the agent's registered Ed25519 key or it is denied before any
trust, ring or policy gate runs. Nothing here is simulated: the same real
IdentityStore challenge-response drives both paths.
"""

from agentmesh.identity import AgentIdentity


def _register(client, agent_id="crypto-agent", trust=0.9):
    return client.post("/agents", json={
        "id": agent_id, "name": agent_id, "trust_score": trust,
        "owner": "ops@example.com", "purpose": "attestation test",
    }).json()


def _sign(private_jwk, nonce):
    return AgentIdentity.from_jwk(private_jwk).sign(nonce.encode("utf-8"))


def _attested_call(client, agent_id, private_jwk):
    challenge = client.post("/identity/challenge", json={"agent_id": agent_id}).json()
    sig = _sign(private_jwk, challenge["nonce"])
    return client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": agent_id,
        "attestation": {"nonce": challenge["nonce"], "signature": sig},
    }).json()


def test_flag_off_by_default_keeps_unattested_calls_allowed(client):
    _register(client, "research-agent")
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent",
    }).json()
    assert res["allowed"] is True
    assert res["identity_verified"] is False


def test_flag_on_denies_an_unattested_call(client, monkeypatch):
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    _register(client, "research-agent")
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent",
    }).json()
    assert res["allowed"] is False
    assert res["denied_by"] == "identity"
    assert res["rule"] == "identity:attestation_required"


def test_flag_on_allows_a_properly_attested_call(client, monkeypatch):
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    issued = _register(client)["identity"]
    res = _attested_call(client, "crypto-agent", issued["private_jwk"])
    assert res["allowed"] is True
    assert res["identity_verified"] is True


def test_flag_on_still_denies_a_forged_signature(client, monkeypatch):
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    _register(client, "agent-a")
    b = _register(client, "agent-b")
    challenge = client.post("/identity/challenge", json={"agent_id": "agent-a"}).json()
    forged = _sign(b["identity"]["private_jwk"], challenge["nonce"])
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "agent-a",
        "attestation": {"nonce": challenge["nonce"], "signature": forged},
    }).json()
    assert res["allowed"] is False
    assert res["denied_by"] == "identity"
    assert res["rule"] == "identity:attestation_failed"
