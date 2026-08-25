"""Real cryptographic agent identity: DID issuance and challenge-response attestation.

These pin the Trust-pillar guarantee that replaced the self-asserted agent_id:
every agent has an Ed25519 keypair, the platform keeps only the public key, and
possession is proven by signing a single-use challenge nonce.
"""

from agentmesh.identity import AgentIdentity


def _register(client, agent_id="crypto-agent", trust=0.9):
    return client.post("/agents", json={
        "id": agent_id, "name": agent_id, "trust_score": trust,
        "owner": "ops@example.com", "purpose": "identity test",
    }).json()


def _sign(private_jwk, nonce):
    """Sign a nonce the way a real agent client would, from its issued private key."""
    return AgentIdentity.from_jwk(private_jwk).sign(nonce.encode("utf-8"))


def test_seeded_agents_have_real_dids(client):
    agents = client.get("/agents").json()
    for a in agents:
        assert a["did"].startswith("did:mesh:")


def test_registration_issues_a_did_and_private_key(client):
    view = _register(client)
    assert view["did"].startswith("did:mesh:")
    issued = view["identity"]
    assert issued["did"] == view["did"]
    # The one-time private JWK carries the private scalar; the public key never does.
    assert "d" in issued["private_jwk"]


def test_public_identity_endpoint_hides_private_key(client):
    _register(client)
    body = client.get("/agents/crypto-agent/identity").json()
    assert body["did"].startswith("did:mesh:")
    assert "d" not in body["public_jwk"], "the platform must never expose the private key"
    assert body["did_document"]["id"] == body["did"]


def test_attestation_round_trip_verifies(client):
    issued = _register(client)["identity"]
    challenge = client.post("/identity/challenge", json={"agent_id": "crypto-agent"}).json()
    sig = _sign(issued["private_jwk"], challenge["nonce"])
    res = client.post("/identity/attest", json={
        "agent_id": "crypto-agent", "nonce": challenge["nonce"], "signature": sig,
    }).json()
    assert res["verified"] is True
    assert res["did"] == issued["did"]


def test_attestation_rejects_a_foreign_key(client):
    _register(client, "agent-a")
    b = _register(client, "agent-b")
    challenge = client.post("/identity/challenge", json={"agent_id": "agent-a"}).json()
    # Sign agent-a's challenge with agent-b's key — must not verify as agent-a.
    forged = _sign(b["identity"]["private_jwk"], challenge["nonce"])
    res = client.post("/identity/attest", json={
        "agent_id": "agent-a", "nonce": challenge["nonce"], "signature": forged,
    }).json()
    assert res["verified"] is False


def test_challenge_nonce_is_single_use(client):
    issued = _register(client)["identity"]
    challenge = client.post("/identity/challenge", json={"agent_id": "crypto-agent"}).json()
    sig = _sign(issued["private_jwk"], challenge["nonce"])
    first = client.post("/identity/attest", json={
        "agent_id": "crypto-agent", "nonce": challenge["nonce"], "signature": sig,
    }).json()
    second = client.post("/identity/attest", json={
        "agent_id": "crypto-agent", "nonce": challenge["nonce"], "signature": sig,
    }).json()
    assert first["verified"] is True
    assert second["verified"] is False, "a nonce must not be replayable"


def test_attested_tool_call_is_marked_verified(client):
    issued = _register(client)["identity"]
    challenge = client.post("/identity/challenge", json={"agent_id": "crypto-agent"}).json()
    sig = _sign(issued["private_jwk"], challenge["nonce"])
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "crypto-agent",
        "attestation": {"nonce": challenge["nonce"], "signature": sig},
    }).json()
    assert res["allowed"] is True
    assert res["identity_verified"] is True
    assert res["did"] == issued["did"]


def test_forged_attestation_denies_the_call(client):
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


def test_unattested_call_is_allowed_but_flagged(client):
    """Backward-compat: without an attestation the agent_id is self-asserted and marked so."""
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent",
    }).json()
    assert res["allowed"] is True
    assert res["identity_verified"] is False
