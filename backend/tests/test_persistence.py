"""Durable state: agents, trust, tenant and DIDs survive a restart.

These tests enable persistence by pointing AGT_STATE_DIR at a temp directory
and reloading the module stores. A "restart" is simulated with
`main.reset_state()`, which reconstructs every store from AGT_STATE_DIR — the
same code path a fresh process runs — and rehydrates from disk rather than
re-seeding. The rest of the suite runs with AGT_STATE_DIR unset (in-memory).
"""

import json
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def state_dir(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="agt-state-"))
    monkeypatch.setenv("AGT_STATE_DIR", str(d))
    # Rebuild stores against the temp dir, then seed a fresh (empty) state.
    main.reset_state()
    try:
        yield d
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        main.reset_state()  # back to in-memory for later tests


@pytest.fixture
def client(state_dir):
    return TestClient(main.app)


def _restart():
    """Simulate a process restart: stores reload from AGT_STATE_DIR."""
    main.reset_state()


def test_state_dir_writes_the_expected_files(client, state_dir):
    client.post("/agents", json={"id": "keeper", "name": "keeper", "trust_score": 0.8})
    assert (state_dir / "agents.json").exists()
    assert (state_dir / "agent_meta.json").exists()
    assert (state_dir / "identities.json").exists()


def test_created_agent_survives_a_restart(client, state_dir):
    created = client.post("/agents", json={
        "id": "keeper", "name": "keeper", "trust_score": 0.66,
        "owner": "ops@acme", "purpose": "long runner",
    }).json()
    did = created["did"]

    _restart()
    after = {a["id"]: a for a in TestClient(main.app).get("/agents").json()}
    assert "keeper" in after
    assert after["keeper"]["trust_score"] == 0.66
    assert after["keeper"]["did"] == did          # DID is stable across restart


def test_public_identity_survives_restart_and_still_verifies(client, state_dir):
    from identity_store import IdentityStore  # noqa: F401
    from agentmesh.identity import AgentIdentity

    created = client.post("/agents", json={"id": "signer", "name": "signer"}).json()
    private_jwk = created["identity"]["private_jwk"]

    _restart()
    fresh = TestClient(main.app)
    # The reloaded public identity can still verify a signature made with the
    # once-issued private key — proving the keypair (not just the name) persisted.
    nonce = fresh.post("/identity/challenge", json={"agent_id": "signer"}).json()["nonce"]
    sig = AgentIdentity.from_jwk(private_jwk).sign(nonce.encode("utf-8"))
    verified = fresh.post("/identity/attest", json={
        "agent_id": "signer", "nonce": nonce, "signature": sig,
    }).json()["verified"]
    assert verified is True


def test_kill_switch_survives_a_restart(client, state_dir):
    client.post("/agents", json={"id": "haltme", "name": "haltme"})
    client.post("/sre/kill/haltme")

    _restart()
    after = {a["id"]: a for a in TestClient(main.app).get("/agents").json()}
    assert after["haltme"]["state"] == "suspended"


def test_decommissioned_agent_stays_decommissioned_after_restart(client, state_dir):
    # "Delete" is an AGT decommission — a lifecycle transition that keeps the
    # record and its audit trail. So it survives a restart, marked decommissioned.
    client.post("/agents", json={"id": "temp", "name": "temp"})
    client.delete("/agents/temp")

    _restart()
    after = {a["id"]: a for a in TestClient(main.app).get("/agents").json()}
    assert after["temp"]["state"] == "decommissioned"


def test_persisted_agents_skip_demo_reseeding(client, state_dir):
    # A populated state dir must not re-seed the demo roster on restart.
    client.post("/agents", json={"id": "solo", "name": "solo"})
    _restart()
    ids = {a["id"] for a in TestClient(main.app).get("/agents").json()}
    assert "solo" in ids
    assert "research-agent" not in ids  # demos only seed into an empty state dir


def test_in_memory_default_writes_nothing(monkeypatch):
    monkeypatch.delenv("AGT_STATE_DIR", raising=False)
    main.reset_state()
    assert main._meta.durable is False
    c = TestClient(main.app)
    c.post("/agents", json={"id": "ephemeral", "name": "ephemeral"})
    # Nothing to assert on disk; this simply pins that persistence is opt-in.
    assert main._meta.load() == {}
