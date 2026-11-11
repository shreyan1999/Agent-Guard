"""Proving an entry, verifying the file, and exporting as evidence.

`/audit/verify` re-walks the chain held in memory, and you have to trust this
instance to read the result. These are the three artefacts that do not:

* a **Merkle inclusion proof** for one entry, checkable without the whole log;
* **`HashChainVerifier`** over the durable HMAC-signed file — the half of durable
  audit AGT ships and this platform had never called;
* an **accountability export** carrying a digest of the policy that made each
  decision, rather than a JSON dump of the chain.
"""

import json
import os

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


@pytest.fixture
def signed(tmp_path, monkeypatch):
    """A freshly-seeded app streaming to a durable, HMAC-signed audit file."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AGT_AUDIT_FILE", str(path))
    monkeypatch.setenv("AGT_AUDIT_KEY", "test-signing-key")
    main.reset_state()
    c = TestClient(main.app)
    c.post("/tools/call", json={"tool_name": "db_query", "action": "read",
                                "agent_id": "research-agent"})
    c.post("/tools/call", json={"tool_name": "db_query", "action": "drop",
                                "agent_id": "data-agent"})
    yield c, path
    monkeypatch.delenv("AGT_AUDIT_FILE", raising=False)
    monkeypatch.delenv("AGT_AUDIT_KEY", raising=False)
    main.reset_state()


def _tamper(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["action"] = "TAMPERED"
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── 1. Merkle inclusion proof ────────────────────────────────────────────────

def test_an_entry_carries_a_verifiable_inclusion_proof(client):
    for _ in range(3):
        client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    entry_id = client.get("/audit?limit=5").json()["events"][0]["id"]

    proof = client.get(f"/audit/proof/{entry_id}").json()
    assert proof["verified"] is True
    assert proof["merkle_root"] == client.get("/audit/verify").json()["merkle_root"]
    assert proof["entry"]["entry_id"] == entry_id
    # Sibling hashes with the side each sits on — what makes the proof checkable
    # without handing over the rest of the log.
    assert all(side in ("left", "right") for _, side in proof["merkle_proof"])


def test_an_unknown_entry_has_no_proof(client):
    assert client.get("/audit/proof/audit_doesnotexist").status_code == 404


def test_a_lone_entry_is_explained_not_reported_missing(client):
    """A one-leaf tree has no sibling path. Reporting that as 404 "Entry not
    found" told an operator their entry did not exist when it plainly did."""
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    events = client.get("/audit?limit=5").json()["events"]
    assert len(events) == 1

    r = client.get(f"/audit/proof/{events[0]['id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["merkle_proof"] is None
    assert body["verified"] is None
    assert "only entry" in body["reason"]
    assert body["merkle_root"]


# ── 2. Verifying the durable file ────────────────────────────────────────────

def test_an_intact_file_verifies(signed):
    c, path = signed
    body = c.get("/audit/verify-file").json()
    assert body["configured"] is True
    assert body["valid"] is True
    assert body["errors"] == []


def test_an_edited_entry_breaks_the_file(signed):
    c, path = signed
    _tamper(path)
    body = c.get("/audit/verify-file").json()
    assert body["valid"] is False
    assert any("hash" in e.lower() or "hmac" in e.lower() for e in body["errors"])


def test_the_signing_key_is_never_returned(signed):
    """The presence of a key is a fact an operator needs; its value is not."""
    c, _ = signed
    body = c.get("/audit/verify-file").json()
    assert body["key_present"] is True
    assert "test-signing-key" not in json.dumps(body)


def test_durable_audit_off_is_reported_not_failed(client):
    """Off is an ordinary state, not an error — `valid` is null rather than
    false, so 'not configured' cannot be misread as 'does not verify'."""
    body = client.get("/audit/verify-file").json()
    assert body["configured"] is False
    assert body["valid"] is None
    assert "AGT_AUDIT_FILE" in body["reason"]


def test_a_configured_but_unwritten_file_is_reported_not_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("AGT_AUDIT_FILE", str(tmp_path / "never-written.jsonl"))
    monkeypatch.setenv("AGT_AUDIT_KEY", "k")
    main.reset_state()
    try:
        body = TestClient(main.app).get("/audit/verify-file").json()
        assert body["configured"] is True
        assert body["valid"] is None
        assert "does not exist" in body["reason"]
    finally:
        monkeypatch.delenv("AGT_AUDIT_FILE")
        monkeypatch.delenv("AGT_AUDIT_KEY")
        main.reset_state()


def test_verifying_the_file_is_admin_only(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokOp:op:acme:operator,tokAd:ad:acme:admin")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        assert c.get("/audit/verify-file",
                     headers={"Authorization": "Bearer tokOp"}).status_code == 403
        assert c.get("/audit/verify-file",
                     headers={"Authorization": "Bearer tokAd"}).status_code == 200
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()


def test_the_in_memory_chain_and_the_file_are_checked_separately(signed):
    """Tampering with the file must not make the in-memory chain report broken,
    and vice versa — they are two artefacts, verified two ways."""
    c, path = signed
    _tamper(path)
    assert c.get("/audit/verify-file").json()["valid"] is False
    assert c.get("/audit/verify").json()["valid"] is True


# ── 3. Accountability export ─────────────────────────────────────────────────

def test_entries_export_as_accountability_records(client):
    client.post("/tools/call", json={"tool_name": "db_query", "action": "drop",
                                     "agent_id": "data-agent"})
    body = client.get("/audit/export/accountability?limit=10").json()

    assert body["profile"] == "agt.audit_entry.external_accountability_export"
    assert body["count"] > 0
    assert body["failed"] == 0
    record = body["records"][0]
    for field in ("actor_ref", "operation", "decision", "policy_digest",
                  "occurred_at", "evidence_refs"):
        assert field in record["export"], field
    # A digest of the policy that made the decision is what makes the record
    # checkable rather than merely readable.
    assert record["export"]["policy_digest"].startswith("sha256:")
    assert record["digest"].startswith("sha256:")


def test_each_record_carries_an_eeoap_statement(client):
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    record = client.get("/audit/export/accountability?limit=5").json()["records"][0]
    assert set(record["eeoap"]) >= {"profile", "actor", "operation", "policy",
                                    "provenance", "evidence", "validation"}


def test_the_export_is_bound_to_the_chain_it_came_from(client):
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    body = client.get("/audit/export/accountability").json()
    assert body["merkle_root"] == client.get("/audit/verify").json()["merkle_root"]


def test_the_export_honours_the_same_filters_as_the_log(client):
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})
    client.post("/tools/call", json={"tool_name": "db_query", "action": "drop",
                                     "agent_id": "data-agent"})
    body = client.get("/audit/export/accountability?agent_id=data-agent").json()
    assert body["count"] > 0
    assert all(r["export"]["actor_ref"] == "data-agent" for r in body["records"])


def test_an_unmappable_entry_is_reported_not_dropped(client, monkeypatch):
    """A silently shorter export would misrepresent the chain."""
    client.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"})

    def boom(entry):
        raise ValueError("cannot map this entry")
    monkeypatch.setattr(main.audit_export, "audit_entry_to_accountability_export", boom)

    body = client.get("/audit/export/accountability?limit=3").json()
    assert body["count"] == body["failed"] > 0
    assert all(r["export"] is None and r["error"] for r in body["records"])
