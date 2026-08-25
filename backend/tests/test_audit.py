"""Evidence pillar: the audit chain must detect tampering.

A hash chain is only worth claiming if edits, deletions, reorderings and
recomputed hashes are all caught. Each attack below mutates the chain directly,
because no HTTP route can perform them — which is the point.
"""

import pytest


@pytest.fixture
def chained(client, app_module):
    """A client whose audit chain holds a few known events."""
    for agent, action in [("research-agent", "read"),
                          ("data-agent", "drop"),
                          ("research-agent", "read")]:
        client.post("/tools/call", json={
            "tool_name": "db_query", "action": action, "agent_id": agent,
        })
    return client, app_module


def entries(app_module):
    """The live entry list inside AGT's MerkleAuditChain."""
    return app_module._audit._log._chain._entries


# ── Chain construction ───────────────────────────────────────────────────────

def test_entries_are_hash_chained(chained):
    client, app_module = chained
    chain = entries(app_module)
    assert len(chain) >= 3
    assert chain[0].previous_hash == ""
    for prev, cur in zip(chain, chain[1:]):
        assert cur.previous_hash == prev.entry_hash
        assert cur.entry_hash


def test_events_are_returned_newest_first_with_hashes(chained):
    client, _ = chained
    body = client.get("/audit", params={"limit": 50}).json()
    assert body["merkle_root"]
    stamps = [e["timestamp"] for e in body["events"]]
    assert stamps == sorted(stamps, reverse=True)
    assert all(e["entry_hash"] for e in body["events"])


def test_verify_reports_an_intact_chain(chained):
    client, _ = chained
    d = client.get("/audit/verify").json()
    assert d["valid"] is True
    assert d["error"] is None
    assert d["entry_count"] >= 3


def test_merkle_inclusion_proof_verifies(chained):
    client, _ = chained
    entry_id = client.get("/audit", params={"limit": 50}).json()["events"][-1]["id"]
    proof = client.get(f"/audit/proof/{entry_id}").json()
    assert proof["verified"] is True
    assert proof["merkle_root"]


def test_proof_for_unknown_entry_is_404(chained):
    client, _ = chained
    assert client.get("/audit/proof/does-not-exist").status_code == 404


# ── Tamper detection ─────────────────────────────────────────────────────────

def test_editing_an_entry_breaks_verification(chained):
    """Flip a recorded denial into a success."""
    client, app_module = chained
    victim = entries(app_module)[1]
    victim.outcome = "success"
    assert client.get("/audit/verify").json()["valid"] is False


def test_deleting_an_entry_breaks_verification(chained):
    client, app_module = chained
    entries(app_module).pop(1)
    d = client.get("/audit/verify").json()
    assert d["valid"] is False
    assert "chain" in d["error"].lower()


def test_reordering_entries_breaks_verification(chained):
    client, app_module = chained
    chain = entries(app_module)
    chain[1], chain[2] = chain[2], chain[1]
    assert client.get("/audit/verify").json()["valid"] is False


def test_recomputing_the_edited_hash_still_breaks_the_chain(chained):
    """The sophisticated attack: cover your tracks by re-hashing the entry.

    The edited entry then verifies against itself, but the *next* entry still
    carries the old previous_hash, so the chain link fails.
    """
    client, app_module = chained
    victim = entries(app_module)[1]
    victim.data = {"tool": "db_query", "action": "read"}
    victim.entry_hash = victim.compute_hash()
    assert victim.verify_hash() is True          # the entry looks self-consistent
    assert client.get("/audit/verify").json()["valid"] is False


# ── Reset semantics ──────────────────────────────────────────────────────────

def test_reset_opens_a_new_chain_recording_the_old_root(chained):
    """DELETE /audit must not erase in place: an append-only log cannot."""
    client, _ = chained
    before = client.get("/audit/verify").json()

    reset = client.delete("/audit").json()
    assert reset["previous_merkle_root"] == before["merkle_root"]

    first = client.get("/audit", params={"limit": 50}).json()["events"][0]
    assert first["event_type"] == "audit.chain.reset"
    assert first["details"]["previous_merkle_root"] == before["merkle_root"]
    assert first["details"]["previous_entry_count"] == before["entry_count"]


def test_chain_is_valid_after_reset(chained):
    client, _ = chained
    client.delete("/audit")
    assert client.get("/audit/verify").json()["valid"] is True


# ── Export ───────────────────────────────────────────────────────────────────

def test_export_carries_the_root_and_every_entry(chained):
    client, _ = chained
    export = client.get("/audit/export").json()
    verify = client.get("/audit/verify").json()
    assert export["merkle_root"] == verify["merkle_root"]
    assert export["entry_count"] == len(export["entries"]) == verify["entry_count"]


# ── Filtering ────────────────────────────────────────────────────────────────

def test_events_can_be_filtered_by_agent(chained):
    client, _ = chained
    events = client.get("/audit", params={"agent_id": "data-agent"}).json()["events"]
    assert events and all(e["agent_id"] == "data-agent" for e in events)


def test_denials_are_recorded_as_denied(chained):
    client, _ = chained
    events = client.get("/audit", params={"event_type": "tool.call.denied.policy"}).json()["events"]
    assert events and all(e["allowed"] is False for e in events)
