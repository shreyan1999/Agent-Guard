"""What /stats costs, and what it is allowed to claim in exchange.

Verifying the chain re-hashes every entry. `/stats` did that on every request,
and the dashboard polls it every eight seconds per open browser — so the cost of
leaving the page open grew with the length of the chain, while holding the lock
every append needs. It also materialised and reversed the whole chain twice more
just to count it.

The fix has an honesty constraint attached, and these tests pin both halves.

**Cheap:** a poll answers from the last verification rather than recomputing one,
and counts come from a single allocation-free pass.

**Still true:** the cached verdict is reported with `chain_verified_at` and
`chain_verified_entries`, so it cannot be read as a statement about *now*;
`/audit/verify` — the endpoint an operator reaches for, and the Verify button —
always does a fresh walk and refreshes what `/stats` reports; and no count comes
from a side tally, because a counter would go on reporting the length of a chain
somebody had just deleted an entry from, and catching exactly that is the point.
"""

import pytest


@pytest.fixture
def chained(client, app_module):
    """A client whose audit chain holds a few known events, one of them denied."""
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


def count_verifications(app_module):
    """Replace AGT's verify_integrity with a counting passthrough."""
    calls = []
    real = app_module._audit._log.verify_integrity

    def counting():
        calls.append(1)
        return real()

    app_module._audit._log.verify_integrity = counting
    return calls


# -- Cost ---------------------------------------------------------------------

def test_polling_stats_does_not_rehash_the_chain_every_time(chained):
    client, app_module = chained
    calls = count_verifications(app_module)
    for _ in range(6):
        client.get("/stats")
    assert len(calls) == 1, \
        f"/stats re-verified the chain {len(calls)} times across 6 polls"


def test_audit_verify_is_always_a_fresh_walk(chained):
    """The on-demand endpoint never answers from the poller's cache."""
    client, app_module = chained
    calls = count_verifications(app_module)
    for _ in range(3):
        client.get("/audit/verify")
    assert len(calls) == 3


def test_a_compliance_report_verifies_for_real(chained):
    """A report is evidence, so it pays for the walk rather than reading a cache."""
    client, app_module = chained
    client.get("/stats")                       # warm the cache
    calls = count_verifications(app_module)
    client.get("/compliance/report?framework=soc2")
    assert len(calls) == 1


def test_the_cached_verdict_expires(chained, monkeypatch):
    client, app_module = chained
    monkeypatch.setattr(type(app_module._audit), "VERIFY_TTL_SECONDS", 0.0)
    calls = count_verifications(app_module)
    client.get("/stats")
    client.get("/stats")
    assert len(calls) == 2


# -- Honesty ------------------------------------------------------------------

def test_stats_says_when_the_verdict_was_taken(chained):
    client, _ = chained
    d = client.get("/stats").json()
    assert d["chain_valid"] is True
    assert d["chain_verified_at"], "a cached verdict with no timestamp is a claim"
    assert d["chain_verified_entries"] >= 3


def test_tampering_is_caught_immediately_despite_a_warm_cache(chained):
    """The cache must never be able to hide a break from the real check."""
    client, app_module = chained
    client.get("/stats")                       # caches a valid verdict
    entries(app_module)[1].outcome = "success"
    assert client.get("/audit/verify").json()["valid"] is False


def test_a_fresh_verify_updates_what_stats_reports(chained):
    """The cache is refreshed by the real walk, not bypassed by it."""
    client, app_module = chained
    assert client.get("/stats").json()["chain_valid"] is True
    entries(app_module)[1].outcome = "success"
    client.get("/audit/verify")
    assert client.get("/stats").json()["chain_valid"] is False


def test_reset_drops_the_verdict_for_the_chain_it_replaced(chained):
    client, app_module = chained
    entries(app_module)[1].outcome = "success"
    assert client.get("/audit/verify").json()["valid"] is False
    client.delete("/audit")
    assert client.get("/stats").json()["chain_valid"] is True


# -- Counting -----------------------------------------------------------------

def test_entry_count_is_read_from_the_chain_not_a_counter(chained):
    """A tally would keep reporting the old length after an entry was removed."""
    client, app_module = chained
    before = client.get("/audit/verify").json()["entry_count"]
    entries(app_module).pop()
    after = client.get("/audit/verify").json()["entry_count"]
    assert after == before - 1, \
        "entry_count survived a deletion, so it is not being read from the chain"


def test_stats_counters_match_the_chain_exactly(chained):
    client, app_module = chained
    chain = entries(app_module)
    expected_denials = sum(1 for e in chain if e.outcome == "denied")
    d = client.get("/stats").json()
    assert d["audit_events"] == len(chain)
    assert d["denials"] == expected_denials
    assert expected_denials >= 1, "the fixture should have produced a denial"


def test_audit_total_matches_the_chain(chained):
    client, app_module = chained
    body = client.get("/audit", params={"limit": 1}).json()
    assert body["total"] == len(entries(app_module))
    assert len(body["events"]) == 1


def test_listing_is_still_newest_first_and_bounded(chained):
    """The backwards walk must not have changed the order or the page size."""
    client, _ = chained
    events = client.get("/audit", params={"limit": 3}).json()["events"]
    assert len(events) == 3
    stamps = [e["timestamp"] for e in events]
    assert stamps == sorted(stamps, reverse=True)


def test_filtered_listing_is_unchanged(chained):
    """agent_id / event_type still route through AGT's own query()."""
    client, _ = chained
    events = client.get("/audit", params={"agent_id": "data-agent"}).json()["events"]
    assert events and all(e["agent_id"] == "data-agent" for e in events)
