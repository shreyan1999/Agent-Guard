"""The demo scenario the dashboard can load and unload on demand.

A fresh instance has an empty audit chain, so every panel reading from it is
honestly blank. `/demo/seed` fills it in — and the point of these tests is that
filling it in is not the same as faking it. Every row the endpoint produces goes
through the real handlers and is decided by the real gates, so the tests assert
on the *verdicts*, not on the fact that rows appeared.

The removal half carries the harder constraint. Agents can be decommissioned and
a policy deleted, but the decisions those agents made are in an append-only,
hash-linked chain. Quietly dropping entries would be exactly the tampering the
chain exists to detect, so the endpoint leaves them and says so. That admission
is tested here, because an unload that implied a clean slate would be the lie.
"""

import os

import pytest
from starlette.testclient import TestClient

import demo_seed
import main


def _status(client):
    return client.get("/demo/seed").json()


@pytest.fixture
def auth_client():
    """An instance with auth on, so the role gate can be exercised."""
    main.reset_state()
    os.environ["AGT_API_KEYS"] = ("op-tok:otto:acme:operator, "
                                  "admin-tok:root:acme:admin")
    main.reload_auth()
    try:
        yield TestClient(main.app)
    finally:
        os.environ.pop("AGT_API_KEYS", None)
        main.reload_auth()
        main.teardown_state(clear_policies=True)


# -- loading ------------------------------------------------------------------

def test_a_fresh_instance_reports_the_scenario_unloaded(client):
    body = _status(client)
    assert body["loaded"] is False
    assert body["agents"] == []
    assert body["agent_ids"] == list(demo_seed.SEEDED_AGENT_IDS)


def test_loading_registers_the_fleet_and_the_child_policy(client):
    body = client.post("/demo/seed").json()
    assert body["loaded"] is True
    assert sorted(body["agents_created"]) == sorted(demo_seed.SEEDED_AGENT_IDS)
    assert body["policy_created"] == demo_seed.SEEDED_POLICY

    names = {p["name"] for p in client.get("/policies").json()}
    assert demo_seed.SEEDED_POLICY in names
    live = {a["id"] for a in client.get("/agents").json()}
    assert set(demo_seed.SEEDED_AGENT_IDS) <= live


def test_the_child_policy_really_inherits_the_baseline(client):
    """`extends` is not decoration: the parent's rules must reach the child."""
    client.post("/demo/seed")
    resolved = client.get(f"/policies/{demo_seed.SEEDED_POLICY}/resolved").json()
    assert "default-policy" in resolved["chain"]
    inherited = {r["name"] for r in resolved["rules"] if r["inherited"]}
    assert "block-destructive" in inherited


def test_every_gate_denies_at_least_once(client):
    """The scenario exists to exercise the gates, not to fill a table."""
    body = client.post("/demo/seed").json()
    assert {"lifecycle", "trust", "ring", "policy"} <= set(body["gates_exercised"]), \
        f"gates actually exercised: {body['gates_exercised']}"


def test_the_platform_agrees_with_every_advertised_verdict(client):
    """A demo that mislabels its own data poisons every panel it fills."""
    body = client.post("/demo/seed").json()
    assert body["surprises"] == [], body["surprises"]


def test_loading_produces_real_audit_entries_and_alerts(client):
    before = client.get("/audit").json()["total"]
    client.post("/demo/seed")
    after = client.get("/audit").json()["total"]
    assert after > before

    # Denials raise alerts through AGT's own AlertManager, not through a
    # fixture: if the calls were fake there would be nothing to alert on.
    alerts = client.get("/sre/alerts").json()["alerts"]
    assert any(a["source"] == "governance" for a in alerts)


def test_a_denied_call_is_recorded_as_denied(client):
    client.post("/demo/seed")
    denied = client.get("/audit?event_type=tool.call.denied.policy").json()["events"]
    assert denied and all(e["allowed"] is False for e in denied)


def test_loading_twice_is_reproducible(client):
    """The second load must exercise the same gates as the first.

    This is the regression that matters: the scenario suspends an agent at the
    end, and the lifecycle gate runs before the ring gate — so without resuming
    it first, the re-run's ring denials silently become lifecycle denials and
    the scenario quietly covers one gate fewer.
    """
    first = client.post("/demo/seed").json()
    second = client.post("/demo/seed").json()

    assert second["agents_created"] == []
    assert sorted(second["agents_reused"]) == sorted(demo_seed.SEEDED_AGENT_IDS)
    assert "scraper-agent" in second["agents_resumed"]
    assert second["gates_exercised"] == first["gates_exercised"]
    assert second["surprises"] == []


def test_the_kill_switch_is_engaged_and_denies(client):
    body = client.post("/demo/seed").json()
    assert body["suspended"] == "scraper-agent"
    agent = next(a for a in client.get("/agents").json() if a["id"] == "scraper-agent")
    assert agent["state"] == "suspended"


# -- the parts that depend on the environment ---------------------------------

def test_the_playground_agents_are_registered_when_missing(client):
    """Durable mode seeds none, which would break the Tool Playground presets.

    In memory-only mode the platform has already seeded them, so the load must
    leave them alone rather than failing on a duplicate.
    """
    client.post("/demo/seed")
    live = {a["id"] for a in client.get("/agents").json()}
    for agent_id, *_ in demo_seed.PLAYGROUND_AGENTS:
        assert agent_id in live, f"{agent_id} is missing; playground presets would break"


def test_the_mcp_half_runs_in_process_and_fills_the_receipts_panel(client):
    """The seed starts the bundled MCP server in-process, so the fifth gate is
    exercised and the receipts panel is filled without a second terminal.

    The calls really cross the wire to a real MCP server on loopback; the SSRF
    guard is relaxed only for that import, via a request-scoped override.
    """
    body = client.post("/demo/seed").json()
    mcp = body["mcp"]
    assert mcp["skipped"] is None, mcp["skipped"]
    assert len(mcp["imported"]) == 4
    # Every MCP decision earns a signed receipt, allow or deny.
    assert mcp["calls"], "the MCP calls must have run"
    assert all(c["receipt"] for c in mcp["calls"])
    assert body["receipts"] >= len(mcp["calls"])
    # The fifth gate denies too: a critical descriptor is refused at dispatch.
    assert "mcp_proxy" in body["gates_exercised"]
    # And the rest of the scenario is unaffected.
    assert {"lifecycle", "trust", "ring", "policy"} <= set(body["gates_exercised"])
    assert body["surprises"] == []


def test_the_load_reports_whether_tracing_is_on(client):
    """Traces need AGT_STATE_DIR; the response says so rather than the panel
    being mysteriously empty."""
    body = client.post("/demo/seed").json()
    assert body["traces_enabled"] is False          # no state dir in the suite
    assert client.get("/traces").json()["enabled"] is False


def test_receipts_are_reported_and_stay_after_an_unload(client):
    """Receipts are signed and hash-chained, so they are kept like audit entries."""
    loaded = client.post("/demo/seed").json()
    assert "receipts" in loaded
    body = client.delete("/demo/seed").json()
    assert "receipts_retained" in body
    assert body["receipts_retained"] == loaded["receipts"]


# -- unloading ----------------------------------------------------------------

def test_unloading_decommissions_the_agents_and_deletes_the_policy(client):
    client.post("/demo/seed")
    body = client.delete("/demo/seed").json()

    assert body["loaded"] is False
    assert sorted(body["agents_decommissioned"]) == sorted(demo_seed.SEEDED_AGENT_IDS)
    assert body["policy_removed"] == demo_seed.SEEDED_POLICY
    assert body["failed"] == []

    names = {p["name"] for p in client.get("/policies").json()}
    assert demo_seed.SEEDED_POLICY not in names
    assert _status(client)["loaded"] is False


def test_a_decommissioned_demo_agent_can_no_longer_call(client):
    """Removal has to actually remove the capability, not just the listing."""
    client.post("/demo/seed")
    client.delete("/demo/seed")
    result = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "billing-agent",
    }).json()
    assert result["allowed"] is False
    assert result["denied_by"] == "lifecycle"


def test_unloading_keeps_the_audit_entries_and_says_so(client):
    """The admission is the feature: an append-only chain cannot be edited."""
    client.post("/demo/seed")
    entries_before = client.get("/audit").json()["total"]

    body = client.delete("/demo/seed").json()

    assert body["audit_entries_retained"] >= entries_before
    assert "append-only" in body["note"]
    # And the chain is still intact and still holds them.
    verify = client.get("/audit/verify").json()
    assert verify["valid"] is True
    assert client.get("/audit").json()["total"] >= entries_before


def test_unloading_leaves_the_platform_default_policy_alone(client):
    client.post("/demo/seed")
    client.delete("/demo/seed")
    names = {p["name"] for p in client.get("/policies").json()}
    assert "default-policy" in names


def test_unloading_when_nothing_is_loaded_is_harmless(client):
    body = client.delete("/demo/seed").json()
    assert body["agents_decommissioned"] == []
    assert body["policy_removed"] is None
    assert body["failed"] == []


def test_load_unload_load_returns_to_a_working_scenario(client):
    client.post("/demo/seed")
    client.delete("/demo/seed")
    again = client.post("/demo/seed").json()
    assert again["loaded"] is True
    assert {"lifecycle", "trust", "ring", "policy"} <= set(again["gates_exercised"])


# -- who may do it ------------------------------------------------------------

@pytest.mark.parametrize("method", ["post", "delete"])
def test_mutating_the_demo_data_is_admin_only(auth_client, method):
    """It registers agents and writes to the chain, so it needs the same bar
    as the adversarial run."""
    operator = {"Authorization": "Bearer op-tok"}
    admin = {"Authorization": "Bearer admin-tok"}
    assert getattr(auth_client, method)("/demo/seed", headers=operator).status_code == 403
    assert getattr(auth_client, method)("/demo/seed", headers=admin).status_code == 200
