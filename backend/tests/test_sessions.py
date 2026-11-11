"""Sessions: the ACS agent_startup and agent_shutdown points.

Before this there was nothing bracketing a call — one arrived, was decided, and
that was the whole of an agent's visible life. A session supplies the bracket,
and it is AGT's: `sessions.SessionManager` wraps the Hypervisor's own state
machine, handshake and teardown rather than modelling a session here.

Three properties are worth more than the endpoint coverage:

  * **binding is optional.** Every existing caller passes no session and must be
    decided exactly as before;
  * **a session cannot buy privilege.** The ring is the stricter of the two on
    offer, so binding one can only ever narrow what an agent may do; and
  * **the claims are kept honest.** `/compliance/acs` says which points this
    platform answers, and the tests below assert the "implemented" ones
    actually answer rather than taking the table's word for it.
"""

import pytest

import main
import sessions
from hypervisor.models import ExecutionRing


@pytest.fixture
def worker(client):
    client.post("/agents", json={"id": "worker", "name": "worker",
                                 "trust_score": 0.9})
    return client


def open_session(client):
    return client.post("/sessions", json={}).json()["session_id"]


# -- the state machine is the toolkit's ---------------------------------------

def test_a_session_walks_agts_own_states(worker):
    session_id = open_session(worker)
    assert worker.get(f"/sessions/{session_id}").json()["state"] == "HANDSHAKING"

    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})
    worker.post(f"/sessions/{session_id}/activate")
    assert worker.get(f"/sessions/{session_id}").json()["state"] == "ACTIVE"

    closed = worker.delete(f"/sessions/{session_id}").json()
    assert closed["state"] == "ARCHIVED"


def test_the_handshake_assigns_the_ring_not_this_platform(worker):
    """AGT derives it from the same score, then may demote. Never promote."""
    worker.post("/agents", json={"id": "low", "name": "low", "trust_score": 0.45})
    session_id = open_session(worker)

    high = worker.post(f"/sessions/{session_id}/join",
                       json={"agent_id": "worker"}).json()
    low = worker.post(f"/sessions/{session_id}/join",
                      json={"agent_id": "low"}).json()

    assert high["ring_name"] == "RING_2_STANDARD"
    assert low["ring_name"] == "RING_3_SANDBOX"


def test_the_delta_root_is_reported_as_the_toolkit_returns_it(worker):
    """It is always None here, and saying so beats omitting the field.

    AGT computes that root over deltas recorded in the session's own
    DeltaEngine. This platform writes its evidence to the audit chain instead
    and records no such deltas, so there is nothing to hash — a field that
    looks like evidence must not be quietly dropped.
    """
    session_id = open_session(worker)
    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})
    worker.post(f"/sessions/{session_id}/activate")

    closed = worker.delete(f"/sessions/{session_id}").json()
    assert "delta_hash_chain_root" in closed
    assert closed["delta_hash_chain_root"] is None


# -- binding a call ------------------------------------------------------------

def test_a_call_without_a_session_is_decided_exactly_as_before(worker):
    """The whole feature is additive or it is a breaking change."""
    result = worker.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "worker"}).json()
    assert result["allowed"] is True


def test_a_call_may_be_bound_to_an_active_session(worker):
    session_id = open_session(worker)
    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})
    worker.post(f"/sessions/{session_id}/activate")

    result = worker.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "worker", "session_id": session_id}).json()
    assert result["allowed"] is True


def test_a_session_that_has_not_been_activated_refuses_calls(worker):
    session_id = open_session(worker)
    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})

    result = worker.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "worker", "session_id": session_id}).json()

    assert result["allowed"] is False
    assert result["denied_by"] == "session"
    assert result["rule"] == "session:inactive"


def test_a_closed_session_refuses_calls(worker):
    session_id = open_session(worker)
    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})
    worker.post(f"/sessions/{session_id}/activate")
    worker.delete(f"/sessions/{session_id}")

    result = worker.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "worker", "session_id": session_id}).json()
    assert result["allowed"] is False
    assert result["rule"] == "session:inactive"


def test_an_agent_that_never_joined_cannot_use_the_session(worker):
    worker.post("/agents", json={"id": "outsider", "name": "outsider",
                                 "trust_score": 0.9})
    session_id = open_session(worker)
    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})
    worker.post(f"/sessions/{session_id}/activate")

    result = worker.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "outsider", "session_id": session_id}).json()

    assert result["allowed"] is False
    assert result["rule"] == "session:not_a_participant"


def test_a_session_can_only_narrow_what_an_agent_may_do(client):
    """The property that makes binding one safe.

    The agent joins while sandboxed, then its trust rises. Outside the session
    it is ring 2 and may reach the network; inside, it is still held at the
    ring it joined at. A session must never be a way to gain privilege, so the
    stricter of the two always wins.
    """
    client.post("/agents", json={"id": "grower", "name": "grower",
                                 "trust_score": 0.45})
    session_id = open_session(client)
    joined = client.post(f"/sessions/{session_id}/join",
                         json={"agent_id": "grower"}).json()
    client.post(f"/sessions/{session_id}/activate")
    assert joined["ring_name"] == "RING_3_SANDBOX"

    # Trust rises after the handshake.
    main._trust_scores["grower"] = 0.9
    assert main._ring_for(0.9) is ExecutionRing.RING_2_STANDARD

    inside = client.post("/tools/call", json={
        "tool_name": "send_email", "action": "read",
        "agent_id": "grower", "session_id": session_id}).json()
    outside = client.post("/tools/call", json={
        "tool_name": "send_email", "action": "read",
        "agent_id": "grower"}).json()

    assert inside["allowed"] is False
    assert inside["rule"] == "ring:network"
    assert outside["allowed"] is True


# -- evidence ------------------------------------------------------------------

def test_the_session_boundary_lands_in_the_one_audit_chain(worker):
    """There is no second chain: open, join and close are ordinary events."""
    session_id = open_session(worker)
    worker.post(f"/sessions/{session_id}/join", json={"agent_id": "worker"})
    worker.post(f"/sessions/{session_id}/activate")
    worker.delete(f"/sessions/{session_id}")

    kinds = {e["event_type"] for e in worker.get("/audit?limit=100").json()["events"]}
    assert {"session.opened", "session.joined",
            "session.activated", "session.closed"} <= kinds

    verify = worker.get("/audit/verify").json()
    assert verify["valid"] is True


def test_the_boundary_events_name_the_acs_point_they_answer(worker):
    session_id = open_session(worker)
    worker.delete(f"/sessions/{session_id}")
    events = worker.get("/audit?event_type=session.opened").json()["events"]
    assert any(e["details"].get("acs_point") == "agent_startup" for e in events)
    closed = worker.get("/audit?event_type=session.closed").json()["events"]
    assert any(e["details"].get("acs_point") == "agent_shutdown" for e in closed)


# -- the ACS claim -------------------------------------------------------------

def test_the_acs_report_covers_the_whole_specification(client):
    body = client.get("/compliance/acs").json()
    assert body["total_points"] == 8
    assert {p["point"] for p in body["points"]} == {
        "agent_startup", "input", "pre_model_call", "post_model_call",
        "pre_tool_call", "post_tool_call", "output", "agent_shutdown"}


def test_the_model_points_are_called_out_of_scope_not_missing(client):
    """The distinction is the point of publishing the table at all."""
    by_point = {p["point"]: p for p in client.get("/compliance/acs").json()["points"]}
    for name in ("pre_model_call", "post_model_call", "output"):
        assert by_point[name]["status"] == "out_of_scope"
        assert by_point[name]["detail"]


@pytest.mark.parametrize("point", ["agent_startup", "pre_tool_call",
                                   "agent_shutdown"])
def test_every_point_claimed_implemented_really_answers(worker, point):
    """A table that drifts from the code is worse than no table.

    Each claim is exercised rather than trusted: a session opens and closes,
    and a tool call is decided by the gates.
    """
    by_point = {p["point"]: p
                for p in worker.get("/compliance/acs").json()["points"]}
    assert by_point[point]["status"] == "implemented"

    if point == "agent_startup":
        session_id = open_session(worker)
        assert worker.get(f"/sessions/{session_id}").json()["state"] == "HANDSHAKING"
    elif point == "agent_shutdown":
        session_id = open_session(worker)
        assert worker.delete(f"/sessions/{session_id}").json()["state"] == "ARCHIVED"
    else:
        decided = worker.post("/tools/call", json={
            "tool_name": "db_query", "action": "read",
            "agent_id": "worker"}).json()
        assert "allowed" in decided


def test_an_unknown_session_is_a_404(client):
    assert client.get("/sessions/session:nope").status_code == 404
    assert client.delete("/sessions/session:nope").status_code == 404


def test_sessions_do_not_survive_a_teardown():
    """Session state is process state, like the breach detectors."""
    manager = sessions.SessionManager()
    manager.open(creator="did:mesh:op")
    assert len(manager.all()) == 1
    manager.clear()
    assert manager.all() == []
