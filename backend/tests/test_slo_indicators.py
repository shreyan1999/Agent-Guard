"""What fills each of an SLO's four indicators — and what leaves one empty.

The Agent SRE card shows four indicators per agent. Three of them were reachable
only from a real governed call; the panel's demo buttons feed exactly one. That
is by design and is pinned below, because a card reading `task_success_rate 67%`
beside three rows of "no data" looks broken when it is in fact telling the truth
about how little has been measured.

The fourth row was genuinely broken. ``ResponseLatency`` computes its percentile
from a list it keeps on the indicator, and only ``record_latency()`` appends to
it — the inherited ``record()`` writes the measurement store alone. AgentGuard
called ``record()``, so the indicator reported a rising ``measurement_count``
with ``current_value`` permanently ``None``: "no data" next to a count of every
call ever made. Worse than a missing number, because the count implied the
number should have been there.

The same mismatch came back after every restart even once recording was fixed,
since nothing repopulated that list from the durable store. Both halves are
covered here.
"""

import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main

AGENT = "research-agent"


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def indicators(client, agent=AGENT):
    """Every indicator for one agent, keyed by name."""
    slo = next(s for s in client.get("/sre/slos").json()
               if s["agent_id"] == agent)
    return slo, {i["name"]: i for i in slo["indicators"]}


def call(client, tool="db_query", action="read", agent=AGENT):
    return client.post("/tools/call", json={
        "tool_name": tool, "action": action, "agent_id": agent}).json()


# ── the latency percentile ───────────────────────────────────────────────────

def test_latency_reports_a_value_not_just_a_count(client, endpoint_tool):
    """The bug this file exists for.

    A count with no value is the worst of both: it says a measurement was taken
    and then declines to say what it was.
    """
    for _ in range(3):
        assert call(client, tool="reporting")["allowed"] is True

    _, ind = indicators(client)
    latency = ind["response_latency_p95"]
    assert latency["measurement_count"] == 3
    assert latency["current_value"] is not None
    assert latency["current_value"] > 0


def test_a_count_without_a_value_is_never_reported(client, endpoint_tool):
    """Stated as the general rule rather than for latency alone: any indicator
    claiming measurements must be able to say what they were."""
    for _ in range(2):
        call(client, tool="reporting")

    _, ind = indicators(client)
    for name, entry in ind.items():
        if entry["measurement_count"] > 0:
            assert entry["current_value"] is not None, name


def test_the_percentile_survives_a_restart(client, state_dir):
    """`_latencies` is in-memory and nothing refills it from the durable store,
    so without an explicit replay the indicator goes back to "no data" on every
    restart while the persisted count keeps climbing."""
    c = TestClient(main.app)
    c.post("/agents", json={"id": "runner", "name": "runner",
                            "trust_score": 0.9, "owner": "ops@acme",
                            "purpose": "latency replay"})
    for _ in range(3):
        c.post("/tools/call", json={"tool_name": "db_query", "action": "read",
                                    "agent_id": "runner"})
    _, before = indicators(c, "runner")
    assert before["response_latency_p95"]["current_value"] is not None

    main.reset_state()          # the same path a fresh process takes

    _, after = indicators(TestClient(main.app), "runner")
    assert after["response_latency_p95"]["measurement_count"] == 3
    assert after["response_latency_p95"]["current_value"] is not None


# ── which signal fills which indicator ───────────────────────────────────────

def test_a_real_call_fills_every_indicator(client, endpoint_tool):
    """A governed call against a tool that really runs is the only thing that
    moves all four."""
    call(client, tool="reporting")
    _, ind = indicators(client)
    for name in ("task_success_rate", "policy_compliance",
                 "response_latency_p95", "tool_call_accuracy"):
        assert ind[name]["measurement_count"] == 1, name


def test_the_demo_button_fills_only_task_success(client):
    """Which is why the other three read "no data" on a card driven by clicks."""
    client.post(f"/sre/signal/{AGENT}?success=true")
    _, ind = indicators(client)
    assert ind["task_success_rate"]["measurement_count"] == 1
    for name in ("policy_compliance", "response_latency_p95",
                 "tool_call_accuracy"):
        assert ind[name]["measurement_count"] == 0, name


def test_a_decision_only_tool_does_not_move_accuracy(client):
    """db_query has no endpoint bound. Governance allowed the call, but nothing
    ran, so scoring it as an accurate tool call would inflate the indicator
    with calls that never happened."""
    call(client)
    _, ind = indicators(client)
    assert ind["task_success_rate"]["measurement_count"] == 1
    assert ind["tool_call_accuracy"]["measurement_count"] == 0


def test_a_denial_moves_task_and_policy_together(client):
    client.post("/agents", json={"id": "low", "name": "low",
                                 "trust_score": 0.05, "owner": "ops@acme",
                                 "purpose": "denial"})
    assert call(client, agent="low")["allowed"] is False
    _, ind = indicators(client, "low")
    assert ind["task_success_rate"]["current_value"] == 0.0


# ── what the card says about itself ──────────────────────────────────────────

def test_hand_entered_measurements_are_counted_and_disclosed(client):
    for success in (True, True, False):
        client.post(f"/sre/signal/{AGENT}?success={str(success).lower()}")
    slo, ind = indicators(client)
    assert slo["synthetic_measurements"] == 3
    assert slo["task_measurements"] == 3
    assert slo["evidence_only"] is False
    assert ind["task_success_rate"]["current_value"] == pytest.approx(2 / 3, abs=1e-3)


def test_real_calls_are_marked_as_evidence(client, endpoint_tool):
    call(client, tool="reporting")
    slo, _ = indicators(client)
    assert slo["synthetic_measurements"] == 0
    assert slo["evidence_only"] is True


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def endpoint_tool(client, monkeypatch):
    """A tool with a live endpoint, so calls actually execute."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    monkeypatch.setenv("AGT_TOOL_ALLOW_PRIVATE", "1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/run"
    client.post("/tools/register", json={
        "name": "reporting", "description": "Runs a report.",
        "actions": ["read"], "risk": "low", "category": "data_read",
        "endpoint_url": url})
    try:
        yield url
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def state_dir(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="agt-slo-ind-"))
    monkeypatch.setenv("AGT_STATE_DIR", str(d))
    main.reset_state()
    try:
        yield d
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        main.reset_state()
