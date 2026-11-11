"""Replayable traces of governed calls (`agent_sre.replay` + `agent_sre.tracing`).

The audit chain answers *that* a decision happened and proves the record has not
been edited. These tests pin the other question: *how* it happened — which gate
ran, in what order, how long each took — and the honesty constraints on that
answer. A timeline is easy to make look precise; the work here is making sure
every duration on it is something that was actually measured.

Specifically:

* the trace ends on the gate that stopped the call, and no later gate appears;
* the gates share none of their time with the audit and alert writes that follow
  the decision — those get their own span, so the trace duration is accounted
  for rather than silently attributed to whichever gate ran last;
* the remote round trip is the connector's own measurement, not a slice of the
  governance window;
* ring, policy and the MCP proxy share one span, because AGT decides them inside
  `govern()` and this platform cannot honestly time them apart;
* AGT's `ReplayEngine` — not a text diff — says how two traces differ.
"""

import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main


# ── Tracing is durable-mode only, so every test runs under a state dir ───────

@pytest.fixture
def client(app_module, monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="agt-traces-"))
    monkeypatch.setenv("AGT_STATE_DIR", str(d))
    main.reset_state()
    c = TestClient(main.app)
    # Durable mode seeds no demo agents: a real deployment is populated by real
    # registrations, so the fixture registers what it needs.
    for name, trust in (("tracer-agent", 0.9), ("low-agent", 0.1)):
        c.post("/agents", json={"id": name, "name": name, "trust_score": trust,
                                "owner": "ops@example.com", "purpose": "tracing"})
    try:
        yield c
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        main.reset_state()


class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length) if length else b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({"echo": True}).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


@pytest.fixture
def webhook(monkeypatch):
    """A live loopback endpoint, so a dispatch span has a real call behind it."""
    monkeypatch.setenv("AGT_TOOL_ALLOW_PRIVATE", "1")
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/hook"
    finally:
        server.shutdown()
        server.server_close()


def _call(client, agent="tracer-agent", tool="db_query", **kw):
    return client.post("/tools/call",
                       json={"tool_name": tool, "agent_id": agent, **kw}).json()


def _spans(client, trace_id):
    return client.get(f"/traces/{trace_id}").json()["spans"]


def _names(spans):
    return [s["name"] for s in spans]


# ── A call produces a trace ──────────────────────────────────────────────────

def test_an_allowed_call_returns_a_trace_id(client):
    body = _call(client)
    assert body["allowed"] is True
    assert body["trace_id"]
    assert client.get(f"/traces/{body['trace_id']}").status_code == 200


def test_a_denied_call_is_traced_too(client):
    """A trace only of the yeses would be worth little: the interesting
    question is almost always why something was refused."""
    body = _call(client, agent="low-agent")
    assert body["allowed"] is False and body["denied_by"] == "trust"
    trace = client.get(f"/traces/{body['trace_id']}").json()
    assert trace["success"] is False
    assert trace["metadata"]["agent.policy.decision"] == "deny"


def test_the_gates_appear_in_the_order_they_run(client):
    trace_id = _call(client)["trace_id"]
    gates = [n for n in _names(_spans(client, trace_id)) if n.startswith("gate:")]
    assert gates == ["gate:lifecycle", "gate:identity", "gate:tenant",
                     "gate:trust", "gate:govern"]


def test_semantic_attribute_names_are_agts_not_ours(client):
    """Emitting AGT's vocabulary is what makes a trace readable by anything else
    that speaks it."""
    from agent_sre.tracing import (
        AGENT_DID, AGENT_POLICY_NAME, AGENT_TOOL_NAME, AGENT_TRUST_SCORE,
    )
    meta = client.get(f"/traces/{_call(client)['trace_id']}").json()["metadata"]
    for key in (AGENT_DID, AGENT_POLICY_NAME, AGENT_TOOL_NAME, AGENT_TRUST_SCORE):
        assert key in meta, key
    assert meta[AGENT_TRUST_SCORE] == 0.9


# ── The trace stops where the decision was made ──────────────────────────────

def test_a_denial_ends_on_the_gate_that_denied(client):
    trace_id = _call(client, agent="low-agent")["trace_id"]
    spans = _spans(client, trace_id)
    gate = next(s for s in spans if s["name"] == "gate:trust")
    assert gate["status"] == "error"
    assert "deny-low-trust" in gate["error"]
    # Nothing downstream of the denial may appear: a trace showing govern after
    # a trust denial would describe a call that never happened.
    assert "gate:govern" not in _names(spans)


def test_an_unregistered_agent_stops_at_the_first_gate(client):
    trace_id = _call(client, agent="ghost")["trace_id"]
    gates = [n for n in _names(_spans(client, trace_id)) if n.startswith("gate:")]
    assert gates == ["gate:lifecycle"]


# ── Durations are measurements, not decoration ───────────────────────────────

def test_the_spans_account_for_the_whole_trace(client):
    """The gap between a trace's duration and its spans is where a reader would
    otherwise guess a gate was slow. The post-decision writes get their own span
    so there is nothing left to guess about."""
    trace = client.get(f"/traces/{_call(client)['trace_id']}").json()
    total = sum(s["duration_ms"] for s in trace["spans"])
    assert total == pytest.approx(trace["duration_ms"], abs=5.0)


def test_the_governance_write_down_is_not_charged_to_a_gate(client):
    """Audit hashing and alerting cost real milliseconds. Billing them to
    whichever gate happened to decide would make that gate look slow and hide
    the actual cost."""
    spans = {s["name"]: s for s in _spans(client, _call(client)["trace_id"])}
    assert "record:governance" in spans
    assert spans["record:governance"]["kind"] == "internal"
    # The gates themselves are in-process comparisons; they are not where the
    # time goes, and the trace should say so.
    assert spans["gate:trust"]["duration_ms"] < spans["record:governance"]["duration_ms"]


def test_a_dispatch_span_carries_the_connectors_own_measurement(client, webhook):
    client.post("/tools/register", json={"name": "echo_tool", "risk": "low",
                                         "endpoint_url": webhook})
    body = _call(client, tool="echo_tool")
    assert body["executed"] is True
    spans = {s["name"]: s for s in _spans(client, body["trace_id"])}
    assert "echo_tool" in spans, list(spans)
    dispatch = spans["echo_tool"]
    assert dispatch["kind"] == "tool_call"
    # The remote round trip AGT's connector timed, not a slice of the govern
    # window apportioned after the fact.
    assert dispatch["duration_ms"] == pytest.approx(
        body["result"]["latency_ms"], abs=3.0)
    # And it is subtracted from govern rather than double-counted.
    assert spans["gate:govern"]["duration_ms"] >= 0


def test_a_decision_only_tool_has_no_dispatch_span(client):
    """Nothing was dispatched, so nothing may appear as if it had been."""
    client.post("/tools/register", json={"name": "ledger", "risk": "low"})
    body = _call(client, tool="ledger")
    assert body["executed"] is False
    assert all(s["kind"] != "tool_call" for s in _spans(client, body["trace_id"]))


def test_ring_policy_and_the_proxy_share_one_span(client):
    """AGT decides all three inside govern() and returns one outcome. Three
    spans here would be three invented durations."""
    spans = _spans(client, _call(client)["trace_id"])
    assert _names(spans).count("gate:govern") == 1
    assert not any(n in _names(spans) for n in ("gate:ring", "gate:policy",
                                                "gate:mcp_proxy"))
    govern = next(s for s in spans if s["name"] == "gate:govern")
    assert govern["attributes"]["ring"] == "RING_2_STANDARD"
    assert govern["attributes"]["mcp_proxy"] is False


# ── Replay: AGT's engine says how two traces differ ──────────────────────────

def test_two_identical_calls_diff_clean(client):
    a, b = _call(client)["trace_id"], _call(client)["trace_id"]
    result = client.get(f"/traces/diff?a={a}&b={b}").json()
    assert result["identical"] is True
    assert result["diffs"] == []


def test_an_allow_and_a_deny_diff_into_typed_findings(client):
    allowed = _call(client)["trace_id"]
    denied = _call(client, agent="low-agent")["trace_id"]
    result = client.get(f"/traces/diff?a={allowed}&b={denied}").json()
    assert result["identical"] is False
    kinds = {d["type"] for d in result["diffs"]}
    # Typed findings from AGT's ReplayEngine, not a text diff: "the same call
    # decided differently" is a machine-readable fact.
    assert "status_change" in kinds
    assert any(d["span"] == "gate:trust" for d in result["diffs"])


def test_diffing_a_missing_trace_is_a_404(client):
    trace_id = _call(client)["trace_id"]
    assert client.get(f"/traces/diff?a={trace_id}&b=nope").status_code == 404


# ── The store ────────────────────────────────────────────────────────────────

def test_traces_are_listed_newest_first_and_filterable(client):
    """AGT lists by filename and a trace id is random hex, so its order is
    arbitrary. Someone opening this list wants the call that just failed."""
    first = _call(client)["trace_id"]
    second = _call(client, agent="low-agent")["trace_id"]
    body = client.get("/traces").json()
    assert body["enabled"] is True
    assert [t["trace_id"] for t in body["traces"]] == [second, first]
    mine = client.get("/traces?agent_id=low-agent").json()["traces"]
    assert [t["agent_id"] for t in mine] == ["low-agent"]


def test_a_trace_survives_a_restart(client):
    """The point of writing them to AGT_STATE_DIR: the trace of the call that
    caused an incident is still there after the process that served it is gone."""
    trace_id = _call(client)["trace_id"]
    main.teardown_state()      # rebuilds every store from the environment
    assert client.get(f"/traces/{trace_id}").status_code == 200


def test_a_trace_can_be_deleted(client):
    trace_id = _call(client)["trace_id"]
    assert client.delete(f"/traces/{trace_id}").status_code == 200
    assert client.get(f"/traces/{trace_id}").status_code == 404


def test_deleting_a_trace_is_audited(client):
    trace_id = _call(client)["trace_id"]
    client.delete(f"/traces/{trace_id}")
    events = client.get("/audit?limit=100").json()["events"]
    assert any(e["event_type"] == "trace.deleted"
               and e["details"]["trace_id"] == trace_id for e in events)


def test_an_unknown_trace_is_a_404(client):
    assert client.get("/traces/nope").status_code == 404
    assert client.delete("/traces/nope").status_code == 404


# ── Off is off, and says so ──────────────────────────────────────────────────

def test_without_a_state_dir_tracing_is_off_and_admits_it(app_module):
    """TraceStore's default path would write into whatever directory the server
    was started from, so the honest default is off — stated plainly rather than
    returning an empty list that reads as "no calls have been made"."""
    c = TestClient(main.app)
    body = c.get("/traces").json()
    assert body["enabled"] is False
    assert body["traces"] == []
    assert "AGT_STATE_DIR" in body["note"]
    assert c.get("/traces/diff?a=x&b=y").status_code == 409


def test_a_call_still_succeeds_with_tracing_off(app_module):
    """Tracing is observability. A trace that could fail a governed call would
    be a liability, not a feature."""
    c = TestClient(main.app)
    body = c.post("/tools/call", json={"tool_name": "db_query",
                                       "agent_id": "research-agent"}).json()
    assert body["allowed"] is True
    assert body["trace_id"] is None


def test_the_runtime_controls_report_tracing_honestly(client, app_module):
    assert main._runtime_controls()["call_tracing"] is True
    main.teardown_state()
    import os
    os.environ.pop("AGT_STATE_DIR", None)
    main.reset_state()
    assert main._runtime_controls()["call_tracing"] is False


# ── Reachable from the UI ────────────────────────────────────────────────────

def test_the_trace_endpoints_are_bound_in_the_frontend(frontend_src):
    """The recurring failure in this codebase has been a capability that is
    built, tested and documented but that no button reaches. A trace nobody can
    open is a file on disk, not a feature."""
    api_js = (frontend_src / "api.js").read_text(encoding="utf-8")
    for call in ("/traces?limit=", "/traces/diff?a=", "traces:"):
        assert call in api_js, call

    panel = (frontend_src / "panels" / "AuditPanel.js").read_text(encoding="utf-8")
    for binding in ("api.traces.list", "api.traces.get",
                    "api.traces.diff", "api.traces.remove"):
        assert binding in panel, binding


def test_the_panel_does_not_promise_a_gate_the_trace_cannot_show(frontend_src):
    """Ring, policy and the MCP proxy share one span. A panel offering them as
    separate rows would be advertising precision the timing cannot support."""
    panel = (frontend_src / "panels" / "AuditPanel.js").read_text(encoding="utf-8")
    for absent in ("gate:ring", "gate:policy", "gate:mcp_proxy"):
        assert absent not in panel, absent
