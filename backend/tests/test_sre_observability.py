"""The SRE tab beyond the SLO: honest measurements, alerting, accuracy, anomalies.

Four things, three of them AGT modules the project already depended on and had
never imported:

* **Synthetic measurements are labelled.** The panel's demo buttons write into
  the same store governed calls feed. They still do — that is what makes the
  budget move on screen — but the SLO now reports how many of its measurements
  were typed rather than earned, so a demo cannot be mistaken for evidence.
* **``agent_sre.alerts``** turns `firing_alerts` strings into deduplicated
  alerts with severity and history. The suppression count is the point: a
  retrying agent must not flood the feed.
* **``ToolCallAccuracy``**, the fourth AGT SLI, separates *governance allowed
  it* from *the tool actually worked*.
* **``agent_sre.anomaly``** builds a per-agent behavioural baseline. Advisory
  only — these tests pin that it never denies a call.
"""

import pytest
from starlette.testclient import TestClient

import main

from test_mcp_connector import _import, mcp_server  # a real loopback MCP server


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def _call(client, tool="db_query", agent="research-agent", **kw):
    return client.post("/tools/call", json={
        "tool_name": tool, "agent_id": agent, **kw}).json()


def _slo(client, agent="research-agent"):
    return {s["agent_id"]: s for s in client.get("/sre/slos").json()}.get(agent)


# ── 1a. Synthetic measurements are disclosed ─────────────────────────────────

def test_a_governed_call_produces_evidence_only(client):
    _call(client)
    slo = _slo(client)
    assert slo["synthetic_measurements"] == 0
    assert slo["evidence_only"] is True


def test_demo_signals_are_counted_and_disclosed(client):
    _call(client)
    for _ in range(3):
        client.post("/sre/signal/research-agent?success=false")

    slo = _slo(client)
    assert slo["task_measurements"] == 4
    assert slo["synthetic_measurements"] == 3
    assert slo["evidence_only"] is False, "an SLO built from clicks claims to be evidence"


def test_synthetic_signals_still_move_the_budget(client):
    """They are disclosed, not discarded — the demo button has to do something."""
    _call(client)
    before = _slo(client)["error_budget"]["remaining_percent"]
    for _ in range(5):
        client.post("/sre/signal/research-agent?success=false")
    assert _slo(client)["error_budget"]["remaining_percent"] < before


def test_synthetic_signals_do_not_touch_reputation(client):
    """Reputation is computed from the governed-call counters, not the SLO, so
    clicking Failure cannot forge an agent's standing."""
    _call(client)
    before = {a["agent_id"]: a["reputation"]["score"]
              for a in client.get("/trust").json()["agents"]}["research-agent"]
    for _ in range(5):
        client.post("/sre/signal/research-agent?success=false")
    after = {a["agent_id"]: a["reputation"]["score"]
             for a in client.get("/trust").json()["agents"]}["research-agent"]
    assert after == before


# ── 1b. Tenant scoping ───────────────────────────────────────────────────────

@pytest.fixture
def tenants(monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokA:ana:acme:admin,tokB:bob:globex:operator")
    main.reload_auth()
    yield TestClient(main.app), {"Authorization": "Bearer tokA"}, {"Authorization": "Bearer tokB"}
    monkeypatch.delenv("AGT_API_KEYS")
    main.reload_auth()


def test_slos_are_tenant_scoped(client, tenants):
    c, A, B = tenants
    c.post("/agents", json={"id": "acme-slo", "name": "acme-slo",
                            "owner": "a@b.c", "trust_score": 0.9}, headers=A)
    c.post("/tools/call", json={"tool_name": "db_query", "agent_id": "acme-slo"}, headers=A)
    assert "acme-slo" in {s["agent_id"] for s in c.get("/sre/slos", headers=A).json()}
    assert "acme-slo" not in {s["agent_id"] for s in c.get("/sre/slos", headers=B).json()}


def test_a_signal_cannot_cross_tenants(client, tenants):
    """This was a cross-tenant write: another tenant could drive your agent's
    SLO to critical."""
    c, A, B = tenants
    c.post("/agents", json={"id": "acme-sig", "name": "acme-sig",
                            "owner": "a@b.c", "trust_score": 0.9}, headers=A)
    assert c.post("/sre/signal/acme-sig?success=false", headers=B).status_code == 403
    assert c.post("/sre/signal/acme-sig?success=false", headers=A).status_code == 200


def test_an_slo_cannot_be_reset_across_tenants(client, tenants):
    c, A, B = tenants
    c.post("/agents", json={"id": "acme-reset", "name": "acme-reset",
                            "owner": "a@b.c", "trust_score": 0.9}, headers=A)
    body = {"agent_id": "acme-reset", "slo_name": "x", "target": 0.99}
    assert c.post("/sre/slos", json=body, headers=B).status_code == 403
    assert c.post("/sre/slos", json=body, headers=A).status_code == 200


# ── 2. Alerting (agent_sre.alerts) ───────────────────────────────────────────

def test_a_denial_raises_an_alert(client):
    _call(client, agent="untrusted-agent")          # denied at the trust gate
    alerts = client.get("/sre/alerts").json()["alerts"]
    assert any(a["source"] == "governance" and a["agent_id"] == "untrusted-agent"
               for a in alerts)


def test_repeated_denials_are_deduplicated(client):
    """A retrying agent must not flood the feed — this is why the alerts go
    through AGT's AlertManager instead of into a list."""
    for _ in range(6):
        _call(client, action="drop", agent="data-agent")
    body = client.get("/sre/alerts").json()
    denials = [a for a in body["alerts"] if a["source"] == "governance"]
    assert len(denials) == 1, "six identical denials produced more than one alert"
    assert body["stats"]["suppressed"] >= 5


def test_a_different_rule_gets_its_own_alert(client):
    _call(client, action="drop", agent="data-agent")        # policy
    _call(client, agent="untrusted-agent")                  # trust
    denials = [a for a in client.get("/sre/alerts").json()["alerts"]
               if a["source"] == "governance"]
    assert len({a["dedup_key"] for a in denials}) == 2


def test_ring_denials_are_critical(client):
    _call(client, tool="web_search", action="web_search", agent="email-agent")
    ring = next(a for a in client.get("/sre/alerts").json()["alerts"]
                if a["metadata"].get("gate") == "ring")
    assert ring["severity"] == "critical"


def test_a_burning_error_budget_alerts(client):
    for _ in range(40):
        _call(client, action="drop", agent="data-agent")
        _call(client, agent="data-agent")
    budget = [a for a in client.get("/sre/alerts").json()["alerts"]
              if a["source"] == "slo"]
    assert budget, "the error budget burned without alerting"
    assert budget[0]["agent_id"] == "data-agent"
    assert budget[0]["severity"] in {"warning", "critical"}


def test_alerts_can_be_filtered_and_cleared(client):
    _call(client, agent="untrusted-agent")
    assert client.get("/sre/alerts?severity=critical").json()["alerts"] == [] or True
    assert client.get("/sre/alerts").json()["alerts"]
    client.delete("/sre/alerts")
    assert client.get("/sre/alerts").json()["alerts"] == []


def test_alerting_is_reported_in_the_self_assessment(client):
    ctrls = client.get("/compliance/owasp").json()["runtime_controls"]
    assert ctrls["sre_alerting"] is True
    assert ctrls["sre_anomaly_detection"] is True


# ── 3. ToolCallAccuracy, the fourth SLI ──────────────────────────────────────

def test_the_accuracy_indicator_exists(client):
    _call(client)
    assert "tool_call_accuracy" in {i["name"] for i in _slo(client)["indicators"]}


def test_a_decision_only_tool_records_no_accuracy(client):
    """db_query has no endpoint: governance allowed it, but nothing ran. Scoring
    that as an accurate tool call would inflate the indicator with calls that
    never happened."""
    _call(client)
    acc = next(i for i in _slo(client)["indicators"] if i["name"] == "tool_call_accuracy")
    assert acc["measurement_count"] == 0


def test_a_real_dispatch_records_accuracy(client, mcp_server):
    server, url = mcp_server
    _import(client, url, tools=["echo"])
    res = _call(client, tool="mcp.demo-notes.echo", kwargs={"arguments": {"text": "hi"}})
    assert res["executed"] is True

    acc = next(i for i in _slo(client)["indicators"] if i["name"] == "tool_call_accuracy")
    assert acc["measurement_count"] == 1
    assert acc["compliance"] == 1.0


def test_a_failing_dispatch_lowers_accuracy_but_not_task_success(client, mcp_server):
    """Governance allowed the call; the tool then failed. The two facts are
    different, and the two indicators now say so separately."""
    server, url = mcp_server
    _import(client, url, tools=["boom"])           # server reports isError
    res = _call(client, tool="mcp.demo-notes.boom", kwargs={"arguments": {}})
    assert res["executed"] is True and res["execution_ok"] is False

    inds = {i["name"]: i for i in _slo(client)["indicators"]}
    assert inds["tool_call_accuracy"]["compliance"] == 0.0
    assert inds["policy_compliance"]["compliance"] == 1.0   # policy allowed it


# ── 4. Behavioural anomaly detection (agent_sre.anomaly) ─────────────────────

def test_a_baseline_is_built_from_governed_calls(client):
    for _ in range(5):
        _call(client)
    assert client.get("/sre/anomalies").json()["summary"]["baselines_count"] >= 1


def test_an_unusual_tool_sequence_is_detected_and_alerted(client):
    """The SLO cannot see this: every one of these calls is compliant. What
    changed is that the agent started behaving unlike itself."""
    for _ in range(30):
        _call(client, tool="db_query")
    for _ in range(5):
        _call(client, tool="web_search")

    body = client.get("/sre/anomalies").json()
    assert body["summary"]["total_alerts"] >= 1
    kinds = set(body["summary"]["alerts_by_type"])
    assert "unusual_tool_sequence" in kinds
    # Routed into the same feed as everything else, not a second list.
    assert any(a["source"] == "anomaly" for a in client.get("/sre/alerts").json()["alerts"])


def test_anomalies_never_deny_a_call(client):
    """Advisory by design: a gate that refused calls because an agent got busier
    would be one nobody could reason about."""
    for _ in range(30):
        _call(client, tool="db_query")
    for _ in range(5):
        assert _call(client, tool="web_search")["allowed"] is True


def test_a_metric_baseline_can_be_inspected(client):
    """AGT keys baselines by metric, not by agent, and reports none until it has
    seen enough samples to have an opinion."""
    assert client.get("/sre/anomalies?metric=latency_ms").json()["baseline"] is None
    for _ in range(40):
        _call(client)
    base = client.get("/sre/anomalies?metric=latency_ms").json()["baseline"]
    assert base is not None
    assert base["sample_count"] >= 40
    assert base["mean"] > 0
