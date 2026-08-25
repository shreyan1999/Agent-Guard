"""Out-of-band telemetry ingestion.

A registered agent streams execution events to /ingest/events; the platform
feeds them into the real agent_sre SLOs, updates call/denial counters, and
records a single summarised, source-tagged audit note per batch. Ingested
events are self-reported telemetry, never an authoritative allow/deny verdict.
"""


def _register(client, agent_id="ingest-agent"):
    return client.post("/agents", json={"id": agent_id, "name": agent_id}).json()


def test_ingest_feeds_the_real_slo(client):
    _register(client)
    res = client.post("/ingest/events", json={
        "agent_id": "ingest-agent",
        "events": [
            {"tool": "search", "allowed": True, "latency_ms": 40},
            {"tool": "search", "allowed": True, "latency_ms": 60},
        ],
    })
    assert res.status_code == 200
    body = res.json()
    assert body["accepted"] == 2
    assert body["denied_reported"] == 0
    # The SLO is the real agent_sre one and now carries measurements.
    slo = {s["agent_id"]: s for s in client.get("/sre/slos").json()}
    assert "ingest-agent" in slo


def test_ingest_counts_reported_denials(client):
    _register(client)
    client.post("/ingest/events", json={
        "agent_id": "ingest-agent",
        "events": [
            {"tool": "delete", "allowed": False, "policy_denied": True, "latency_ms": 5},
            {"tool": "read", "allowed": True, "latency_ms": 5},
        ],
    })
    agent = {a["id"]: a for a in client.get("/agents").json()}["ingest-agent"]
    assert agent["calls"] == 2
    assert agent["denials"] == 1


def test_ingest_writes_one_summary_audit_note(client):
    _register(client)
    client.post("/ingest/events", json={
        "agent_id": "ingest-agent",
        "events": [{"tool": "search", "allowed": True, "latency_ms": 10}],
    })
    events = client.get("/audit").json()["events"]
    telemetry = [e for e in events if e["event_type"] == "ingest.telemetry"]
    assert len(telemetry) == 1
    assert telemetry[0]["details"]["source"] == "agent-reported"
    # Verifiability is preserved after ingestion.
    assert client.get("/audit/verify").json()["valid"] is True


def test_ingest_rejects_an_unregistered_agent(client):
    res = client.post("/ingest/events", json={
        "agent_id": "ghost",
        "events": [{"tool": "search"}],
    })
    assert res.status_code == 404


def test_ingest_rejects_an_empty_batch(client):
    _register(client)
    res = client.post("/ingest/events", json={"agent_id": "ingest-agent", "events": []})
    assert res.status_code == 400


def test_ingest_rejects_an_oversized_batch(client):
    _register(client)
    events = [{"tool": "search", "allowed": True} for _ in range(1001)]
    res = client.post("/ingest/events", json={"agent_id": "ingest-agent", "events": events})
    assert res.status_code == 413
