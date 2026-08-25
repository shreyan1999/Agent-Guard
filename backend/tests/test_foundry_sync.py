"""UI onboarding for a Microsoft Foundry agent.

A user registers a governance twin with the Foundry link (project endpoint +
agent id), then pastes the run steps exported from Foundry. The sync endpoint
maps the tool-call steps through the same connector the SDK uses, feeding this
agent's real agent_sre SLOs and one source-tagged audit note. The backend never
calls the Foundry SDK — it only consumes the RunStep dicts it is handed.
"""


def _register(client, agent_id="foundry-twin", **extra):
    body = {"id": agent_id, "name": agent_id}
    body.update(extra)
    return client.post("/agents", json=body).json()


def _run_steps():
    """Two run steps in the documented RunStep schema: a completed function
    tool call and a failed one, plus a message_creation step that must be
    ignored."""
    return [
        {"type": "message_creation", "status": "completed",
         "step_details": {"message_creation": {"message_id": "msg_1"}}},
        {"type": "tool_calls", "status": "completed",
         "created_at": 1000, "completed_at": 1002,
         "step_details": {"tool_calls": [
             {"type": "function", "function": {"name": "web_search"}}]}},
        {"type": "tool_calls", "status": "failed",
         "created_at": 2000, "failed_at": 2005,
         "last_error": {"code": "server_error", "message": "tool crashed"},
         "step_details": {"tool_calls": [
             {"type": "function", "function": {"name": "write_file"}}]}},
    ]


def test_registration_records_the_foundry_link(client):
    view = _register(client, project_endpoint="https://x.services.ai.azure.com/api/projects/p",
                     foundry_agent_id="asst_abc123")
    assert view["foundry"] == {
        "project_endpoint": "https://x.services.ai.azure.com/api/projects/p",
        "foundry_agent_id": "asst_abc123",
    }
    # And it is surfaced on the list view the panel renders.
    listed = {a["id"]: a for a in client.get("/agents").json()}
    assert listed["foundry-twin"]["foundry"]["foundry_agent_id"] == "asst_abc123"


def test_plain_registration_has_no_foundry_link(client):
    view = _register(client, agent_id="plain")
    assert view["foundry"] is None


def test_sync_feeds_the_real_slo_and_counts_failures(client):
    _register(client)
    res = client.post("/agents/foundry-twin/foundry/sync",
                      json={"run_steps": _run_steps()})
    assert res.status_code == 200
    body = res.json()
    # Only the two tool_calls steps map to events; the message step is skipped.
    assert body["accepted"] == 2
    assert body["denied_reported"] == 1
    slo = {s["agent_id"]: s for s in client.get("/sre/slos").json()}
    assert "foundry-twin" in slo


def test_sync_writes_one_source_tagged_audit_note(client):
    _register(client)
    client.post("/agents/foundry-twin/foundry/sync", json={"run_steps": _run_steps()})
    events = client.get("/audit").json()["events"]
    notes = [e for e in events if e["event_type"] == "foundry.telemetry"]
    assert len(notes) == 1
    assert notes[0]["details"]["source"] == "foundry-runsteps"
    assert notes[0]["details"]["events"] == 2
    # The chain still verifies after the note is appended.
    assert client.get("/audit/verify").json()["valid"] is True


def test_sync_with_no_tool_calls_is_accepted_empty(client):
    _register(client)
    res = client.post("/agents/foundry-twin/foundry/sync", json={"run_steps": [
        {"type": "message_creation", "status": "completed",
         "step_details": {"message_creation": {"message_id": "m"}}},
    ]})
    assert res.status_code == 200
    assert res.json()["accepted"] == 0


def test_sync_rejects_unknown_agent(client):
    res = client.post("/agents/ghost/foundry/sync", json={"run_steps": _run_steps()})
    assert res.status_code == 404


def test_sync_rejects_empty_run_steps(client):
    _register(client)
    res = client.post("/agents/foundry-twin/foundry/sync", json={"run_steps": []})
    assert res.status_code == 400


def test_sync_rejects_oversized_batch(client):
    _register(client)
    step = {"type": "tool_calls", "status": "completed", "created_at": 1, "completed_at": 2,
            "step_details": {"tool_calls": [{"type": "function", "function": {"name": "t"}}]}}
    res = client.post("/agents/foundry-twin/foundry/sync",
                      json={"run_steps": [step] * 1001})
    assert res.status_code == 413


def test_foundry_link_survives_a_restart(monkeypatch, tmp_path):
    # A durable deployment persists the Foundry link alongside the twin. Mirror
    # test_persistence: point AGT_STATE_DIR at a temp dir and reload the stores.
    import main
    from starlette.testclient import TestClient
    monkeypatch.setenv("AGT_STATE_DIR", str(tmp_path))
    main.reset_state()
    try:
        TestClient(main.app).post("/agents", json={
            "id": "durable-foundry", "name": "durable-foundry",
            "foundry_agent_id": "asst_keep", "project_endpoint": "https://e/p",
        })
        main.reset_state()  # restart: stores reload from disk
        listed = {a["id"]: a for a in TestClient(main.app).get("/agents").json()}
        assert listed["durable-foundry"]["foundry"]["foundry_agent_id"] == "asst_keep"
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        main.reset_state()  # back to in-memory for later tests
