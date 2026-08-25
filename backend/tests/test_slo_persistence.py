"""Durable SLOs: with AGT_STATE_DIR set, an agent's real agent_sre
measurements survive a process restart.

Without a state directory the SLO stores are in-memory (the ephemeral
playground default) and reset with the process. Point AGT_STATE_DIR at a temp
directory and each agent's measurements are written to its own
SQLiteMeasurementStore — agent_sre's own durable backend — so the recorded
SLIs, their computed compliance and the reconstructed error budget come back
after a restart. A "restart" is simulated with main.reset_state(), the same
code path a fresh process runs.
"""

import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def state_dir(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="agt-slo-"))
    monkeypatch.setenv("AGT_STATE_DIR", str(d))
    main.reset_state()
    try:
        yield d
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        main.reset_state()  # back to in-memory for later tests


@pytest.fixture
def client(state_dir):
    return TestClient(main.app)


def _slo_for(rows, agent_id):
    return next(s for s in rows if s["agent_id"] == agent_id)


def _task_count(slo_view):
    task = next(i for i in slo_view["indicators"] if "task" in i["name"].lower())
    return task["measurement_count"]


def test_default_mode_is_in_memory(app_module):
    """With AGT_STATE_DIR unset the SLO store is not durable."""
    assert main._slo.durable is False


def test_state_dir_makes_slos_durable(client, state_dir):
    assert main._slo.durable is True


def test_measurements_survive_a_restart(client, state_dir):
    client.post("/agents", json={
        "id": "runner", "name": "runner", "trust_score": 0.9,
        "owner": "ops@acme", "purpose": "slo durability",
    })
    for _ in range(3):
        r = client.post("/tools/call", json={
            "tool_name": "db_query", "action": "read", "agent_id": "runner",
        }).json()
        assert r["allowed"] is True

    before = _task_count(_slo_for(client.get("/sre/slos").json(), "runner"))
    assert before == 3

    # A per-agent SQLite database was written under the state directory.
    assert (state_dir / "slo").exists()
    assert list((state_dir / "slo").glob("slo_*.db"))

    main.reset_state()  # restart: stores reload from AGT_STATE_DIR

    after = _task_count(_slo_for(TestClient(main.app).get("/sre/slos").json(), "runner"))
    assert after == before, "durable SLO measurements must survive a restart"


def test_error_budget_burn_is_reconstructed(client, state_dir):
    client.post("/agents", json={
        "id": "burner", "name": "burner", "trust_score": 0.1,
        "owner": "ops@acme", "purpose": "error budget",
    })
    # A trust score below the minimum is a genuine denial at the trust gate,
    # which records a failed task measurement and burns one unit of budget.
    denied = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "burner",
    }).json()
    assert denied["allowed"] is False

    before = _slo_for(client.get("/sre/slos").json(), "burner")["error_budget"]
    assert before["consumed"] >= 1.0
    main.reset_state()
    after = _slo_for(TestClient(main.app).get("/sre/slos").json(), "burner")["error_budget"]

    # The burned budget (events consumed) is replayed from the durable
    # task-success measurements, so it is not silently reset to full.
    assert after["consumed"] == before["consumed"]
