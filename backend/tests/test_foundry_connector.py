"""Mapping Microsoft Foundry run-step telemetry into the governance platform.

The fixtures mirror the documented Azure AI Agents ``RunStep`` schema
(``type``, ``status``, ``step_details.tool_calls``, ``function.name``,
``created_at``/``completed_at``/``failed_at``, ``last_error``). The connector
maps them to ingestion events and streams them via the client SDK.
"""
import pytest
from starlette.testclient import TestClient

import agt_client
from foundry_connector import FoundryConnector, run_steps_to_events


def _run_steps():
    return [
        {  # the model composing a reply — not a tool invocation
            "type": "message_creation", "status": "completed",
            "created_at": 100, "completed_at": 101,
            "step_details": {"type": "message_creation"},
        },
        {  # a successful function tool call
            "type": "tool_calls", "status": "completed",
            "created_at": 200, "completed_at": 202, "last_error": None,
            "step_details": {"type": "tool_calls", "tool_calls": [
                {"id": "tc1", "type": "function",
                 "function": {"name": "web_search", "arguments": "{}", "output": "ok"}},
            ]},
        },
        {  # a failed tool step, carrying the error
            "type": "tool_calls", "status": "failed",
            "created_at": 300, "failed_at": 305,
            "last_error": {"code": "server_error", "message": "tool crashed"},
            "step_details": {"type": "tool_calls", "tool_calls": [
                {"id": "tc2", "type": "code_interpreter", "code_interpreter": {}},
            ]},
        },
    ]


def test_maps_only_tool_call_steps():
    events = run_steps_to_events(_run_steps())
    assert len(events) == 2  # the message_creation step is skipped


def test_function_tool_name_is_extracted():
    events = run_steps_to_events(_run_steps())
    assert events[0]["tool"] == "web_search"


def test_non_function_tool_uses_its_type():
    events = run_steps_to_events(_run_steps())
    assert events[1]["tool"] == "code_interpreter"


def test_failed_step_is_denied_with_error():
    events = run_steps_to_events(_run_steps())
    failed = events[1]
    assert failed["allowed"] is False
    assert failed["error"] == "tool crashed"


def test_latency_is_derived_from_timestamps():
    events = run_steps_to_events(_run_steps())
    assert events[0]["latency_ms"] == 2000.0   # 202 - 200 seconds
    assert events[1]["latency_ms"] == 5000.0   # 305 - 300 seconds


def test_missing_timestamps_yield_zero_latency():
    events = run_steps_to_events([{
        "type": "tool_calls", "status": "completed",
        "step_details": {"type": "tool_calls", "tool_calls": [
            {"id": "x", "type": "function", "function": {"name": "f"}},
        ]},
    }])
    assert events[0]["latency_ms"] == 0.0


@pytest.fixture
def connector(app_module):
    client = agt_client.GovernanceClient(session=TestClient(app_module.app))
    client.register("foundry-agent", owner="foundry@corp")
    return FoundryConnector(client), client


def test_sync_run_feeds_the_platform(connector):
    conn, client = connector
    result = conn.sync_run(_run_steps())
    assert result["accepted"] == 2
    assert result["denied_reported"] == 1
    slo = {s["agent_id"]: s for s in client._session.get("/sre/slos").json()}
    assert "foundry-agent" in slo


def test_empty_run_makes_no_request(connector):
    conn, _ = connector
    # A run with no tool_calls steps must not POST an empty (rejected) batch.
    result = conn.sync_run([{"type": "message_creation", "status": "completed"}])
    assert result == {"accepted": 0, "denied_reported": 0}
