"""Bridge Microsoft Foundry agent telemetry into the governance platform.

Foundry (Azure AI Agents) records each thread run as a sequence of *run steps*.
A step of type ``tool_calls`` lists the tools the agent invoked, with a status
and timestamps. This module maps those steps into the platform's execution-event
shape and streams them through the client SDK's ``/ingest/events`` pipeline, so a
Foundry-hosted agent's tool use feeds the same ``agent_sre`` SLOs and audit trail
as any other agent.

The connector never calls the Foundry SDK itself — that keeps it dependency-free
and testable. The caller fetches the run steps (for example with
``project.agents.run_steps.list(thread_id=..., run_id=...)`` and ``.as_dict()``)
and hands the connector plain dicts in the documented ``RunStep`` schema.
"""
from __future__ import annotations

from typing import Iterable, Optional

from agt_client import GovernanceClient

# The ingestion endpoint caps a batch; a long run is chunked to stay under it.
_MAX_BATCH = 1000


def _tool_name(tool_call: dict) -> str:
    """The invoked tool's name: the function name, else the tool-call type."""
    if tool_call.get("type") == "function":
        function = tool_call.get("function") or {}
        return function.get("name") or "function"
    return tool_call.get("type") or "tool"


def _latency_ms(step: dict) -> float:
    """Wall-clock milliseconds of a run step from its Unix-second timestamps."""
    start = step.get("created_at")
    end = step.get("completed_at") or step.get("failed_at") or step.get("cancelled_at")
    if not start or not end:
        return 0.0
    return max(0.0, (float(end) - float(start)) * 1000.0)


def run_steps_to_events(steps: Iterable[dict]) -> list[dict]:
    """Map Foundry ``RunStep`` dicts to platform ingestion events.

    Only ``tool_calls`` steps become events — ``message_creation`` steps are the
    model writing a reply, not a governed tool invocation. A step's ``completed``
    status marks the call allowed; a ``failed`` status carries the error message.
    ``policy_denied`` is always false: Foundry reports what ran, and only this
    platform's own gates produce a policy denial.
    """
    events: list[dict] = []
    for step in steps:
        if step.get("type") != "tool_calls":
            continue
        status = step.get("status")
        allowed = status == "completed"
        last_error = step.get("last_error")
        error = None
        if status == "failed" and isinstance(last_error, dict):
            error = last_error.get("message")
        latency = _latency_ms(step)
        details = step.get("step_details") or {}
        for tool_call in details.get("tool_calls") or []:
            events.append({
                "tool": _tool_name(tool_call),
                "action": "invoke",
                "allowed": allowed,
                "policy_denied": False,
                "latency_ms": latency,
                "error": error,
            })
    return events


class FoundryConnector:
    """Streams a Foundry agent's run-step telemetry into the platform."""

    def __init__(self, client: GovernanceClient) -> None:
        self._client = client

    def sync_run(self, run_steps: Iterable[dict]) -> dict:
        """Ingest one run's steps, chunked under the endpoint's batch limit."""
        events = run_steps_to_events(run_steps)
        if not events:
            return {"accepted": 0, "denied_reported": 0}
        accepted = 0
        denied = 0
        for start in range(0, len(events), _MAX_BATCH):
            result = self._client.report(events[start:start + _MAX_BATCH])
            accepted += result.get("accepted", 0)
            denied += result.get("denied_reported", 0)
        return {"accepted": accepted, "denied_reported": denied}
