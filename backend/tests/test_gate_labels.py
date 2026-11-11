"""The gate strip in the UI has to know every gate the backend can deny at.

This is not a cosmetic concern. ToolPanel decides which gates to grey out by
looking up ``denied_by`` in its own ordered list, and treats a name it does not
recognise as coming *last* — so a denial at an unknown gate renders every gate
before it as passed. A call refused by the parameter scan showed four green
ticks and no failure mark.

It was true of ``identity`` before any of the new controls existed, which is
what makes it worth a test rather than a careful edit: the list drifts silently,
and nothing about the drift is visible until someone reads a denial and believes
the wrong thing.

So the frontend's table is parsed out of the source and checked against the
gates this backend actually reports, in both directions — a gate the UI cannot
label, and a label for a gate that no longer exists, are both failures.
"""

import re

import pytest
from starlette.testclient import TestClient

import main

# Every value the backend passes as `_deny(..., gate, ...)`, plus the ones it
# lists in `passed_gates`. Written out rather than scraped so that adding a gate
# to main.py without adding it here is itself a failing test.
BACKEND_GATES = {
    "signature",        # AGT MCPMessageSigner — replay protection
    "lifecycle",        # AGT LifecycleManager
    "identity",         # attestation and MCP caller sessions
    "tenant",           # per-tenant policy isolation
    "trust",            # AGT TrustPolicy
    "ring",             # AGT RingEnforcer
    "policy",           # AGT PolicyEngine
    "session",          # AGT Hypervisor session binding
    "mcp_parameters",   # AGT MCPGateway, outbound parameters
    "mcp_proxy",        # AGT TrustProxy
    "mcp_budget",       # AGT MCPSlidingRateLimiter
}

ORDER_RE = re.compile(r"const GATE_ORDER\s*=\s*\[(.*?)\];", re.S)
LABEL_RE = re.compile(r"const GATE_LABEL\s*=\s*\{(.*?)\n\};", re.S)
NAME_RE = re.compile(r"'([a-z_]+)'")
KEY_RE = re.compile(r"^\s*([a-z_]+):", re.M)


@pytest.fixture
def panel(frontend_src):
    return (frontend_src / "panels" / "ToolPanel.js").read_text(encoding="utf-8")


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def test_the_ui_knows_the_order_of_every_gate(panel):
    """A gate missing here is not merely unlabelled — it makes the strip wrong."""
    block = ORDER_RE.search(panel)
    assert block, "GATE_ORDER not found in ToolPanel.js"
    ordered = NAME_RE.findall(block.group(1))

    missing = BACKEND_GATES - set(ordered) - {"session", "tenant"}
    assert not missing, (
        f"ToolPanel's GATE_ORDER does not know {sorted(missing)}. A denial at "
        f"one of those renders every earlier gate as passed.")


def test_every_ordered_gate_has_a_label(panel):
    order_block = ORDER_RE.search(panel)
    label_block = LABEL_RE.search(panel)
    assert order_block and label_block

    ordered = set(NAME_RE.findall(order_block.group(1)))
    labelled = set(KEY_RE.findall(label_block.group(1)))
    assert ordered == labelled, (
        f"GATE_ORDER and GATE_LABEL disagree: "
        f"{sorted(ordered ^ labelled)}")


def test_the_ui_does_not_label_a_gate_the_backend_never_reports(panel):
    """The other direction. A label for a gate that cannot fire is a row in the
    strip that is always green, which reads as assurance and is not."""
    block = LABEL_RE.search(panel)
    labelled = set(KEY_RE.findall(block.group(1)))
    unknown = labelled - BACKEND_GATES
    assert not unknown, f"ToolPanel labels gates the backend never reports: {sorted(unknown)}"


# ── what the backend actually returns ────────────────────────────────────────

def test_an_allowed_mcp_call_reports_every_gate_it_passed(client, mcp_server):
    from test_mcp_connector import _import
    _import(client, mcp_server[1], tools=["echo"])
    res = client.post("/tools/call", json={
        "tool_name": "mcp.demo-notes.echo", "agent_id": "research-agent",
        "kwargs": {"arguments": {"text": "hi"}}}).json()

    assert res["allowed"] is True
    assert res["passed_gates"] == [
        "lifecycle", "trust", "ring", "policy",
        "mcp_parameters", "mcp_proxy", "mcp_budget"]


def test_a_webhook_call_claims_none_of_the_mcp_gates(client):
    res = client.post("/tools/call", json={"tool_name": "db_query",
                                           "agent_id": "research-agent"}).json()
    assert res["passed_gates"] == ["lifecycle", "trust", "ring", "policy"]


def test_a_signed_call_reports_the_signature_gate(client):
    import mcp_caller_auth as auth
    body = {"tool_name": "db_query", "agent_id": "research-agent"}
    payload = auth.canonical_payload(body)
    headers = dict(main._call_signer.sign(payload, "research-agent"))
    headers["Content-Type"] = "application/json"
    res = client.post("/tools/call", content=payload.encode(),
                      headers=headers).json()
    assert res["passed_gates"][0] == "signature"


def test_every_reported_gate_is_one_the_ui_can_label(client, panel, mcp_server):
    """End to end: run a real MCP call and check the labels cover what came
    back, rather than trusting the two tables above to stay in step."""
    from test_mcp_connector import _import
    _import(client, mcp_server[1], tools=["echo"])
    res = client.post("/tools/call", json={
        "tool_name": "mcp.demo-notes.echo", "agent_id": "research-agent",
        "kwargs": {"arguments": {"text": "hi"}}}).json()

    labelled = set(KEY_RE.findall(LABEL_RE.search(panel).group(1)))
    assert set(res["passed_gates"]) <= labelled


@pytest.fixture
def mcp_server(monkeypatch):
    from test_mcp_connector import _start_server, _stop_server
    monkeypatch.setenv("AGT_TOOL_ALLOW_PRIVATE", "1")
    server, url = _start_server()
    try:
        yield server, url
    finally:
        _stop_server(server)
