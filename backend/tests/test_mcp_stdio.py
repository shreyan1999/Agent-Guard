"""Local (stdio) MCP servers: the transport where the server is a child process.

The distinguishing fact about stdio is that connecting *runs something*. These
tests are therefore less about JSON-RPC framing — that belongs to the Agent
Governance Toolkit's client, which this platform calls rather than reimplements
— and more about the two things that are this platform's to get right:

  * a local server reaches the governed registry by exactly the same route a
    remote one does, so the gates, the receipts and the rug-pull check all still
    apply to it; and
  * the toolkit's launch controls are genuinely in force, not merely cited.

`demo_mcp_stdio.py` is the server under test. It is launched with `python`,
which is on AGT's command allowlist, and it is deliberately the local twin of
`demo_mcp_server.py` so the grades either transport produces can be compared.
"""

import os
import sys

import pytest

import mcp_connector
from tool_registry import ToolError

SERVER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "demo_mcp_stdio.py")
# Starting an interpreter is not instant, and CI is slower than a laptop.
TIMEOUT_MS = 30_000


def launch(**overrides):
    body = {
        "transport": "stdio",
        "command": sys.executable,
        "args": [SERVER],
        "timeout_ms": TIMEOUT_MS,
        "call_timeout_ms": TIMEOUT_MS,
        "server_name": "local-notes",
    }
    body.update(overrides)
    return body


pytestmark = pytest.mark.skipif(
    not mcp_connector.STDIO_AVAILABLE,
    reason=f"AGT stdio client unavailable: {mcp_connector.STDIO_UNAVAILABLE_REASON}",
)


# -- the transport itself -----------------------------------------------------

def test_the_toolkit_ships_the_stdio_client_this_platform_uses():
    """The spawn is AGT's, and the project should fail loudly if that changes.

    A fallback to a hand-rolled subprocess launch would silently drop the
    command allowlist and the environment-hijack defences, so there is none.
    """
    assert mcp_connector.STDIO_AVAILABLE
    assert mcp_connector.STDIO_UNAVAILABLE_REASON == ""


def test_discovery_launches_a_local_server_and_reads_its_catalogue():
    d = mcp_connector.discover(**{k: v for k, v in launch().items()
                                  if k in ("transport", "command", "args", "timeout_ms")})
    assert d["transport"] == "stdio"
    assert d["server_url"] is None
    assert d["server_info"]["name"] == "demo-notes-local"
    assert {t["name"] for t in d["tools"]} == {
        "echo", "lookup_order", "purge_bucket", "search_notes"}


def test_the_launch_line_is_reported_without_any_environment_value():
    d = mcp_connector.discover(transport="stdio", command=sys.executable,
                               args=[SERVER], timeout_ms=TIMEOUT_MS)
    launch_spec = d["launch"]
    assert launch_spec["command"] == sys.executable
    assert launch_spec["args"] == [SERVER]
    # Names only, never values — the same rule that keeps a bearer token out.
    assert launch_spec["env_passthrough"] == []


def test_auto_never_resolves_to_launching_a_process():
    """Falling back to executing something is not a fallback.

    Pointed at a closed loopback port so both remote transports fail fast; the
    handshake error names every candidate it tried, and stdio must not be one.
    """
    client = mcp_connector.MCPClient("http://127.0.0.1:9/mcp", transport="auto",
                                     allow_private=True, timeout_ms=1000)
    assert client.requested_transport == "auto"
    with pytest.raises(mcp_connector.MCPError) as exc:
        client.initialize()
    client.close()
    detail = str(exc.value)
    assert "http:" in detail and "sse:" in detail
    assert "stdio" not in detail
    assert client.transport is None


# -- the toolkit's launch controls, actually exercised ------------------------

def test_a_command_off_the_toolkit_allowlist_is_refused():
    """AGT decides which runtimes may be launched; this only reports its answer."""
    with pytest.raises(mcp_connector.MCPError) as exc:
        mcp_connector.discover(transport="stdio", command="curl",
                               args=["http://example.com"], timeout_ms=5000)
    assert "not on the allowed command list" in str(exc.value)


@pytest.mark.parametrize("name", ["LD_PRELOAD", "NODE_OPTIONS", "PATH", "HOME",
                                  "PYTHONSTARTUP", "SECRET_TOKEN"])
def test_only_agt_mcp_variables_reach_a_local_server(name):
    """The keys that turn an allowlisted python/node into RCE never get through.

    This platform's rule is narrower than the toolkit's blocklist and lands on
    the same side of it: an AGT_MCP_* allowlist cannot express LD_PRELOAD at all.
    """
    with pytest.raises(ToolError) as exc:
        mcp_connector.stdio_env([name])
    assert "AGT_MCP_" in str(exc.value)


def test_a_named_variable_is_resolved_at_spawn_time(monkeypatch):
    monkeypatch.setenv("AGT_MCP_LOCAL_TOKEN", "s3cret")
    assert mcp_connector.stdio_env(["AGT_MCP_LOCAL_TOKEN"]) == {
        "AGT_MCP_LOCAL_TOKEN": "s3cret"}
    # A name that is not set is absent rather than an empty string, which a
    # server would otherwise read as "configured, but blank".
    assert mcp_connector.stdio_env(["AGT_MCP_NOT_SET"]) == {}


def test_the_toolkit_blocklist_and_this_ones_agree():
    """Guard against the two defences drifting apart."""
    from agent_os.cli.mcp_scan import _blocked_command_env_keys
    assert _blocked_command_env_keys({"LD_PRELOAD": "x"}) == ["LD_PRELOAD"]
    # AGT_MCP_* is inert by the toolkit's own reckoning, which is what makes it
    # safe for this platform to pass through.
    assert _blocked_command_env_keys({"AGT_MCP_TOKEN": "x"}) == []


# -- a local server is graded for being local ---------------------------------

def test_a_local_tool_is_graded_for_running_a_process():
    """The transport is a capability fact the descriptor cannot express.

    `echo` is as harmless as a descriptor gets. Served locally it still starts a
    program on this host, and the grade says so — which is what keeps a Ring 3
    agent from dispatching it on the strength of a friendly description.
    """
    descriptor = {
        "name": "echo", "description": "Return the text supplied.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to echo"}},
            "required": ["text"], "additionalProperties": False,
        },
    }
    remote = mcp_connector.evaluate_tool(descriptor)
    local = mcp_connector.evaluate_tool(descriptor, local_execution=True)

    assert "transport.local_execution" not in {f["id"] for f in remote["findings"]}
    assert "transport.local_execution" in {f["id"] for f in local["findings"]}
    assert remote["risk"] == "low"
    assert local["risk"] == "medium"


# -- end to end through the governed API --------------------------------------

def test_a_local_server_imports_through_the_same_route_as_a_remote_one(client):
    body = client.post("/mcp/import", json=launch(max_risk="high")).json()
    assert body["transport"] == "stdio"
    assert body["server_url"] is None
    names = {t["name"] for t in body["imported"]}
    assert "mcp.local-notes.echo" in names
    # The poisoned descriptor is refused by the ceiling exactly as it would be
    # from a remote server: the attack on MCP is the descriptor, not the wire.
    assert [s["tool"] for s in body["skipped"]] == ["search_notes"]


def test_the_registry_stores_a_launch_line_instead_of_a_url(client):
    client.post("/mcp/import", json=launch(max_risk="high"))
    registered = client.get("/tools").json()["registered"]
    entry = next(t for t in registered if t["name"] == "mcp.local-notes.echo")
    mcp = entry["mcp"]
    assert mcp["transport"] == "stdio"
    assert mcp["server_url"] is None
    assert mcp["command"] == sys.executable
    assert mcp["args"] == [SERVER]


def test_a_governed_call_really_runs_the_local_server(client):
    client.post("/mcp/import", json=launch(max_risk="high"))
    client.post("/agents", json={"id": "local-caller", "name": "local-caller",
                                 "trust_score": 0.9})
    result = client.post("/tools/call", json={
        "tool_name": "mcp.local-notes.echo", "action": "invoke",
        "agent_id": "local-caller",
        "kwargs": {"arguments": {"text": "round trip"}},
    }).json()

    assert result["allowed"] is True
    outcome = result["result"]
    assert outcome["executed"] is True
    assert outcome["transport"] == "stdio"
    # The text came back out of the child process. Nothing here is fabricated:
    # a server that had not run would have no way to produce it.
    assert any(part.get("text") == "round trip"
               for part in outcome["content"])


def test_a_local_call_earns_a_signed_receipt_like_any_other_mcp_call(client):
    client.post("/mcp/import", json=launch(max_risk="high"))
    client.post("/agents", json={"id": "local-caller", "name": "local-caller",
                                 "trust_score": 0.9})
    result = client.post("/tools/call", json={
        "tool_name": "mcp.local-notes.echo", "action": "invoke",
        "agent_id": "local-caller", "kwargs": {"arguments": {"text": "x"}},
    }).json()
    assert result.get("receipt")
    verify = client.get("/mcp/receipts/verify").json()
    assert verify["valid"] is True


def test_a_sandboxed_agent_cannot_start_a_local_server_at_all(client):
    """0.35 clears the platform trust floor and is still refused — at the ring.

    A local MCP tool is dispatched by starting a process, and ring 3 forbids
    subprocesses outright. That reason arrives *before* the trust floor the
    tool's own grade carries, and it is the stronger of the two: no amount of
    per-tool trust makes a sandboxed agent entitled to spawn something.
    """
    client.post("/mcp/import", json=launch(max_risk="high"))
    client.post("/agents", json={"id": "middling", "name": "middling",
                                 "trust_score": 0.35})
    result = client.post("/tools/call", json={
        "tool_name": "mcp.local-notes.echo", "action": "invoke",
        "agent_id": "middling", "kwargs": {"arguments": {"text": "x"}},
    }).json()

    assert result["allowed"] is False
    assert result["denied_by"] == "ring"
    assert result["rule"] == "ring:subprocess"


def test_the_local_grade_still_denies_once_the_ring_is_satisfied(client):
    """The reconciliation with the ring model, isolated from the ring itself.

    0.7 is ring 2, so subprocesses are permitted and the ring gate passes.
    `purge_bucket` grades `high` — partly *because* it is served locally — so
    the trust proxy demands 0.8 and refuses. The grade is doing the work here,
    not the ring.
    """
    client.post("/mcp/import", json=launch(max_risk="high"))
    client.post("/agents", json={"id": "trusted-ish", "name": "trusted-ish",
                                 "trust_score": 0.7})
    result = client.post("/tools/call", json={
        "tool_name": "mcp.local-notes.purge_bucket", "action": "invoke",
        "agent_id": "trusted-ish", "kwargs": {"arguments": {"bucket": "b"}},
    }).json()

    assert result["allowed"] is False
    assert result["denied_by"] == "mcp_proxy"
    assert result["rule"] == "mcp_proxy:min_trust"


def test_removing_a_local_server_removes_its_tools(client):
    client.post("/mcp/import", json=launch(max_risk="high"))
    removed = client.delete("/mcp/servers/local-notes").json()
    assert removed["removed"]
    live = {t["name"] for t in client.get("/tools").json()["registered"]}
    assert not any(n.startswith("mcp.local-notes.") for n in live)


def test_a_local_server_can_be_re_verified_for_a_rug_pull(client):
    """Re-verification relaunches the server, which is the only way to ask it."""
    client.post("/mcp/import", json=launch(max_risk="high"))
    body = client.post("/mcp/servers/local-notes/verify").json()
    assert body["clean"] is True
    assert body["changed"] == 0
    assert {c["tool"] for c in body["checked"]} == {
        "mcp.local-notes.echo", "mcp.local-notes.lookup_order",
        "mcp.local-notes.purge_bucket"}


# -- refusing badly-formed launch lines --------------------------------------

def test_a_local_import_without_a_command_is_refused(client):
    body = launch()
    body.pop("command")
    assert client.post("/mcp/import", json=body).status_code == 400


def test_a_remote_import_without_a_url_is_refused(client):
    assert client.post("/mcp/import", json={"transport": "http"}).status_code == 400


def test_a_working_directory_that_does_not_exist_is_refused(client):
    body = launch(cwd=os.path.join(os.path.dirname(SERVER), "no-such-dir"))
    assert client.post("/mcp/import", json=body).status_code in (400, 502)
