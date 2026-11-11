"""What a ring forbids, checked against what the tool actually reaches for.

AGT's ``govern()`` already enforces ring resource constraints — this does not
replace it. But a decorator can only read the *action string*, and infers the
resource type from it by exact token match. Most of this registry is invisible
to that: every MCP tool arrives as ``invoke``, and ``execute_command`` misses
AGT's ``exec`` token, so both are classed TOOL_EXECUTION, which every ring
permits. The demo's ring denials fire only because their verbs — ``web_search``,
``shell_exec`` — happen to carry a matching token.

So the platform's own docstring ("Ring 3 — no network, filesystem or
subprocess") was true only for tools whose verb gave the game away. These tests
cover the part that closes it: the registry supplies the resource type, and
AGT's own ``RingEnforcer`` still returns the verdict.
"""

import pytest

from hypervisor.rings import ResourceType

import main


def spec(category="data_read", **extra):
    base = {"name": "t", "category": category, "kind": "webhook"}
    base.update(extra)
    return base


# -- the mapping ---------------------------------------------------------------

@pytest.mark.parametrize("category,expected", [
    ("code_execution", ResourceType.SUBPROCESS),
    ("filesystem",     ResourceType.FILESYSTEM),
    ("network",        ResourceType.NETWORK),
    # A message leaves this host over the network whatever carries it.
    ("communication",  ResourceType.NETWORK),
])
def test_a_category_that_names_a_resource_is_mapped_to_it(category, expected):
    assert main._ring_resource(spec(category)) is expected


@pytest.mark.parametrize("category", ["data_read", "search", "data_write",
                                      "secrets", "finance", "uncategorised"])
def test_anything_uncertain_stays_at_the_type_every_ring_permits(category):
    """A guess must never become a denial.

    These categories do not name a resource on their own — a `data_write` may
    be a database row rather than a file — so they fall to TOOL_EXECUTION,
    which AGT's constraint table allows at every ring.
    """
    assert main._ring_resource(spec(category)) is ResourceType.TOOL_EXECUTION


def test_a_local_mcp_tool_is_a_subprocess_whatever_its_category():
    """Not a guess: dispatching it starts a process on this host."""
    local = spec("data_read", kind="mcp",
                 mcp={"transport": "stdio", "command": "python"})
    assert main._ring_resource(local) is ResourceType.SUBPROCESS


def test_a_remote_mcp_tool_is_judged_on_its_category_alone():
    remote = spec("data_read", kind="mcp",
                  mcp={"transport": "http", "server_url": "https://x/mcp"})
    assert main._ring_resource(remote) is ResourceType.TOOL_EXECUTION


def test_the_constraint_table_is_the_toolkits_own():
    """Borrowed, not copied — a local table would drift from AGT's."""
    from hypervisor.rings import RING_CONSTRAINTS
    from hypervisor.models import ExecutionRing
    sandbox = RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX]
    assert sandbox.network_allowed is False
    assert sandbox.subprocess_allowed is False
    assert sandbox.filesystem_scope == "none"
    standard = RING_CONSTRAINTS[ExecutionRing.RING_2_STANDARD]
    assert standard.network_allowed is True


# -- enforcement ---------------------------------------------------------------

@pytest.fixture
def sandboxed(client):
    """Trust 0.45: over the 0.3 trust floor, under the 0.6 ring-2 line."""
    client.post("/agents", json={"id": "sandboxed", "name": "sandboxed",
                                 "trust_score": 0.45})
    return client


@pytest.fixture
def standard(client):
    client.post("/agents", json={"id": "standard", "name": "standard",
                                 "trust_score": 0.72})
    return client


@pytest.mark.parametrize("tool,rule", [
    ("send_email", "ring:network"),
    ("write_file", "ring:filesystem"),
])
def test_ring_three_cannot_reach_a_resource_its_ring_forbids(sandboxed, tool, rule):
    """The action verb here is a harmless "read" — the registry is what tells."""
    result = sandboxed.post("/tools/call", json={
        "tool_name": tool, "action": "read", "agent_id": "sandboxed"}).json()

    assert result["allowed"] is False
    assert result["denied_by"] == "ring"
    assert result["rule"] == rule


def test_ring_two_may_reach_the_same_resources(standard):
    for tool in ("send_email", "write_file"):
        result = standard.post("/tools/call", json={
            "tool_name": tool, "action": "read", "agent_id": "standard"}).json()
        assert result["allowed"] is True, f"{tool} should be allowed at ring 2"


def test_a_harmless_tool_is_untouched_at_ring_three(sandboxed):
    result = sandboxed.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "sandboxed"}).json()
    assert result["allowed"] is True


def test_agts_own_inference_still_decides_when_the_verb_carries_it(sandboxed):
    """This adds to AGT's check rather than replacing it.

    `shell_exec` carries AGT's own `shell` token, so the denial comes back
    under AGT's rule name, not this platform's.
    """
    result = sandboxed.post("/tools/call", json={
        "tool_name": "db_query", "action": "shell_exec",
        "agent_id": "sandboxed"}).json()

    assert result["allowed"] is False
    assert result["denied_by"] == "ring"
    assert result["rule"] == "ring_enforcement"


def test_a_resource_denial_does_not_trip_agts_breaker(sandboxed):
    """AGT cuts a session off after repeated ring violations of its own.

    This gate denies before govern() runs, so it never feeds that detector —
    an agent refused a network tool can still do the reading it is entitled
    to, rather than being locked out of everything by one refusal.
    """
    denied = sandboxed.post("/tools/call", json={
        "tool_name": "send_email", "action": "read",
        "agent_id": "sandboxed"}).json()
    assert denied["allowed"] is False

    after = sandboxed.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "sandboxed"}).json()
    assert after["allowed"] is True


def test_the_denial_reaches_the_audit_chain_as_a_ring_denial(sandboxed):
    sandboxed.post("/tools/call", json={
        "tool_name": "send_email", "action": "read", "agent_id": "sandboxed"})
    events = sandboxed.get("/audit?event_type=tool.call.denied.ring").json()["events"]
    assert events and all(e["allowed"] is False for e in events)
    assert any(e["details"].get("rule") == "ring:network" for e in events)


# -- the grammar ----------------------------------------------------------------

def test_the_ring_paths_agt_injects_are_advertised(client):
    """govern() puts these in the context; a path nobody documents is a path
    nobody writes a rule against."""
    paths = {f["path"] for f in client.get("/policies/schema").json()["fields"]}
    assert {"ring.level", "ring.network_allowed",
            "ring.subprocess_allowed"} <= paths


def test_a_policy_can_be_written_against_the_injected_ring_context(client):
    """The paths are real, not just documented.

    Written as `ring.level > 2` rather than `ring.network_allowed == false`:
    AGT's grammar has no unquoted boolean comparison, and this project's own
    condition linter refuses the second form rather than storing a rule that
    could never match. The schema help says so.
    """
    client.post("/agents", json={"id": "r3", "name": "r3", "trust_score": 0.45})
    created = client.post("/policies", json={
        "name": "sandbox-rule", "description": "x", "default_action": "allow",
        "rules": [{"name": "no-sandbox-writes",
                   "condition": "ring.level > 2",
                   "action": "deny", "reason": "Sandboxed."}]})
    assert created.status_code == 200

    result = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": "r3", "policy_name": "sandbox-rule"}).json()

    assert result["allowed"] is False
    assert result["rule"] == "no-sandbox-writes"
