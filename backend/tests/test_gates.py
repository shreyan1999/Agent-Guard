"""The four enforcement gates on POST /tools/call.

Gates run lifecycle -> trust -> ring -> policy. Each test names the gate it
expects to stop the call, because "denied" alone would pass even if the wrong
control fired.
"""

import pytest


def call(client, **kw):
    body = {"tool_name": "db_query", "action": "read", "agent_id": "research-agent"}
    body.update(kw)
    r = client.post("/tools/call", json=body)
    assert r.status_code == 200, r.text
    return r.json()


# ── Gate 1: lifecycle ────────────────────────────────────────────────────────

def test_unregistered_agent_is_denied(client):
    d = call(client, agent_id="nobody-at-all")
    assert d["allowed"] is False
    assert d["denied_by"] == "lifecycle"


def test_suspended_agent_cannot_execute(client):
    """Regression for F-04: the kill switch used to be a display-only field."""
    assert call(client)["allowed"] is True

    assert client.post("/sre/kill/research-agent").status_code == 200
    denied = call(client)
    assert denied["allowed"] is False
    assert denied["denied_by"] == "lifecycle"
    assert "suspended" in denied["reason"]

    assert client.post("/sre/resume/research-agent").status_code == 200
    assert call(client)["allowed"] is True


def test_lifecycle_gate_precedes_policy(client):
    """A suspended agent must not reach the policy engine at all."""
    client.post("/sre/kill/data-agent")
    d = call(client, agent_id="data-agent", action="drop")
    # 'drop' would be denied by policy, but lifecycle must win.
    assert d["denied_by"] == "lifecycle"


def test_invalid_lifecycle_transition_is_rejected(client):
    """AGT's state machine rejects suspend-on-suspended; we surface it as 409."""
    assert client.post("/sre/kill/research-agent").status_code == 200
    assert client.post("/sre/kill/research-agent").status_code == 409


# ── Gate 2: trust ────────────────────────────────────────────────────────────

def test_low_trust_agent_is_denied(client):
    """Regression for F-04: trust used to have no effect on execution."""
    d = call(client, agent_id="untrusted-agent")
    assert d["allowed"] is False
    assert d["denied_by"] == "trust"


def test_trust_score_changes_the_verdict(client):
    assert call(client, agent_id="untrusted-agent")["allowed"] is False
    client.post("/trust/update", params={"agent_id": "untrusted-agent", "score": 0.5})
    assert call(client, agent_id="untrusted-agent")["allowed"] is True
    client.post("/trust/update", params={"agent_id": "untrusted-agent", "score": 0.05})
    assert call(client, agent_id="untrusted-agent")["allowed"] is False


def test_agents_are_not_interchangeable(client):
    """Regression for F-04: every agent used to get a byte-identical decision."""
    trusted = call(client, agent_id="research-agent")
    untrusted = call(client, agent_id="untrusted-agent")
    assert trusted["allowed"] != untrusted["allowed"]


# ── Gate 3: ring ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("action,resource", [
    ("web_search", "network"),
    ("shell_exec", "subprocess"),
    ("write_file", "filesystem"),
])
def test_sandbox_ring_blocks_privileged_resources(client, action, resource):
    """email-agent sits at 0.55, below AGT's 0.60 Ring 2 threshold.

    Asserted on the matched rule rather than the reason text: after repeated
    violations AGT trips its circuit breaker and the wording changes, which is
    correct behaviour and covered separately below.
    """
    d = call(client, agent_id="email-agent", tool_name=action, action=action)
    assert d["allowed"] is False
    assert d["denied_by"] == "ring"
    assert d["rule"] == "ring_enforcement"
    assert resource in d["reason"]


def test_ring_2_agent_may_use_network(client):
    d = call(client, agent_id="research-agent", tool_name="web_search", action="web_search")
    assert d["allowed"] is True
    assert d["ring"] == "RING_2_STANDARD"


def test_trust_change_re_derives_the_ring(client):
    """Trust selects the ring, so a score change must change capability."""
    blocked = call(client, agent_id="email-agent", tool_name="web_search", action="web_search")
    assert blocked["denied_by"] == "ring"
    assert blocked["rule"] == "ring_enforcement"

    client.post("/trust/update", params={"agent_id": "email-agent", "score": 0.8})
    allowed = call(client, agent_id="email-agent", tool_name="web_search", action="web_search")
    assert allowed["allowed"] is True
    assert allowed["ring"] == "RING_2_STANDARD"

    client.post("/trust/update", params={"agent_id": "email-agent", "score": 0.4})
    again = call(client, agent_id="email-agent", tool_name="web_search", action="web_search")
    assert again["denied_by"] == "ring"


# ── Gate 4: policy ───────────────────────────────────────────────────────────

def test_destructive_action_denied_by_policy(client):
    d = call(client, agent_id="data-agent", action="drop")
    assert d["allowed"] is False
    assert d["denied_by"] == "policy"
    assert d["rule"] == "block-destructive"


def test_pii_in_input_is_denied(client):
    """Regression for F-02: this rule silently enforced nothing."""
    d = call(client, agent_id="data-agent", input_text="User SSN: 123-45-6789")
    assert d["allowed"] is False
    assert d["denied_by"] == "policy"
    assert d["rule"] == "block-pii"


def test_clean_input_passes_every_gate(client):
    d = call(client, input_text="SELECT name FROM users")
    assert d["allowed"] is True
    assert d["passed_gates"] == ["lifecycle", "trust", "ring", "policy"]


# ── AGT ring circuit breaker ─────────────────────────────────────────────────

def test_repeated_ring_violations_trip_the_breaker(client):
    """AGT cuts off an agent that keeps probing its sandbox."""
    rules = []
    for _ in range(5):
        d = call(client, agent_id="email-agent", tool_name="web_search", action="web_search")
        assert d["allowed"] is False
        rules.append(d["rule"])

    assert rules[0] == "ring_enforcement"
    assert "ring_breaker" in rules, "the breaker never tripped"


def test_a_tripped_breaker_blocks_even_permitted_actions(client):
    """Once tripped, the breaker denies before the ring check runs."""
    for _ in range(4):
        call(client, agent_id="email-agent", tool_name="web_search", action="web_search")

    # 'read' is tool_execution, allowed in every ring — but the breaker wins.
    d = call(client, agent_id="email-agent", action="read")
    assert d["allowed"] is False
    assert d["rule"] == "ring_breaker"


def test_resuming_an_agent_clears_its_breaker(client):
    """Suspend/resume is the operator's remedy for a tripped breaker."""
    for _ in range(4):
        call(client, agent_id="email-agent", tool_name="web_search", action="web_search")
    assert call(client, agent_id="email-agent", action="read")["rule"] == "ring_breaker"

    client.post("/sre/kill/email-agent")
    client.post("/sre/resume/email-agent")

    assert call(client, agent_id="email-agent", action="read")["allowed"] is True


def test_breaker_state_does_not_leak_between_tests(client):
    """Guards the fixture: AGT holds detectors in its own module globals."""
    d = call(client, agent_id="email-agent", tool_name="web_search", action="web_search")
    assert d["rule"] == "ring_enforcement", "a breaker survived from an earlier test"
