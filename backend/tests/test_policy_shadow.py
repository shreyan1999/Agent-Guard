"""Dry-running a policy edit before it enforces (`agentmesh.governance.shadow`).

The question is "if I save this, what changes?", so these tests pin that the
comparison is **policy against policy** on contexts the platform really saw, and
that what the replay cannot reproduce is reported rather than guessed at.
"""

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


@pytest.fixture
def traffic(client):
    """Governed calls whose contexts a shadow run replays."""
    for _ in range(8):
        client.post("/tools/call", json={"tool_name": "db_query", "action": "read",
                                         "agent_id": "research-agent"})
    for _ in range(3):
        client.post("/tools/call", json={"tool_name": "send_email", "action": "send_email",
                                         "agent_id": "data-agent"})
    for _ in range(2):
        client.post("/tools/call", json={"tool_name": "db_query", "action": "drop",
                                         "agent_id": "data-agent"})
    return client


def _shadow(client, rules=None, **kw):
    body = {"baseline": "default-policy", **kw}
    if rules is not None:
        body["candidate"] = {"name": "draft", "default_action": "allow", "rules": rules}
    return client.post("/policies/shadow", json=body)


DENY_READS = [{"name": "block-reads", "condition": "action.type == 'read'",
               "action": "deny", "priority": 10}]


# ── The replay ───────────────────────────────────────────────────────────────

def test_contexts_come_from_real_traffic(traffic):
    r = _shadow(traffic, DENY_READS).json()
    assert r["replayed"] == 13
    actions = {c["action"] for c in r["comparisons"]}
    assert actions == {"read", "send_email", "drop"}
    assert all(c["agent_id"] in {"research-agent", "data-agent"} for c in r["comparisons"])


def test_no_traffic_replays_nothing_rather_than_guessing(client):
    r = _shadow(client, DENY_READS).json()
    assert r["replayed"] == 0
    assert r["diverged"] == 0
    assert r["divergence_rate"] == 0.0


def test_only_governed_calls_are_replayed(traffic):
    """Policy edits, lifecycle moves and chaos runs are in the chain too, and
    none of them is a policy decision."""
    traffic.post("/policies", json={"name": "noise", "rules": []})
    traffic.post("/sre/kill/email-agent")
    r = _shadow(traffic, DENY_READS).json()
    assert r["replayed"] == 13, "a non-decision event was replayed as one"


# ── Policy against policy ────────────────────────────────────────────────────

def test_an_identical_candidate_diverges_nowhere(traffic):
    """The clearest signal the comparison is real: the shipped policy compared
    against itself must change nothing."""
    live = traffic.get("/policies/default-policy").json()
    r = _shadow(traffic, live["rules"]).json()
    assert r["diverged"] == 0
    assert r["divergence_rate"] == 0.0
    assert r["within_target"] is True
    assert r["would_newly_deny"] == 0 and r["would_newly_allow"] == 0


def test_a_stricter_candidate_reports_what_it_would_newly_deny(traffic):
    r = _shadow(traffic, DENY_READS).json()
    assert r["would_newly_deny"] == 8            # the eight reads
    reads = [c for c in r["comparisons"] if c["action"] == "read"]
    assert all(c["production_allowed"] and not c["candidate_allowed"] for c in reads)
    assert all(c["candidate_rule"] == "block-reads" for c in reads)


def test_a_looser_candidate_reports_what_it_would_newly_allow(traffic):
    """Dropping the `warn` rule flips send_email to allowed — AGT computes
    allowed = (action == "allow"), so a warn rule denies."""
    r = _shadow(traffic, [{"name": "block-destructive",
                           "condition": 'action.type in ["drop","delete"]',
                           "action": "deny", "priority": 10}]).json()
    assert r["would_newly_allow"] == 3
    assert r["would_newly_deny"] == 0
    emails = [c for c in r["comparisons"] if c["action"] == "send_email"]
    assert all(c["production_rule"] == "flag-elevated" for c in emails)
    assert all(c["candidate_allowed"] for c in emails)
    # The rules both policies share must not move.
    drops = [c for c in r["comparisons"] if c["action"] == "drop"]
    assert all(not c["diverged"] for c in drops)


def test_agts_divergence_target_is_applied(traffic):
    r = _shadow(traffic, DENY_READS).json()
    assert r["divergence_target"] == 0.02
    assert r["divergence_rate"] > 0.02
    assert r["within_target"] is False


def test_a_saved_policy_can_be_shadowed_by_name(traffic):
    traffic.post("/policies", json={"name": "candidate", "rules": DENY_READS})
    r = _shadow(traffic, candidate_name="candidate").json()
    assert r["candidate"] == "candidate"
    assert r["would_newly_deny"] == 8


# ── What the replay cannot reproduce ─────────────────────────────────────────

def test_text_dependent_rules_are_named(traffic):
    """The audit chain does not retain input_text, so a rule reading it cannot
    be replayed — and the report says which rules those are."""
    r = _shadow(traffic, DENY_READS).json()
    named = {x["rule"] for x in r["text_dependent_rules"]}
    assert "block-pii" in named            # from the shipped default policy
    assert r["replay_limitation"] and "input_text" in r["replay_limitation"]


def test_a_comparison_resting_on_a_text_rule_is_uncertain_not_counted(traffic):
    """Evaluating a PII rule against an empty string and reporting the result as
    fact would be worse than reporting nothing."""
    r = _shadow(traffic, [{"name": "block-pii", "condition": "input_text.has_pii",
                           "action": "deny", "priority": 10}]).json()
    assert r["replay_limitation"] is not None
    # Nothing is claimed as a divergence on the strength of a rule that could
    # not be fed its input.
    for c in r["comparisons"]:
        if c["uncertain"]:
            assert c["diverged"] is False


def test_no_text_rules_means_no_caveat(client):
    client.post("/policies", json={"name": "plain", "rules": [
        {"name": "block-drop", "condition": "action.type == 'drop'",
         "action": "deny", "priority": 10}]})
    r = _shadow(client, DENY_READS, baseline="plain").json()
    assert r["text_dependent_rules"] == []
    assert r["replay_limitation"] is None


# ── The draft never becomes a policy ─────────────────────────────────────────

def test_the_draft_is_removed_after_the_run(traffic):
    _shadow(traffic, DENY_READS)
    assert [n for n in main._policies.names() if n.startswith("shadow-draft-")] == []
    assert [p["name"] for p in traffic.get("/policies").json()
            if p["name"].startswith("shadow-draft-")] == []


def test_the_draft_is_removed_even_when_the_run_fails(traffic, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("comparison exploded")
    monkeypatch.setattr(main.policy_shadow, "compare", boom)
    with pytest.raises(RuntimeError):
        _shadow(traffic, DENY_READS)
    assert [n for n in main._policies.names() if n.startswith("shadow-draft-")] == []


def test_a_draft_that_agt_cannot_parse_is_refused(client):
    r = _shadow(client, [{"name": "bad", "condition": "input_text matches /x/",
                          "action": "deny", "priority": 10}])
    assert r.status_code == 400


def test_a_shadow_run_enforces_nothing(traffic):
    """The whole point: the candidate is evaluated, never applied."""
    before = traffic.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent"}).json()
    _shadow(traffic, DENY_READS)
    after = traffic.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent"}).json()
    assert before["allowed"] is True and after["allowed"] is True


# ── Contract ─────────────────────────────────────────────────────────────────

def test_an_unknown_baseline_or_candidate_is_404(client):
    assert _shadow(client, DENY_READS, baseline="nope").status_code == 404
    assert _shadow(client, candidate_name="nope").status_code == 404


def test_a_run_needs_a_candidate(client):
    assert client.post("/policies/shadow", json={"baseline": "default-policy"}).status_code == 400


def test_a_shadow_run_is_audited(traffic):
    r = _shadow(traffic, DENY_READS).json()
    events = traffic.get("/audit?limit=100").json()["events"]
    entry = next(e for e in events if e["event_type"] == "policy.shadow")
    assert entry["details"]["replayed"] == r["replayed"]
    assert entry["details"]["would_newly_deny"] == r["would_newly_deny"]


def test_a_shadow_run_needs_operator(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tokV:vic:acme:viewer,tokOp:op:acme:operator")
    main.reload_auth()
    try:
        c = TestClient(main.app)
        body = {"baseline": "default-policy",
                "candidate": {"name": "d", "default_action": "allow", "rules": DENY_READS}}
        assert c.post("/policies/shadow", json=body,
                      headers={"Authorization": "Bearer tokV"}).status_code == 403
        assert c.post("/policies/shadow", json=body,
                      headers={"Authorization": "Bearer tokOp"}).status_code == 200
    finally:
        monkeypatch.delenv("AGT_API_KEYS")
        main.reload_auth()
