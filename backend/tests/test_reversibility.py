"""Whether a governed call can be taken back.

AGT's ring model defines Ring 1 as the band for non-reversible actions, but
this platform derives the ring from the caller's trust alone — so until now a
search and a bucket purge were governed identically whenever the two callers
were equally trusted. These tests cover the half that was missing.

Two properties matter more than the individual mappings:

  * the grade is **evidence-led**. A server's own `readOnlyHint` is a claim,
    and a claim its own wording contradicts is worth less than the wording; and
  * the grade **decides nothing by itself**. It lands as a policy facet, so an
    operator writes the rule. The end-to-end tests assert on a rule firing, not
    on the module refusing anything.
"""

import pytest

import reversibility
from reversibility import ReversibilityLevel, classify


def spec(**overrides):
    base = {"name": "t", "category": "data_read", "kind": "webhook",
            "evaluation": {"findings": []}}
    base.update(overrides)
    return base


def finding(fid, severity="high"):
    return {"id": fid, "severity": severity, "detail": ""}


# -- the vocabulary is the toolkit's ------------------------------------------

def test_the_levels_and_weights_are_agts_own_numbers():
    """Borrowed, not invented — and the test says where from."""
    from agent_runtime import ReversibilityLevel as AGTLevel
    assert ReversibilityLevel is AGTLevel
    assert {lv.value for lv in ReversibilityLevel} == {"full", "partial", "none"}
    assert ReversibilityLevel.FULL.default_risk_weight == 0.2
    assert ReversibilityLevel.PARTIAL.default_risk_weight == 0.65
    assert ReversibilityLevel.NONE.default_risk_weight == 0.95


# -- classification ------------------------------------------------------------

@pytest.mark.parametrize("category,expected", [
    ("search", ReversibilityLevel.FULL),
    ("data_read", ReversibilityLevel.FULL),
    ("data_write", ReversibilityLevel.PARTIAL),
    ("filesystem", ReversibilityLevel.PARTIAL),
    ("network", ReversibilityLevel.PARTIAL),
    ("communication", ReversibilityLevel.NONE),
    ("finance", ReversibilityLevel.NONE),
    ("secrets", ReversibilityLevel.NONE),
    ("code_execution", ReversibilityLevel.NONE),
])
def test_the_category_grades_a_tool_with_no_other_evidence(category, expected):
    assert classify(spec(category=category)) is expected


def test_an_uncategorised_tool_takes_the_toolkits_fail_closed_default():
    """AGT defaults an unregistered action to NONE; so does this."""
    assert classify(spec(category="uncategorised")) is ReversibilityLevel.NONE
    assert reversibility.DEFAULT_LEVEL is ReversibilityLevel.NONE


@pytest.mark.parametrize("fid", ["capability.destructive_action",
                                 "capability.code_execution"])
def test_a_destructive_capability_outranks_a_gentle_category(fid):
    """The finding is evidence; the category is a keyword guess."""
    graded = classify(spec(category="data_read",
                           evaluation={"findings": [finding(fid)]}))
    assert graded is ReversibilityLevel.NONE


# -- the server's own claims ---------------------------------------------------

def mcp_spec(annotations, findings=(), category="data_read"):
    return spec(
        kind="mcp", category=category,
        evaluation={"findings": list(findings)},
        mcp={"server": "s", "remote_tool": "t",
             "descriptor": {"description": "", "input_schema": None,
                            "annotations": annotations}},
    )


def test_a_read_only_claim_is_honoured_when_nothing_contradicts_it():
    assert classify(mcp_spec({"readOnlyHint": True})) is ReversibilityLevel.FULL


def test_a_read_only_claim_is_refused_when_the_descriptor_contradicts_it():
    """The case this platform already detects, now carried into the grade.

    The demo server's `purge_bucket` says "Delete every object stored in a
    bucket. This cannot be undone." and annotates itself readOnlyHint=true. The
    evaluation raises `annotations.contradicted` for exactly that, and a grade
    that still believed the annotation would be the one place the platform
    took a server at its word after catching it out.
    """
    graded = classify(mcp_spec(
        {"readOnlyHint": True},
        findings=[finding("capability.destructive_action"),
                  finding("annotations.contradicted")],
    ))
    assert graded is ReversibilityLevel.NONE


def test_a_self_declared_destructive_tool_is_taken_at_its_word():
    """A server admitting to destruction needs no corroboration."""
    assert classify(mcp_spec({"destructiveHint": True},
                             category="search")) is ReversibilityLevel.NONE


def test_an_operator_override_outranks_every_derived_signal():
    graded = classify(spec(category="communication", reversibility="full"))
    assert graded is ReversibilityLevel.FULL


def test_an_unknown_override_is_ignored_rather_than_obeyed():
    """A typo must not silently regrade a tool."""
    graded = classify(spec(category="communication", reversibility="reversible"))
    assert graded is ReversibilityLevel.NONE


# -- the index over AGT's registry --------------------------------------------

def test_the_index_answers_through_the_toolkits_registry():
    index = reversibility.ReversibilityIndex()
    index.register(spec(name="purge", category="code_execution"))
    index.register(spec(name="look", category="search"))

    assert index.level("purge") is ReversibilityLevel.NONE
    assert index.risk_weight("purge") == 0.95
    assert index.is_reversible("look") is True
    assert index.is_reversible("purge") is False
    assert index.non_reversible() == ["purge"]
    assert index.has_non_reversible_actions() is True


def test_forgetting_a_tool_stops_it_answering_for_the_next_one():
    index = reversibility.ReversibilityIndex()
    index.register(spec(name="gone", category="search"))
    index.forget("gone")
    # AGT reports an unregistered action at its fail-closed default.
    assert index.level("gone") is ReversibilityLevel.NONE
    assert index.is_reversible("gone") is False


def test_a_reseed_regrades_everything_a_restart_would_have_forgotten():
    index = reversibility.ReversibilityIndex()
    count = index.reseed([spec(name="a", category="search"),
                          spec(name="b", category="communication")])
    assert count == 2
    assert index.level("a") is ReversibilityLevel.FULL
    assert index.level("b") is ReversibilityLevel.NONE


def test_the_facet_carries_both_fields_a_rule_can_use():
    index = reversibility.ReversibilityIndex()
    index.register(spec(name="send", category="communication"))
    assert index.facet("send") == {"reversibility": "none", "risk_weight": 0.95}


# -- through the platform ------------------------------------------------------

def test_the_builtin_tools_are_graded_on_startup(client):
    import main
    registered = {t["name"] for t in client.get("/tools").json()["registered"]}
    assert {"web_search", "db_query", "send_email"} <= registered
    assert main._reversibility.level("web_search") is ReversibilityLevel.FULL
    assert main._reversibility.level("db_query") is ReversibilityLevel.PARTIAL
    # Nothing un-sends an email.
    assert main._reversibility.level("send_email") is ReversibilityLevel.NONE


def test_the_grammar_advertises_the_two_new_paths(client):
    paths = {f["path"] for f in client.get("/policies/schema").json()["fields"]}
    assert {"tool.reversibility", "tool.risk_weight"} <= paths


def test_a_policy_can_refuse_what_cannot_be_undone(client):
    """The payoff: the grade decides nothing, the rule does."""
    client.post("/agents", json={"id": "a1", "name": "a1", "trust_score": 0.9})
    client.post("/policies", json={
        "name": "undoable-only", "description": "x", "default_action": "allow",
        "rules": [{"name": "block-irreversible",
                   "condition": "tool.reversibility == 'none'",
                   "action": "deny", "reason": "Cannot be undone."}]})

    allowed = client.post("/tools/call", json={
        "tool_name": "web_search", "action": "read",
        "agent_id": "a1", "policy_name": "undoable-only"}).json()
    denied = client.post("/tools/call", json={
        "tool_name": "send_email", "action": "send_email",
        "agent_id": "a1", "policy_name": "undoable-only"}).json()

    assert allowed["allowed"] is True
    assert denied["allowed"] is False
    assert denied["rule"] == "block-irreversible"


def test_a_rule_can_be_written_against_the_risk_weight_instead(client):
    """AGT's weights are numbers, so a threshold works as well as a name."""
    client.post("/agents", json={"id": "a2", "name": "a2", "trust_score": 0.9})
    client.post("/policies", json={
        "name": "weighted", "description": "x", "default_action": "allow",
        "rules": [{"name": "heavy", "condition": "tool.risk_weight > 0.9",
                   "action": "deny", "reason": "Too heavy."}]})

    light = client.post("/tools/call", json={
        "tool_name": "web_search", "action": "read",
        "agent_id": "a2", "policy_name": "weighted"}).json()
    heavy = client.post("/tools/call", json={
        "tool_name": "send_email", "action": "send_email",
        "agent_id": "a2", "policy_name": "weighted"}).json()

    assert light["allowed"] is True
    assert heavy["allowed"] is False
    assert heavy["rule"] == "heavy"


def test_the_evaluator_sees_the_same_facet_the_call_path_does(client):
    """/policies/evaluate exists to predict a call; a facet it lacked would
    make it predict the wrong verdict."""
    client.post("/agents", json={"id": "a3", "name": "a3", "trust_score": 0.9})
    client.post("/policies", json={
        "name": "eval-undoable", "description": "x", "default_action": "allow",
        "rules": [{"name": "block-irreversible",
                   "condition": "tool.reversibility == 'none'",
                   "action": "deny", "reason": "Cannot be undone."}]})

    verdict = client.post("/policies/evaluate", json={
        "policy_name": "eval-undoable", "agent_id": "a3",
        "tool_name": "send_email", "action": "send_email"}).json()

    assert verdict["allowed"] is False
    assert verdict["rule_name"] == "block-irreversible"


def test_removing_a_tool_removes_its_grade(client):
    import main
    client.post("/tools/register", json={
        "name": "temp_tool", "description": "Delete every record permanently.",
        "actions": ["drop"], "risk": "high", "category": "data_write"})
    assert main._reversibility.is_reversible("temp_tool") is True

    client.delete("/tools/temp_tool")
    assert main._reversibility.is_reversible("temp_tool") is False
    assert "temp_tool" not in main._reversibility.non_reversible()


def test_a_newly_onboarded_tool_is_graded_at_registration(client):
    import main
    client.post("/tools/register", json={
        "name": "payments", "description": "Send a payment.",
        "actions": ["pay"], "risk": "high", "category": "finance"})
    assert main._reversibility.level("payments") is ReversibilityLevel.NONE
