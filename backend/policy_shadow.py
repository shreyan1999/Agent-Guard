"""Dry-run a policy edit before it enforces, via ``agentmesh.governance.shadow``.

Policies are the one artefact here that decides whether an agent may act, and
until now they were edited blind: you saved, and the next call was governed by
the new rules. ``ShadowMode`` is AGT's answer — it evaluates a *candidate*
policy alongside a production decision and reports where the two diverge.

The question an operator actually asks is "if I save this, what changes?", so
the comparison is **policy against policy**, not candidate against history. Both
engines are evaluated now, on the same contexts:

* the **contexts** come from the audit chain, so the replay is over calls this
  platform really saw rather than invented traffic;
* the **production verdict** is the baseline policy re-evaluated on each of
  those contexts, not the verdict recorded at the time. A call denied at the
  trust gate never reached policy, and counting it as a policy decision would
  attribute a gate's work to a rule.

**What the replay cannot reproduce, it says so about.** The audit chain records
the agent, tool and action of every governed call — it does not record
``input_text``, because the log would then hold whatever an agent sent. So a
rule keyed on ``input_text`` (``has_pii``, ``has_credentials``) cannot be
replayed faithfully: those comparisons are flagged ``uncertain`` rather than
quietly evaluated against an empty string and reported as fact.
"""

from __future__ import annotations

import uuid

import observability

from agentmesh.governance.shadow import ShadowMode, SimulatedAction

_log = observability.get_logger(__name__)

# AGT's own budget: a candidate diverging from production by more than this is
# a material change rather than a tweak.
DIVERGENCE_TARGET = ShadowMode.DIVERGENCE_TARGET

# A reserved prefix for the throwaway policy a draft is compiled through. AGT
# resolves `extends` relative to the policy directory, so a draft that inherits
# has to be written there to be compiled at all.
DRAFT_PREFIX = "shadow-draft-"


def draft_name() -> str:
    return f"{DRAFT_PREFIX}{uuid.uuid4().hex[:10]}"


def text_dependent_rules(*policies) -> list:
    """Rules whose condition reads ``input_text``, from any of *policies*.

    These are the rules a replay cannot honour, because the audit chain does not
    retain the text. Naming them is the difference between a report with a
    caveat and a report that is wrong.
    """
    found = []
    for doc in policies:
        for rule in (doc or {}).get("rules") or []:
            condition = str(rule.get("condition") or "")
            if "input_text" in condition:
                found.append({"policy": (doc or {}).get("name"),
                              "rule": rule.get("name"),
                              "condition": condition})
    return found


def contexts_from_audit(entries: list, limit: int) -> list:
    """Turn recorded tool calls into contexts both engines can be run on.

    Only `tool.call.*` entries carry an action, and only those are replayable.
    Everything else in the chain — policy edits, lifecycle moves, chaos runs —
    is not a governed decision and is skipped rather than counted.
    """
    contexts = []
    for e in entries:
        if not str(e.get("event_type", "")).startswith("tool.call"):
            continue
        details = e.get("details") or {}
        action = details.get("action")
        if not action:
            continue
        contexts.append({
            "audit_id": e.get("id"),
            "agent_id": e.get("agent_id"),
            "tool": details.get("tool"),
            "action": action,
            "recorded_allowed": bool(e.get("allowed")),
            "recorded_policy": details.get("policy"),
        })
        if len(contexts) >= limit:
            break
    return contexts


def _verdict(engine, ctx: dict, agent_facet: dict, tool_facet: dict) -> dict:
    """Evaluate one context on one engine, shaped for comparison.

    ``PolicyEngine.evaluate(agent_did, context)`` takes the agent first — the
    same call ``/policies/evaluate`` makes, so a shadow verdict and a live one
    come from an identically-invoked engine.
    """
    context = {
        "action": {"type": ctx["action"]},
        # The replay cannot supply this; see the module docstring.
        "input_text": {"value": ""},
        "agent": agent_facet,
        "tool": tool_facet,
    }
    try:
        decision = engine.evaluate(str(ctx.get("agent_id") or ""), context)
    except Exception as exc:                      # a candidate that will not compile
        _log.debug("shadow: a candidate policy failed to evaluate", exc_info=True)
        return {"allowed": None, "rule": None, "error": f"{type(exc).__name__}: {exc}"}
    return {
        "allowed": bool(getattr(decision, "allowed", False)),
        "rule": getattr(decision, "matched_rule", None),
        "action": getattr(decision, "action", None),
        "error": None,
    }


def compare(*, baseline_engine, candidate_engine, contexts: list,
            facets_for, uncertain_rules: "set[str] | None" = None) -> dict:
    """Replay *contexts* through both engines and report the divergence.

    ``facets_for(agent_id, tool)`` supplies the agent and tool facets so this
    module never reaches into the app's registries.
    """
    uncertain_rules = uncertain_rules or set()
    shadow = ShadowMode(policy_engine=candidate_engine)
    shadow.start_session()

    comparisons, diverged = [], 0
    newly_denied = newly_allowed = 0
    for ctx in contexts:
        agent_facet, tool_facet = facets_for(ctx.get("agent_id"), ctx.get("tool"))
        production = _verdict(baseline_engine, ctx, agent_facet, tool_facet)
        candidate = _verdict(candidate_engine, ctx, agent_facet, tool_facet)

        # AGT owns the divergence call; the dict keys are the ones it reads.
        result = shadow.evaluate(
            SimulatedAction(
                action_id=str(ctx.get("audit_id") or uuid.uuid4().hex),
                agent_did=str(ctx.get("agent_id") or ""),
                action_type=ctx["action"],
                context={"action": {"type": ctx["action"]}},
            ),
            production_decision={"allowed": production["allowed"],
                                 "action": production.get("action"),
                                 "rule": production.get("rule")},
        )
        # Trust AGT's flag, but fall back to the plain verdict comparison when a
        # decision carried no action for it to compare.
        changed = bool(getattr(result, "diverged", False)) or \
            production["allowed"] != candidate["allowed"]
        # A comparison resting on a rule the replay could not feed is reported
        # as uncertain, not as a finding.
        uncertain = bool({production.get("rule"), candidate.get("rule")} & uncertain_rules)

        if changed and not uncertain:
            diverged += 1
            if production["allowed"] and not candidate["allowed"]:
                newly_denied += 1
            elif not production["allowed"] and candidate["allowed"]:
                newly_allowed += 1

        comparisons.append({
            "audit_id": ctx.get("audit_id"),
            "agent_id": ctx.get("agent_id"),
            "tool": ctx.get("tool"),
            "action": ctx["action"],
            "production_allowed": production["allowed"],
            "production_rule": production["rule"],
            "candidate_allowed": candidate["allowed"],
            "candidate_rule": candidate["rule"],
            "diverged": changed and not uncertain,
            "uncertain": uncertain,
            "reason": getattr(result, "divergence_reason", None),
            "error": candidate["error"] or production["error"],
        })

    shadow.end_session()
    total = len(comparisons)
    rate = (diverged / total) if total else 0.0
    return {
        "replayed": total,
        "diverged": diverged,
        "uncertain": sum(1 for c in comparisons if c["uncertain"]),
        "divergence_rate": round(rate, 4),
        "divergence_target": DIVERGENCE_TARGET,
        # AGT's own threshold for "this is a material change, not a tweak".
        "within_target": rate <= DIVERGENCE_TARGET,
        "would_newly_deny": newly_denied,
        "would_newly_allow": newly_allowed,
        "comparisons": comparisons,
    }
