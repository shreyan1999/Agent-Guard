"""Trust computed from behaviour, via AGT's ``nexus.ReputationEngine``.

Until now an agent's trust score only changed when a human dragged a slider.
That makes the number an *input* to governance and never an *output* of it — an
agent could fail every call it made and stay at 0.92 forever.

``nexus`` is AGT's Agent Trust Exchange, and its ``ReputationEngine`` computes a
0-1000 score from two things: a **verification level** (how well the identity is
established) and a **behavioural history** (what the agent actually did). Both
are already recorded by this platform, so nothing new has to be instrumented —
the governed-call counters and the agent's age *are* the history.

The engine is used offline. ``NexusClient`` talks to a hosted exchange and
``ProofOfOutcome`` is escrow/credits; neither is a governance concern here, so
neither is imported. Only the pure calculation is.

**The computed score does not silently replace the operator's.** It is reported
alongside the manual one, because a trust score that moved on its own without
anyone seeing why would be worse than a stale one. Promoting it to the enforced
score is an operator action, not a background job.

Verification level is earned, not configured:

===================  ==========================================================
``unknown``          No identity has been minted for this agent.
``registered``       An Ed25519 identity and DID exist.
``verified``         The agent has proved possession of its private key at least
                     once, by signing a challenge nonce.
``verified_partner`` Attested *and* carrying a signed TrustedAgentCard whose
                     signature still verifies.
===================  ==========================================================

Every rung above the first is a cryptographic act, not a setting.
"""

from __future__ import annotations

import time

from nexus.reputation import ReputationEngine, ReputationHistory

# AGT scores reputation on 0-1000; this platform's trust gate is a 0.0-1.0
# float. The conversion happens here and at the MCP proxy boundary, nowhere else.
TRUST_SCALE = 1000

VERIFICATION_LEVELS = ("unknown", "registered", "verified", "verified_partner")

_engine = ReputationEngine()


def verification_level(*, has_identity: bool, attested: bool,
                       card_valid: bool) -> str:
    """Which rung of AGT's verification ladder this agent has earned."""
    if not has_identity:
        return "unknown"
    if attested and card_valid:
        return "verified_partner"
    if attested:
        return "verified"
    return "registered"


def _days_since(created_at) -> int:
    """Whole days an agent has existed, from its lifecycle record."""
    if created_at is None:
        return 0
    try:
        stamp = created_at.timestamp()
    except AttributeError:
        stamp = float(created_at)
    return max(0, int((time.time() - stamp) // 86400))


def compute(*, agent_did: str, calls: int, denials: int, created_at=None,
            has_identity: bool = True, attested: bool = False,
            card_valid: bool = False) -> dict:
    """Score one agent from its own governed-call record.

    The mapping onto AGT's history is deliberately narrow and literal:

    * ``successful_tasks``  — governed calls this platform allowed
    * ``failed_tasks``      — governed calls it denied
    * ``uptime_days``       — the agent's age from its lifecycle record

    ``disputes_won``/``disputes_lost``/``times_slashed`` stay at zero because
    this platform models none of them. Inventing values to make the number look
    richer would make it a fiction, which is the opposite of the point.
    """
    level = verification_level(has_identity=has_identity, attested=attested,
                               card_valid=card_valid)
    history = ReputationHistory(
        agent_did=agent_did or "did:unknown",
        successful_tasks=max(0, int(calls)),
        failed_tasks=max(0, int(denials)),
        total_tasks=max(0, int(calls) + int(denials)),
        uptime_days=_days_since(created_at),
    )
    score = _engine.calculate_trust_score(level, history)
    tier = getattr(score.tier, "name", str(score.tier)).replace("TrustTier.", "")
    return {
        "verification_level": level,
        "score": score.total_score,
        "score_normalised": round(score.total_score / TRUST_SCALE, 3),
        "tier": tier,
        "base_score": score.base_score,
        "behavioural_modifier": score.behavioral_modifier,
        "capability_modifier": score.capability_modifier,
        "successful_tasks": history.successful_tasks,
        "failed_tasks": history.failed_tasks,
        "uptime_days": history.uptime_days,
        # No governed calls yet means the behavioural half is unevidenced. Say
        # so, rather than letting a base-score-only number read as a verdict.
        "evidenced": history.total_tasks > 0,
    }
