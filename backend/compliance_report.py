"""Framework compliance reports from real evidence (`agentmesh.governance.compliance`).

AGT owns the control catalogue, the report structure, the score arithmetic and
the violation model. This module supplies the one thing it cannot: whether *this
platform* can actually evidence each control.

That division matters, because the engine's own ``_check_control`` is not usable
here. It produces violations only for HIPAA (unencrypted PHI) and GDPR (personal
data without verified consent), from a per-action context this platform does not
produce — so left to itself it finds nothing, and a report over controls that can
never fail scores 100%. Worse, a framework with no controls loaded *also* scores
100%: ask AGT for a GDPR report with the default engine and it will tell you the
platform is fully compliant with zero controls assessed.

A dashboard that printed that would be lying in the most expensive way
available. So:

* the engine is built with **every framework enabled**, which loads AGT's eight
  real controls (SOC2 CC6.1/CC7.2, GDPR ART5/ART22, HIPAA 164.312(a)(1)/(b),
  EU AI Act ART9/ART13) rather than the SOC2-only default;
* each control is assessed against live platform state — the same runtime
  controls the OWASP panel reads, plus the audit chain and the last adversarial
  run — and anything not fully evidenced is recorded as a real
  ``ComplianceViolation`` so it lands in AGT's score;
* a framework with no controls loaded reports **not assessed**, never 100%.

This is an evidence-backed self-assessment of a running instance. It is not a
certification, and no amount of green here is an audit.
"""

from __future__ import annotations

import datetime as _dt
import uuid

from agentmesh.governance.compliance import (
    ComplianceEngine, ComplianceFramework, ComplianceViolation,
)

FRAMEWORKS = {f.value: f for f in ComplianceFramework}

# Status of one control against this instance. Only `met` counts toward AGT's
# score: `partial` means the control exists but is not fully evidenced, and
# treating that as a pass is how a self-assessment becomes decoration.
MET, PARTIAL, NOT_EVIDENCED = "met", "partial", "not_evidenced"

_SEVERITY = {PARTIAL: "medium", NOT_EVIDENCED: "high"}


def _assess(ctrl: dict) -> dict:
    """Assess AGT's eight controls against live platform state.

    ``ctrl`` is the evidence bundle the app assembles: runtime controls, audit
    chain facts, policy facts and the last adversarial run. Every branch below
    names the concrete thing that backs the verdict — a control marked met with
    no evidence behind it would be worse than one marked unknown.
    """
    auth = bool(ctrl.get("authentication"))
    attested = bool(ctrl.get("attestation_required"))
    durable_audit = bool(ctrl.get("durable_audit"))
    chain_ok = bool(ctrl.get("audit_chain_valid"))
    entries = int(ctrl.get("audit_entries") or 0)
    pii_rule = bool(ctrl.get("pii_rule_present"))
    approval = bool(ctrl.get("registration_approval_required"))
    kill_switch = bool(ctrl.get("kill_switch"))
    chaos = ctrl.get("adversarial") or {}
    chaos_ran = bool(chaos.get("run_id"))
    # A run whose vectors all died at the identity gate never reached policy,
    # ring or the MCP proxy. Counting that as a tested risk-management system
    # would let mandatory attestation buy a control it did not earn.
    chaos_shallow = bool(chaos.get("shallow"))
    chaos_clean = chaos_ran and not chaos.get("breached") and not chaos_shallow
    receipts = int(ctrl.get("receipts") or 0)
    mcp_graded = bool(ctrl.get("mcp_tool_evaluation"))
    anomaly = bool(ctrl.get("sre_anomaly_detection"))

    def verdict(ok, partial_ok, evidence, note):
        status = MET if ok else (PARTIAL if partial_ok else NOT_EVIDENCED)
        return {"status": status, "evidence": evidence, "note": note}

    return {
        # ── SOC2 ────────────────────────────────────────────────────────────
        "SOC2-CC6.1": verdict(
            auth, True,
            {"api_authentication": auth, "role_hierarchy": auth,
             "tenant_isolation": auth},
            "Bearer auth with a viewer/operator/admin hierarchy and per-tenant "
            "scoping. Without AGT_API_KEYS or AGT_JWT_SECRET every caller is an "
            "anonymous local admin, which is not logical access control."),
        "SOC2-CC7.2": verdict(
            chain_ok and entries > 0 and (durable_audit or anomaly),
            chain_ok and entries > 0,
            {"merkle_audit_chain": chain_ok, "audit_entries": entries,
             "durable_audit": durable_audit, "anomaly_detection": anomaly},
            "Every governed decision is hash-linked into a verifiable chain, with "
            "behavioural anomaly detection over the same traffic. Partial until "
            "the chain is also streamed to a durable signed file."),

        # ── HIPAA ───────────────────────────────────────────────────────────
        "HIPAA-164.312(a)(1)": verdict(
            auth and attested, auth,
            {"api_authentication": auth, "attestation_required": attested,
             "kill_switch": kill_switch},
            "Access is gated by bearer auth and the lifecycle state machine. Full "
            "only when AGT_REQUIRE_ATTESTATION makes an agent prove key "
            "possession rather than asserting its own id."),
        "HIPAA-164.312(b)": verdict(
            chain_ok and durable_audit, chain_ok,
            {"merkle_audit_chain": chain_ok, "durable_audit": durable_audit,
             "audit_entries": entries},
            "Audit controls record and examine activity. Partial while the chain "
            "lives only in memory: a restart loses it."),

        # ── GDPR ────────────────────────────────────────────────────────────
        "GDPR-ART5": verdict(
            pii_rule, bool(ctrl.get("pii_facet_available")),
            {"pii_detection_available": bool(ctrl.get("pii_facet_available")),
             "policy_rule_using_pii": pii_rule},
            "Personal data is detected by AGT's CredentialRedactor and exposed to "
            "policy as input_text.has_pii. Partial until a policy actually acts "
            "on it — detection nothing enforces is not a control."),
        "GDPR-ART22": verdict(
            approval and kill_switch, kill_switch,
            {"registration_approval_required": approval,
             "kill_switch": kill_switch, "human_oversight": approval},
            "Human oversight of automated decisions: an operator can suspend any "
            "agent, and with AGT_REQUIRE_APPROVAL an agent cannot act at all "
            "until a human admits it."),

        # ── EU AI Act ───────────────────────────────────────────────────────
        "EUAI-ART9": verdict(
            chaos_ran and chaos_clean, chaos_ran or mcp_graded,
            {"adversarial_run": chaos_ran,
             "vectors_blocked": chaos.get("held"), "breached": chaos.get("breached"),
             "reached_decision_gates": chaos.get("reached_decision_gates"),
             "shallow_run": chaos_shallow,
             "mcp_descriptor_grading": mcp_graded},
            "A risk management system that is tested, not asserted: AGT's "
            "adversarial vectors are fired at the real gates and scored. Partial "
            "while any vector still gets through, and while every vector is "
            "stopped at the identity gate without policy, ring or the MCP proxy "
            "being reached."),
        "EUAI-ART13": verdict(
            entries > 0 and receipts > 0, entries > 0,
            {"decisions_logged": entries, "signed_receipts": receipts,
             "gate_and_rule_recorded": True},
            "Every decision records the gate and rule that made it. Full when "
            "decisions also carry portable signed receipts a third party can "
            "verify without this platform."),
    }


def build(framework: str, days: int, ctrl: dict) -> dict:
    """Generate one framework's report from AGT, backed by live evidence.

    A fresh engine per report on purpose: ``check_compliance`` accumulates
    violations on the instance, so a long-lived engine would report a control as
    failing long after it was fixed.
    """
    fw = FRAMEWORKS.get(framework)
    if fw is None:
        raise ValueError(f"Unknown framework '{framework}'. "
                         f"Expected one of {', '.join(sorted(FRAMEWORKS))}.")

    # Every framework, so AGT loads all eight controls rather than SOC2 alone.
    engine = ComplianceEngine(frameworks=list(ComplianceFramework))
    assessed = _assess(ctrl)

    controls = []
    for control_id, control in sorted(engine._controls.items()):
        if control.framework != fw:
            continue
        finding = assessed.get(control_id)
        if finding is None:
            # A control AGT knows and this platform has no evidence for. Saying
            # so is the point; scoring it as met would be an invention.
            finding = {"status": NOT_EVIDENCED, "evidence": {},
                       "note": "This platform holds no evidence for this control."}
        controls.append({
            "control_id": control_id,
            "name": control.name,
            "description": control.description,
            "category": control.category,
            "requirements": list(control.requirements or []),
            **finding,
        })
        if finding["status"] != MET:
            # A real AGT violation, so it reaches the score and the
            # recommendations rather than being a note beside them.
            engine._violations.append(ComplianceViolation(
                violation_id=f"viol_{uuid.uuid4().hex[:12]}",
                agent_did="platform",
                action_type="governance_posture",
                control_id=control_id,
                framework=fw,
                severity=_SEVERITY.get(finding["status"], "medium"),
                description=finding["note"],
                evidence=finding["evidence"],
            ))

    now = _dt.datetime.now(_dt.timezone.utc)
    report = engine.generate_report(fw, now - _dt.timedelta(days=max(1, days)), now)

    counts = {s: sum(1 for c in controls if c["status"] == s)
              for s in (MET, PARTIAL, NOT_EVIDENCED)}
    return {
        "framework": fw.value,
        "report_id": report.report_id,
        "generated_at": report.generated_at.isoformat(),
        "period_start": report.period_start.isoformat(),
        "period_end": report.period_end.isoformat(),
        "period_days": max(1, days),
        # AGT's own arithmetic, under its own names.
        "total_controls": report.total_controls,
        "controls_met": report.controls_met,
        "controls_failed": report.controls_failed,
        "compliance_score": round(report.compliance_score, 1) if report.total_controls else None,
        "recommendations": list(report.recommendations or []),
        # A score over zero controls is not a score. Say assessed=False rather
        # than reporting 100%, which is what AGT does unaided.
        "assessed": report.total_controls > 0,
        "controls_partial": counts[PARTIAL],
        "controls_not_evidenced": counts[NOT_EVIDENCED],
        "controls": controls,
        "basis": (
            "Evidence-backed self-assessment of this running instance. AGT owns "
            "the control catalogue, the report and the score; the evidence for "
            "each control is read from live platform state. Only fully-evidenced "
            "controls count toward the score. This is not a certification."
        ),
    }
