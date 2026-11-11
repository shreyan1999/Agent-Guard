"""Framework compliance reports, scored from evidence rather than from silence.

AGT's `ComplianceEngine` owns the controls, the report and the arithmetic. Left
alone it reports every framework as 100% compliant — its `_check_control` only
fires for HIPAA and GDPR contexts this platform never produces, and a framework
with *no controls loaded* scores 100% over zero controls. These tests pin the
work that makes the number mean something: each control assessed against live
platform state, anything not fully evidenced recorded as a real violation, and
nothing claimed for a framework that was never assessed.
"""

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


@pytest.fixture
def hardened(tmp_path, monkeypatch):
    """An instance with the opt-in controls actually turned on."""
    monkeypatch.setenv("AGT_API_KEYS", "k:admin:acme:admin")
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    monkeypatch.setenv("AGT_REQUIRE_APPROVAL", "1")
    monkeypatch.setenv("AGT_AUDIT_FILE", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGT_AUDIT_KEY", "key")
    main.reload_auth()
    main.reset_state()
    c = TestClient(main.app)
    h = {"Authorization": "Bearer k"}
    for _ in range(3):
        c.post("/tools/call", json={"tool_name": "db_query", "agent_id": "research-agent"},
               headers=h)
    yield c, h
    for var in ("AGT_API_KEYS", "AGT_REQUIRE_ATTESTATION", "AGT_REQUIRE_APPROVAL",
                "AGT_AUDIT_FILE", "AGT_AUDIT_KEY"):
        monkeypatch.delenv(var, raising=False)
    main.reload_auth()
    main.reset_state()


def _report(client, framework="soc2", headers=None, **kw):
    q = "&".join(f"{k}={v}" for k, v in kw.items())
    return client.get(f"/compliance/report?framework={framework}" + (f"&{q}" if q else ""),
                      headers=headers or {}).json()


def _status(report):
    return {c["control_id"]: c["status"] for c in report["controls"]}


# ── The catalogue is AGT's ───────────────────────────────────────────────────

def test_every_framework_has_controls_loaded(client):
    """The default engine loads SOC2 only, which is why the report builds one
    with every framework enabled — otherwise GDPR would score 100% over zero
    controls."""
    body = client.get("/compliance/frameworks").json()
    counts = {f["id"]: f["controls"] for f in body["frameworks"]}
    assert set(counts) == {"soc2", "gdpr", "hipaa", "eu_ai_act"}
    assert all(n > 0 for n in counts.values()), counts


def test_each_report_covers_only_its_own_framework(client):
    for fw, expected in (("soc2", {"SOC2-CC6.1", "SOC2-CC7.2"}),
                         ("gdpr", {"GDPR-ART5", "GDPR-ART22"}),
                         ("hipaa", {"HIPAA-164.312(a)(1)", "HIPAA-164.312(b)"}),
                         ("eu_ai_act", {"EUAI-ART9", "EUAI-ART13"})):
        r = _report(client, fw)
        assert set(_status(r)) == expected
        assert r["assessed"] is True
        assert r["total_controls"] == 2


def test_an_unknown_framework_is_refused(client):
    assert client.get("/compliance/report?framework=iso27001").status_code == 400


# ── The score responds to what the instance actually does ────────────────────

def test_the_open_playground_does_not_score_full_marks(client):
    """Shipped with no auth, no attestation and no durable audit — a report
    saying otherwise would be the failure this whole module exists to avoid."""
    for fw in ("soc2", "hipaa"):
        r = _report(client, fw)
        assert r["compliance_score"] < 100.0, fw
        assert r["controls_met"] < r["total_controls"], fw


def test_access_control_is_not_evidenced_without_auth(client):
    r = _report(client, "hipaa")
    control = next(c for c in r["controls"] if c["control_id"] == "HIPAA-164.312(a)(1)")
    assert control["status"] == "not_evidenced"
    assert control["evidence"]["api_authentication"] is False


def test_hardening_the_instance_raises_the_score(hardened):
    """The proof the report reads live state rather than a fixed table."""
    c, h = hardened
    for fw in ("soc2", "hipaa", "gdpr"):
        r = _report(c, fw, headers=h)
        assert r["compliance_score"] == 100.0, (fw, _status(r))


def test_evidence_names_the_thing_that_backs_each_verdict(client):
    r = _report(client, "soc2")
    for control in r["controls"]:
        assert control["evidence"], control["control_id"]
        assert control["note"]


# ── Not evidenced is not the same as compliant ───────────────────────────────

def test_unmet_controls_become_real_violations_and_recommendations(client):
    """A finding that did not reach AGT's score would be a note beside the
    number rather than part of it."""
    r = _report(client, "hipaa")
    assert r["controls_failed"] > 0
    assert r["recommendations"]
    assert any("HIPAA-164.312" in rec for rec in r["recommendations"])


def test_partial_controls_do_not_count_as_met(client):
    r = _report(client, "soc2")
    partial = [c for c in r["controls"] if c["status"] == "partial"]
    assert partial, "expected at least one partially-evidenced control"
    assert r["controls_met"] + r["controls_failed"] == r["total_controls"]
    assert r["controls_met"] == sum(1 for c in r["controls"] if c["status"] == "met")


def test_a_report_is_audited(client):
    r = _report(client, "soc2")
    events = client.get("/audit?limit=100").json()["events"]
    entry = next(e for e in events if e["event_type"] == "compliance.report")
    assert entry["details"]["report_id"] == r["report_id"]
    assert entry["details"]["framework"] == "soc2"


def test_the_report_says_what_it_is_not(client):
    assert "not a certification" in _report(client, "soc2")["basis"]


# ── The shallow-run trap ─────────────────────────────────────────────────────

def test_an_adversarial_run_stopped_at_the_door_is_marked_shallow(client, monkeypatch):
    """With mandatory attestation every unattested vector dies at the identity
    gate, so the run scores a perfect A without policy, ring or the MCP proxy
    ever being consulted."""
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    main.reset_state()
    try:
        c = TestClient(main.app)
        run = c.post("/sre/chaos/run", json={}).json()
        assert run["grade"] == "A" and run["breached"] == 0
        assert run["shallow"] is True
        assert run["reached_decision_gates"] == 0
        assert set(run["gates_that_held"]) <= {"identity", "lifecycle"}
        assert "never consulted" in run["shallow_note"]
    finally:
        monkeypatch.delenv("AGT_REQUIRE_ATTESTATION")
        main.reset_state()


def test_a_shallow_run_cannot_satisfy_the_risk_management_control(client, monkeypatch):
    """Otherwise turning on attestation would buy EU AI Act ART9 outright,
    without a single decision gate being tested."""
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    main.reset_state()
    try:
        c = TestClient(main.app)
        c.post("/sre/chaos/run", json={})
        control = next(x for x in _report(c, "eu_ai_act")["controls"]
                       if x["control_id"] == "EUAI-ART9")
        assert control["status"] == "partial"
        assert control["evidence"]["shallow_run"] is True
    finally:
        monkeypatch.delenv("AGT_REQUIRE_ATTESTATION")
        main.reset_state()


def test_a_run_that_reaches_the_gates_is_not_shallow(client):
    run = client.post("/sre/chaos/run", json={}).json()
    assert run["shallow"] is False
    assert run["reached_decision_gates"] > 0
    assert run["shallow_note"] is None
