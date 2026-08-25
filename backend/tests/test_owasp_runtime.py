"""OWASP self-assessment reflects the controls actually enabled.

GET /compliance/owasp is not a static table: it snapshots the live security
posture of the running instance and recomputes the enforcement status of the
risks that depend on configuration. Toggling a control (attestation, auth) is
observable in the report, which is the point — it reports reality, not a claim.
"""

import main


def _coverage(client):
    return {c["id"]: c for c in client.get("/compliance/owasp").json()["coverage"]}


def test_runtime_controls_snapshot_is_present(client):
    d = client.get("/compliance/owasp").json()
    ctrls = d["runtime_controls"]
    for key in ("authentication", "jwt_validation", "attestation_required",
                "durable_state", "durable_slo", "durable_audit",
                "cors_allowlist", "kill_switch", "merkle_audit_chain"):
        assert key in ctrls


def test_default_posture_leaves_identity_and_autonomy_partial(client):
    d = client.get("/compliance/owasp").json()
    assert d["runtime_controls"]["attestation_required"] is False
    assert d["runtime_controls"]["authentication"] is False
    cov = _coverage(client)
    assert cov["ASI-03"]["status"] == "partial"
    assert cov["ASI-09"]["status"] == "partial"


def test_requiring_attestation_promotes_identity_to_enforced(client, monkeypatch):
    monkeypatch.setenv("AGT_REQUIRE_ATTESTATION", "1")
    d = client.get("/compliance/owasp").json()
    assert d["runtime_controls"]["attestation_required"] is True
    assert _coverage(client)["ASI-03"]["status"] == "enforced"


def test_enabling_auth_promotes_autonomy_to_enforced(client, monkeypatch):
    monkeypatch.setenv("AGT_API_KEYS", "tok:svc:acme:admin")
    main.reload_auth()
    try:
        # With auth on, every request needs the bearer token.
        headers = {"Authorization": "Bearer tok"}
        d = client.get("/compliance/owasp", headers=headers).json()
        assert d["runtime_controls"]["authentication"] is True
        cov = {c["id"]: c for c in d["coverage"]}
        assert cov["ASI-09"]["status"] == "enforced"
    finally:
        monkeypatch.delenv("AGT_API_KEYS", raising=False)
        main.reload_auth()


def test_statuses_stay_honest_enforcement_states(client):
    cov = client.get("/compliance/owasp").json()["coverage"]
    statuses = {c["status"] for c in cov}
    assert statuses <= {"enforced", "partial", "not_implemented"}
