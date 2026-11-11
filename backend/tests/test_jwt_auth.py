"""Static HS256 JWT bearer validation.

Set AGT_JWT_SECRET and the platform accepts JSON Web Tokens signed with that
shared secret as an alternative to static API keys. The signature is verified
with the standard library (constant-time HMAC-SHA256), `exp`/`nbf` are honoured
and the principal is read from the token's claims. This is a deliberately
static verifier — HS256 only, one secret, no OIDC discovery or key rotation.
Those tokens minted here are signed the same real way the verifier checks them.
"""

import base64
import hashlib
import hmac
import json
import os
import time

import pytest
from starlette.testclient import TestClient

import main

SECRET = "test-shared-secret-value"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _mint(claims, *, secret=SECRET, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    h = _b64(json.dumps(header).encode("utf-8"))
    p = _b64(json.dumps(claims).encode("utf-8"))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = b"" if alg == "none" else hmac.new(
        secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def jwt_client(monkeypatch):
    main.reset_state()
    monkeypatch.setenv("AGT_JWT_SECRET", SECRET)
    main.reload_auth()
    try:
        yield TestClient(main.app)
    finally:
        monkeypatch.delenv("AGT_JWT_SECRET", raising=False)
        main.reload_auth()
        main.teardown_state(clear_policies=True)


def test_valid_jwt_is_accepted(jwt_client):
    token = _mint({"sub": "svc", "tenant": "acme", "roles": ["operator"]})
    assert jwt_client.get("/agents", headers=_auth(token)).status_code == 200


def test_jwt_roles_are_enforced(jwt_client):
    viewer = _mint({"sub": "v", "tenant": "acme", "roles": ["viewer"]})
    # Creating an agent needs operator; a viewer JWT is authenticated but denied.
    r = jwt_client.post("/agents", headers=_auth(viewer),
                        json={"id": "x", "name": "x"})
    assert r.status_code == 403


def test_operator_jwt_can_create_an_agent(jwt_client):
    op = _mint({"sub": "svc", "tenant": "acme", "roles": ["operator"]})
    r = jwt_client.post("/agents", headers=_auth(op),
                       json={"id": "jwt-made", "name": "jwt-made"})
    assert r.status_code in (200, 201)


def test_wrong_secret_is_rejected(jwt_client):
    forged = _mint({"sub": "svc", "roles": ["admin"]}, secret="not-the-secret")
    assert jwt_client.get("/agents", headers=_auth(forged)).status_code == 401


def test_alg_none_is_rejected(jwt_client):
    token = _mint({"sub": "svc", "roles": ["admin"]}, alg="none")
    assert jwt_client.get("/agents", headers=_auth(token)).status_code == 401


def test_expired_jwt_is_rejected(jwt_client):
    token = _mint({"sub": "svc", "roles": ["operator"], "exp": time.time() - 10})
    assert jwt_client.get("/agents", headers=_auth(token)).status_code == 401


def test_not_yet_valid_jwt_is_rejected(jwt_client):
    token = _mint({"sub": "svc", "roles": ["operator"], "nbf": time.time() + 3600})
    assert jwt_client.get("/agents", headers=_auth(token)).status_code == 401


def test_jwt_without_known_roles_is_rejected(jwt_client):
    token = _mint({"sub": "svc", "tenant": "acme", "roles": ["superuser"]})
    assert jwt_client.get("/agents", headers=_auth(token)).status_code == 401


def test_jwt_without_subject_is_rejected(jwt_client):
    token = _mint({"tenant": "acme", "roles": ["operator"]})
    assert jwt_client.get("/agents", headers=_auth(token)).status_code == 401


def test_issuer_and_audience_are_enforced_when_configured(monkeypatch):
    main.reset_state()
    monkeypatch.setenv("AGT_JWT_SECRET", SECRET)
    monkeypatch.setenv("AGT_JWT_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGT_JWT_AUDIENCE", "agentguard")
    main.reload_auth()
    try:
        client = TestClient(main.app)
        good = _mint({"sub": "svc", "roles": ["operator"],
                      "iss": "https://issuer.example", "aud": "agentguard"})
        wrong_iss = _mint({"sub": "svc", "roles": ["operator"],
                           "iss": "https://evil.example", "aud": "agentguard"})
        assert client.get("/agents", headers=_auth(good)).status_code == 200
        assert client.get("/agents", headers=_auth(wrong_iss)).status_code == 401
    finally:
        monkeypatch.delenv("AGT_JWT_SECRET", raising=False)
        monkeypatch.delenv("AGT_JWT_ISSUER", raising=False)
        monkeypatch.delenv("AGT_JWT_AUDIENCE", raising=False)
        main.reload_auth()
        main.teardown_state(clear_policies=True)
