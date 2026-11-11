"""Who is calling, and has this exact call arrived before.

``agent_os.mcp_session_auth`` gives a caller a short-lived token bound to one
agent, so identity can be proved once rather than re-attested on every call.
``agent_os.mcp_message_signer`` gives the call API a nonce, a timestamp window
and an HMAC, so a captured request cannot simply be sent again.

The second is applied to this platform's own ``POST /tools/call`` rather than to
outbound MCP traffic, and that is a deliberate repurposing. AgentGuard is an MCP
*client*: the third-party servers it calls have never heard of an AgentGuard
signature and would not check one, so signing outbound messages would produce a
header nobody verifies. The threat that is real sits on the near side — a
replayed governed call passes every gate again, correctly, because it genuinely
is a valid request that already happened.

Both are inert until used and both fail closed once used. The tests below insist
on that asymmetry in particular: presenting a *broken* credential must be worse
than presenting none, which is the position the attestation gate beside them
already takes.
"""

import json

import pytest
from starlette.testclient import TestClient

import main
import mcp_caller_auth as auth
from mcp_caller_auth import CallerRejected, CallerSessions, CallSigner

from test_mcp_connector import _import, mcp_server  # noqa: F401

AGENT = "research-agent"


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def signed_post(client, body: dict, agent: str = AGENT, *, signer=None,
                headers: dict = None):
    """Send a call as a client would: canonical bytes, signed, sent verbatim."""
    payload = auth.canonical_payload(body)
    sent = dict((headers if headers is not None
                 else (signer or main._call_signer).sign(payload, agent)))
    sent["Content-Type"] = "application/json"
    return client.post("/tools/call", content=payload.encode("utf-8"),
                       headers=sent)


# ── caller sessions ───────────────────────────────────────────────────────────

def test_a_token_validates_only_for_the_agent_it_names():
    """The binding is the control. A live token that worked for any agent
    would be a worse credential than the self-asserted name it replaces."""
    sessions = CallerSessions()
    token = sessions.mint(AGENT)["token"]
    sessions.validate(AGENT, token)
    with pytest.raises(CallerRejected) as refused:
        sessions.validate("other-agent", token)
    assert refused.value.rule == "mcp_session:invalid"


def test_a_bogus_token_is_refused():
    sessions = CallerSessions()
    with pytest.raises(CallerRejected):
        sessions.validate(AGENT, "not-a-real-token")


def test_a_revoked_token_stops_working():
    sessions = CallerSessions()
    token = sessions.mint(AGENT)["token"]
    assert sessions.revoke(token) is True
    with pytest.raises(CallerRejected):
        sessions.validate(AGENT, token)


def test_revoking_an_agent_drops_all_of_its_tokens():
    sessions = CallerSessions()
    tokens = [sessions.mint(AGENT)["token"] for _ in range(3)]
    assert sessions.revoke_all(AGENT) == 3
    for token in tokens:
        with pytest.raises(CallerRejected):
            sessions.validate(AGENT, token)


def test_the_concurrent_ceiling_is_enforced(monkeypatch):
    monkeypatch.setenv("AGT_MCP_MAX_SESSIONS", "2")
    sessions = CallerSessions()
    sessions.mint(AGENT)
    sessions.mint(AGENT)
    with pytest.raises(RuntimeError):
        sessions.mint(AGENT)


def test_an_expired_token_is_refused(monkeypatch):
    """TTL is real, not decorative."""
    from datetime import timedelta
    sessions = CallerSessions()
    sessions._auth.session_ttl = timedelta(seconds=-1)   # already elapsed
    token = sessions.mint(AGENT)["token"]
    with pytest.raises(CallerRejected):
        sessions.validate(AGENT, token)


# ── sessions through the API ──────────────────────────────────────────────────

def test_minting_returns_a_token_and_its_expiry(client):
    body = client.post("/mcp/sessions", json={"agent_id": AGENT}).json()
    assert body["token"] and body["agent_id"] == AGENT
    assert body["expires_at"] and body["ttl_seconds"] > 0


def test_minting_for_an_unknown_agent_is_a_404(client):
    assert client.post("/mcp/sessions",
                       json={"agent_id": "ghost"}).status_code == 404


def test_a_failed_attestation_refuses_the_token(client):
    """A token must never be easier to obtain than the identity it stands for."""
    r = client.post("/mcp/sessions", json={
        "agent_id": AGENT,
        "attestation": {"nonce": "abc", "signature": "not-a-signature"}})
    assert r.status_code == 403


def test_a_presented_token_is_honoured(client):
    token = client.post("/mcp/sessions", json={"agent_id": AGENT}).json()["token"]
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": AGENT,
        "mcp_session_token": token}).json()
    assert res["allowed"] is True
    assert res["identity_verified"] is True


def test_a_broken_token_is_worse_than_no_token(client):
    """No token is the legacy self-asserted path and still works. A *wrong*
    token is a claim that failed, and fails the call."""
    without = client.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": AGENT}).json()
    assert without["allowed"] is True

    with_bad = client.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": AGENT,
        "mcp_session_token": "forged"}).json()
    assert with_bad["allowed"] is False
    assert with_bad["rule"] == "mcp_session:invalid"


def test_a_token_for_one_agent_cannot_act_as_another(client):
    client.post("/agents", json={"id": "second", "name": "second",
                                 "trust_score": 0.9})
    token = client.post("/mcp/sessions", json={"agent_id": AGENT}).json()["token"]
    res = client.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": "second",
        "mcp_session_token": token}).json()
    assert res["allowed"] is False


def test_requiring_a_session_applies_to_mcp_tools(client, mcp_server, monkeypatch):
    _import(client, mcp_server[1], tools=["echo"])
    monkeypatch.setenv("AGT_REQUIRE_MCP_SESSION", "1")

    refused = client.post("/tools/call", json={
        "tool_name": "mcp.demo-notes.echo", "agent_id": AGENT,
        "kwargs": {"arguments": {"text": "hi"}}}).json()
    assert refused["allowed"] is False
    assert refused["rule"] == "mcp_session:required"

    token = client.post("/mcp/sessions", json={"agent_id": AGENT}).json()["token"]
    allowed = client.post("/tools/call", json={
        "tool_name": "mcp.demo-notes.echo", "agent_id": AGENT,
        "mcp_session_token": token,
        "kwargs": {"arguments": {"text": "hi"}}}).json()
    assert allowed["allowed"] is True


def test_requiring_a_session_leaves_other_tools_alone(client, monkeypatch):
    """The flag says MCP. A webhook tool is decided by the gates it always was."""
    monkeypatch.setenv("AGT_REQUIRE_MCP_SESSION", "1")
    res = client.post("/tools/call", json={"tool_name": "db_query",
                                           "agent_id": AGENT}).json()
    assert res["allowed"] is True


def test_killing_an_agent_revokes_its_tokens(client):
    """A suspended agent still holding a live credential is a kill switch that
    does not switch anything off."""
    token = client.post("/mcp/sessions", json={"agent_id": AGENT}).json()["token"]
    killed = client.post(f"/sre/kill/{AGENT}").json()
    assert killed["sessions_revoked"] == 1
    with pytest.raises(CallerRejected):
        main._mcp_callers.validate(AGENT, token)


def test_revoking_an_unknown_token_is_a_404(client):
    assert client.delete("/mcp/sessions/nope").status_code == 404


# ── replay protection ─────────────────────────────────────────────────────────

def test_a_signed_call_is_accepted_once():
    signer = CallSigner()
    payload = auth.canonical_payload({"tool_name": "db_query"})
    headers = signer.sign(payload, AGENT)
    signer.verify(payload=payload, sender_id=AGENT,
                  nonce=headers[auth.NONCE_HEADER],
                  timestamp=headers[auth.TIMESTAMP_HEADER],
                  signature=headers[auth.SIGNATURE_HEADER])


def test_the_same_call_sent_twice_is_refused():
    """The signature proves the request is authentic; the nonce proves it is
    not the same authentic request twice."""
    signer = CallSigner()
    payload = auth.canonical_payload({"tool_name": "db_query"})
    headers = signer.sign(payload, AGENT)
    kwargs = dict(payload=payload, sender_id=AGENT,
                  nonce=headers[auth.NONCE_HEADER],
                  timestamp=headers[auth.TIMESTAMP_HEADER],
                  signature=headers[auth.SIGNATURE_HEADER])
    signer.verify(**kwargs)
    with pytest.raises(CallerRejected) as refused:
        signer.verify(**kwargs)
    assert refused.value.rule == "call_signature:replay"


def test_an_altered_body_breaks_the_signature():
    signer = CallSigner()
    payload = auth.canonical_payload({"tool_name": "db_query", "action": "read"})
    headers = signer.sign(payload, AGENT)
    with pytest.raises(CallerRejected) as refused:
        signer.verify(
            payload=auth.canonical_payload({"tool_name": "db_query",
                                            "action": "delete"}),
            sender_id=AGENT, nonce=headers[auth.NONCE_HEADER],
            timestamp=headers[auth.TIMESTAMP_HEADER],
            signature=headers[auth.SIGNATURE_HEADER])
    assert refused.value.rule == "call_signature:invalid"


def test_a_stale_timestamp_is_outside_the_window():
    signer = CallSigner()
    payload = auth.canonical_payload({"tool_name": "db_query"})
    headers = signer.sign(payload, AGENT)
    with pytest.raises(CallerRejected):
        signer.verify(payload=payload, sender_id=AGENT,
                      nonce=headers[auth.NONCE_HEADER],
                      timestamp="1000000000000",     # 2001
                      signature=headers[auth.SIGNATURE_HEADER])


@pytest.mark.parametrize("missing", [auth.NONCE_HEADER, auth.TIMESTAMP_HEADER])
def test_a_partial_signature_is_refused(missing):
    signer = CallSigner()
    payload = auth.canonical_payload({"tool_name": "db_query"})
    headers = dict(signer.sign(payload, AGENT))
    headers[missing] = ""
    with pytest.raises(CallerRejected) as refused:
        signer.verify(payload=payload, sender_id=AGENT,
                      nonce=headers[auth.NONCE_HEADER],
                      timestamp=headers[auth.TIMESTAMP_HEADER],
                      signature=headers[auth.SIGNATURE_HEADER])
    assert refused.value.rule == "call_signature:incomplete"


def test_a_non_numeric_timestamp_is_refused():
    signer = CallSigner()
    payload = auth.canonical_payload({"tool_name": "db_query"})
    headers = signer.sign(payload, AGENT)
    with pytest.raises(CallerRejected) as refused:
        signer.verify(payload=payload, sender_id=AGENT,
                      nonce=headers[auth.NONCE_HEADER], timestamp="yesterday",
                      signature=headers[auth.SIGNATURE_HEADER])
    assert refused.value.rule == "call_signature:timestamp"


def test_a_short_pinned_key_is_refused(monkeypatch):
    """AGT requires 32 bytes. Accepting less would be a key that looks like a
    key."""
    import base64
    monkeypatch.setenv("AGT_CALL_SIGNING_KEY",
                       base64.b64encode(b"tooshort").decode())
    with pytest.raises(ValueError):
        CallSigner()


# ── replay protection through the API ─────────────────────────────────────────

def test_an_unsigned_call_still_works(client):
    """Inert unless used: every existing caller is unaffected."""
    assert client.post("/tools/call", json={
        "tool_name": "db_query", "agent_id": AGENT}).json()["allowed"] is True


def test_a_signed_call_is_accepted_and_its_replay_is_not(client):
    body = {"tool_name": "db_query", "agent_id": AGENT}
    payload = auth.canonical_payload(body)
    headers = main._call_signer.sign(payload, AGENT)

    first = signed_post(client, body, headers=headers).json()
    assert first["allowed"] is True

    replayed = signed_post(client, body, headers=headers).json()
    assert replayed["allowed"] is False
    assert replayed["rule"] == "call_signature:replay"
    assert replayed["denied_by"] == "signature"


def test_a_forged_signature_is_refused(client):
    body = {"tool_name": "db_query", "agent_id": AGENT}
    headers = main._call_signer.sign(auth.canonical_payload(body), AGENT)
    headers[auth.SIGNATURE_HEADER] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    res = signed_post(client, body, headers=headers).json()
    assert res["allowed"] is False
    assert res["rule"] == "call_signature:invalid"


def test_requiring_a_signature_refuses_an_unsigned_call(client, monkeypatch):
    monkeypatch.setenv("AGT_REQUIRE_CALL_SIGNATURE", "1")
    res = client.post("/tools/call", json={"tool_name": "db_query",
                                           "agent_id": AGENT}).json()
    assert res["allowed"] is False
    assert res["rule"] == "call_signature:incomplete"


def test_the_signing_parameters_are_published(client):
    body = client.get("/mcp/signing-parameters").json()
    assert body["algorithm"] == "HMAC-SHA256"
    assert body["canonical_form"] == "nonce|timestamp_ms|sender_id|payload"
    assert set(body["headers"]) == {"nonce", "timestamp", "signature"}
    # The key is the secret; the recipe is not. Asserted against the actual key
    # material rather than the word "key", which legitimately appears in
    # "sorted keys".
    import base64
    published = json.dumps(body)
    assert base64.b64encode(main._call_signer._key).decode() not in published
    assert main._call_signer._key.hex() not in published


def test_the_in_process_callers_are_untouched(client, monkeypatch):
    """The demo seeder and chaos runner call call_tool() directly. They never
    crossed a network, so there is no captured request to replay — and
    requiring a signature of them would break the shipped demo."""
    monkeypatch.setenv("AGT_REQUIRE_CALL_SIGNATURE", "1")
    outcome = main.call_tool(
        main.ToolCallIn(tool_name="db_query", agent_id=AGENT),
        main.Principal(subject="test", tenant="default",
                       roles=frozenset({"admin"})))
    assert outcome["allowed"] is True


# ── the report ────────────────────────────────────────────────────────────────

def test_both_controls_report_themselves(client):
    gates = {c["gate"]: c for c in client.get("/mcp/controls").json()["controls"]}
    assert gates["identity"]["control"].endswith("MCPSessionAuthenticator")
    assert gates["signature"]["control"].endswith("MCPMessageSigner")
    assert gates["signature"]["applies_to"] == "this platform's own POST /tools/call"
    # The honest note about why it is not on outbound MCP traffic.
    assert "do not verify" in gates["signature"]["note"]
