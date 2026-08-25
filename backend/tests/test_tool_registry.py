"""Real tool onboarding and evaluation.

A tool onboarded through /tools/register is governed exactly like the built-ins.
When it declares an HTTP(S) endpoint, an allowed call *really* invokes it: these
tests stand up an actual local HTTP server and assert the true status, body and
outcome flow back, that governance still gates the call, and that the SSRF guard
blocks unsafe targets. Nothing here is mocked or simulated.
"""

import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


# ── A real local webhook the governed call can actually hit ──────────────────
class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        code = getattr(self.server, "reply_code", 200)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        payload = {"echo": json.loads(raw or b"{}"), "code": code}
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture
def webhook(monkeypatch):
    """A live loopback HTTP server; loopback is SSRF-blocked unless allowed."""
    monkeypatch.setenv("AGT_TOOL_ALLOW_PRIVATE", "1")
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    server.reply_code = 200
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/hook"
    try:
        yield server, url
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def state_dir(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="agt-tools-"))
    monkeypatch.setenv("AGT_STATE_DIR", str(d))
    main.reset_state()
    try:
        yield d
    finally:
        monkeypatch.delenv("AGT_STATE_DIR", raising=False)
        main.reset_state()


def _register(client, **kwargs):
    body = {"name": "payments_api", "risk": "high"}
    body.update(kwargs)
    return client.post("/tools/register", json=body)


# ── Registry basics ──────────────────────────────────────────────────────────

def test_builtin_tools_are_seeded(client):
    r = client.get("/tools").json()
    assert {"db_query", "send_email", "web_search", "write_file"} <= set(r["available"])
    builtin = {t["name"]: t for t in r["registered"]}
    assert builtin["db_query"]["builtin"] is True
    assert builtin["db_query"]["endpoint_url"] is None


def test_available_is_registry_driven_not_hardcoded(client):
    before = set(client.get("/tools").json()["available"])
    _register(client, name="fresh_tool", risk="low")
    after = set(client.get("/tools").json()["available"])
    assert "fresh_tool" in after and "fresh_tool" not in before


def test_onboard_decision_only_tool(client):
    r = _register(client, name="ledger", risk="medium",
                  description="post a ledger entry", actions=["read", "post"])
    assert r.status_code == 200
    spec = r.json()
    assert spec["endpoint_url"] is None and spec["actions"] == ["read", "post"]

    call = client.post("/tools/call", json={
        "tool_name": "ledger", "action": "read", "agent_id": "research-agent",
    }).json()
    assert call["allowed"] is True
    assert call["executed"] is False
    assert "no endpoint" in call["result"]["note"].lower()


def test_bad_tool_name_rejected(client):
    assert _register(client, name="bad name!").status_code == 400


def test_bad_risk_rejected(client):
    assert _register(client, name="riskytool", risk="apocalyptic").status_code == 400


# ── SSRF protection ──────────────────────────────────────────────────────────

def test_non_http_scheme_rejected(client):
    r = _register(client, name="filetool", endpoint_url="file:///etc/passwd")
    assert r.status_code == 400
    assert "http" in r.json()["detail"].lower()


def test_private_endpoint_blocked_without_flag(client):
    # AGT_TOOL_ALLOW_PRIVATE is not set: a loopback target must be refused.
    r = _register(client, name="localtool", endpoint_url="http://127.0.0.1:9/hook")
    assert r.status_code == 400
    assert "blocked" in r.json()["detail"].lower()


# ── Real webhook invocation ──────────────────────────────────────────────────

def test_webhook_is_really_invoked(client, webhook):
    _server, url = webhook
    _register(client, name="payments_api", endpoint_url=url, actions=["refund"])
    call = client.post("/tools/call", json={
        "tool_name": "payments_api", "action": "refund",
        "input_text": "order-42", "agent_id": "research-agent",
    }).json()
    assert call["allowed"] is True
    assert call["executed"] is True
    assert call["execution_ok"] is True
    assert call["result"]["http_status"] == 200
    # The real server echoed our payload back.
    echoed = json.loads(call["result"]["response"])["echo"]
    assert echoed["tool"] == "payments_api" and echoed["action"] == "refund"


def test_webhook_failure_is_reported_truthfully(client, webhook):
    server, url = webhook
    server.reply_code = 500
    _register(client, name="flaky_api", endpoint_url=url)
    call = client.post("/tools/call", json={
        "tool_name": "flaky_api", "action": "read", "agent_id": "research-agent",
    }).json()
    assert call["allowed"] is True          # governance allowed it
    assert call["executed"] is True
    assert call["execution_ok"] is False    # but the real call failed
    assert call["result"]["http_status"] == 500


def test_webhook_still_gated_by_governance(client, webhook):
    """A denied call never reaches the endpoint."""
    _server, url = webhook
    _register(client, name="guarded_api", endpoint_url=url)
    # untrusted-agent is below MIN_TRUST, so the trust gate denies first.
    call = client.post("/tools/call", json={
        "tool_name": "guarded_api", "action": "read", "agent_id": "untrusted-agent",
    }).json()
    assert call["allowed"] is False
    assert call["denied_by"] == "trust"
    assert "executed" not in call or call.get("executed") is not True


# ── Deletion ─────────────────────────────────────────────────────────────────

def test_builtin_tool_cannot_be_deleted(client):
    assert client.delete("/tools/db_query").status_code == 400


def test_onboarded_tool_can_be_deleted(client):
    _register(client, name="temp_tool")
    assert client.delete("/tools/temp_tool").status_code == 200
    assert "temp_tool" not in client.get("/tools").json()["available"]


def test_delete_unknown_tool_is_404(client):
    assert client.delete("/tools/nope").status_code == 404


# ── Persistence ──────────────────────────────────────────────────────────────

def test_onboarded_tool_survives_a_restart(client, state_dir):
    _register(client, name="durable_tool", risk="critical",
              description="kept across restarts")
    assert "durable_tool" in main._tools.names()

    # A real restart: rebuild every store from the environment, then re-seed.
    main.teardown_state()
    main.seed_state()

    assert "durable_tool" in main._tools.names()
    spec = main._tools.get("durable_tool")
    assert spec["risk"] == "critical"
