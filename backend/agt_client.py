"""Client SDK for the AgentGuard governance gateway.

A real agent embeds this to talk to the platform: register itself (and store the
private key issued once at registration), request inline authorization for a tool
call with a cryptographic attestation, and stream execution telemetry back for
the SLOs.

The SDK is dependency-free by default — the built-in transport uses only the
standard library, so an agent needs nothing beyond Python. Any object exposing
``request(method, url, json=..., headers=...)`` (an ``httpx.Client``, a
``requests.Session`` or a Starlette ``TestClient``) can be injected instead.
Attestation signing uses ``agentmesh.identity`` — the same primitive the server
verifies with — and is only imported when an agent actually signs, so the rest
of the SDK works without the toolkit installed.
"""
from __future__ import annotations

import json as _json
import urllib.error
import urllib.request
from typing import Any, Iterable, Optional


class GovernanceError(RuntimeError):
    """Raised when the gateway rejects a request or is unreachable."""


class _Resp:
    __slots__ = ("status_code", "_body")

    def __init__(self, status_code: int, body: bytes) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return _json.loads(self._body.decode("utf-8")) if self._body else None


class _UrllibSession:
    """Zero-dependency transport with the same shape as httpx/requests/TestClient."""

    def __init__(self, base_url: str = "") -> None:
        self._base = base_url.rstrip("/")

    def request(self, method: str, url: str, json: Any = None,
                headers: Optional[dict] = None) -> _Resp:
        full = url if url.startswith("http") else self._base + url
        data = _json.dumps(json).encode("utf-8") if json is not None else None
        req = urllib.request.Request(full, data=data, method=method.upper())
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req) as resp:  # noqa: S310 (caller-supplied base URL)
                return _Resp(resp.status, resp.read())
        except urllib.error.HTTPError as exc:
            return _Resp(exc.code, exc.read())
        except urllib.error.URLError as exc:
            raise GovernanceError(f"{method} {full} failed: {exc.reason}") from exc


def _sign(private_jwk: dict, nonce: str) -> str:
    """Sign a challenge nonce with the agent's private key (needs the toolkit)."""
    try:
        from agentmesh.identity import AgentIdentity
    except ImportError as exc:  # pragma: no cover - exercised only without AGT
        raise GovernanceError(
            "attestation requires the agent-governance-toolkit package") from exc
    return AgentIdentity.from_jwk(private_jwk).sign(nonce.encode("utf-8"))


class GovernanceClient:
    """A registered agent's handle to the governance gateway."""

    def __init__(self, base_url: str = "", token: Optional[str] = None,
                 session: Any = None, agent_id: Optional[str] = None) -> None:
        self.base_url = base_url
        self.agent_id = agent_id
        self._token = token
        self._private_jwk: Optional[dict] = None
        self._did: Optional[str] = None
        self._session = session if session is not None else _UrllibSession(base_url)

    @property
    def did(self) -> Optional[str]:
        return self._did

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def _call(self, method: str, path: str, payload: Any = None) -> Any:
        resp = self._session.request(method, path, json=payload, headers=self._headers())
        try:
            body = resp.json()
        except Exception:
            body = None
        if resp.status_code >= 400:
            detail = body.get("detail") if isinstance(body, dict) else body
            raise GovernanceError(f"{method} {path} -> {resp.status_code}: {detail}")
        return body

    def register(self, agent_id: Optional[str] = None, name: Optional[str] = None, *,
                 trust_score: float = 0.8, policy: str = "default-policy",
                 owner: str = "unassigned@localhost", purpose: str = "") -> dict:
        """Register with the platform and capture the once-issued private key."""
        aid = agent_id or self.agent_id
        if not aid:
            raise GovernanceError("agent_id is required to register")
        body = self._call("POST", "/agents", {
            "id": aid, "name": name or aid, "trust_score": trust_score,
            "policy": policy, "owner": owner, "purpose": purpose,
        })
        self.agent_id = aid
        identity = body.get("identity") or {}
        self._private_jwk = identity.get("private_jwk")
        self._did = identity.get("did")
        return body

    def attach_identity(self, private_jwk: dict, did: Optional[str] = None) -> None:
        """Reuse a private key stored from a previous registration."""
        self._private_jwk = private_jwk
        if did:
            self._did = did

    def _attestation(self) -> Optional[dict]:
        if not self._private_jwk:
            return None
        challenge = self._call("POST", "/identity/challenge", {"agent_id": self.agent_id})
        nonce = challenge["nonce"]
        return {"nonce": nonce, "signature": _sign(self._private_jwk, nonce)}

    def authorize(self, tool_name: str, *, action: str = "read", input_text: str = "",
                  policy_name: str = "default-policy", attest: bool = True,
                  **kwargs: Any) -> dict:
        """Request an inline allow/deny decision, attaching an attestation if able."""
        if not self.agent_id:
            raise GovernanceError("register or set agent_id before authorizing")
        payload: dict[str, Any] = {
            "tool_name": tool_name, "action": action, "input_text": input_text,
            "policy_name": policy_name, "agent_id": self.agent_id, "kwargs": kwargs,
        }
        if attest:
            attestation = self._attestation()
            if attestation:
                payload["attestation"] = attestation
        return self._call("POST", "/tools/call", payload)

    def report(self, events: Iterable[dict]) -> dict:
        """Stream a batch of execution events into the platform's SLOs and audit note."""
        if not self.agent_id:
            raise GovernanceError("register or set agent_id before reporting")
        return self._call("POST", "/ingest/events",
                          {"agent_id": self.agent_id, "events": list(events)})

    def report_call(self, tool: str, *, action: str = "read", allowed: bool = True,
                    latency_ms: float = 0.0, policy_denied: bool = False,
                    error: Optional[str] = None) -> dict:
        """Report a single execution event."""
        return self.report([{
            "tool": tool, "action": action, "allowed": allowed,
            "latency_ms": latency_ms, "policy_denied": policy_denied, "error": error,
        }])

    def signal(self, success: bool = True) -> dict:
        """Record an out-of-band success/failure signal for the agent's SLO."""
        if not self.agent_id:
            raise GovernanceError("register or set agent_id before signalling")
        flag = "true" if success else "false"
        return self._call("POST", f"/sre/signal/{self.agent_id}?success={flag}")
