"""Who is making this call, and has this exact call been made before.

The two remaining AGT MCP controls, and the two that needed the most thought
about where they honestly belong.

**Sessions** — ``agent_os.mcp_session_auth.MCPSessionAuthenticator``. A caller
names its ``agent_id`` in the request body. Unless it also presents a signed
attestation, that name is self-asserted: the identity gate verifies a signature
when one is offered and otherwise takes the caller's word. Attestation is
challenge–response, so proving identity on *every* call means a round trip
before every call, which is why almost nothing does it. A session token is the
missing middle — attest once, carry a short-lived opaque token afterwards. AGT
supplies expiry, a concurrent-session ceiling per agent, and revocation, which
is what makes killing an agent actually stop its in-flight credentials.

This is **not** the session in ``sessions.py``. That one is an AGT Hypervisor
session: a shared workspace with participants and an execution ring, opened by
``POST /sessions``, and it answers "what may happen inside this collaboration".
This one answers "is the caller who it says it is". They are orthogonal, they
have separate lifecycles, and a call may have either, both or neither.

**Replay** — ``agent_os.mcp_message_signer.MCPMessageSigner``. Applied to
AgentGuard's own API rather than to outbound MCP traffic, and that difference is
worth being plain about. The module is built for signing MCP messages between
peers, but AgentGuard is an MCP *client*: the servers it calls are third
parties that have never heard of an AgentGuard signature and would not check
one. Signing outbound messages would produce a header nobody verifies, and a
control nobody verifies is decoration.

What is real is the threat on the near side. ``POST /tools/call`` executes a
governed action with side effects. Anyone who can capture one request can send
it again, and every gate will pass it again, because it is genuinely a valid
request — it simply already happened. A nonce, a timestamp window and an HMAC
over the body is precisely the shape of that problem, and that is exactly what
``MCPMessageSigner`` implements. So the primitive is used for what it does
rather than for the transport it was named after.

Both are off unless configured, and both fail closed once on. A caller that
presents a bad token or a bad signature is refused — presenting a broken
credential is worse evidence than presenting none, and the identity gate beside
this one already takes that position for attestations.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from agent_os.mcp_message_signer import MCPMessageSigner, MCPSignedEnvelope
from agent_os.mcp_session_auth import MCPSessionAuthenticator

_TRUE = ("1", "true", "yes", "on")

DEFAULT_TTL_MINUTES = 60
DEFAULT_MAX_SESSIONS = 10
DEFAULT_REPLAY_WINDOW_SECONDS = 300

# The headers a signed call carries. Named for the platform rather than for MCP
# because they protect this API, not an MCP transport.
NONCE_HEADER = "x-agentguard-nonce"
TIMESTAMP_HEADER = "x-agentguard-timestamp"
SIGNATURE_HEADER = "x-agentguard-signature"


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


def require_session() -> bool:
    """True when an MCP call must carry a session token to be dispatched."""
    return os.getenv("AGT_REQUIRE_MCP_SESSION", "").strip().lower() in _TRUE


def require_signature() -> bool:
    """True when every governed call must be signed."""
    return os.getenv("AGT_REQUIRE_CALL_SIGNATURE", "").strip().lower() in _TRUE


class CallerRejected(Exception):
    """Raised when a presented credential does not hold up."""

    def __init__(self, reason: str, rule: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.rule = rule


class CallerSessions:
    """AGT's ``MCPSessionAuthenticator``, holding tokens bound to agents."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._auth = self._build()

    @staticmethod
    def _build() -> MCPSessionAuthenticator:
        return MCPSessionAuthenticator(
            session_ttl=timedelta(
                minutes=_int_env("AGT_MCP_SESSION_TTL_MINUTES",
                                 DEFAULT_TTL_MINUTES)),
            max_concurrent_sessions=_int_env("AGT_MCP_MAX_SESSIONS",
                                             DEFAULT_MAX_SESSIONS),
        )

    def mint(self, agent_id: str, user_id: Optional[str] = None) -> dict:
        """Issue a session token for an agent.

        The caller decides whether the agent had to prove anything first; this
        only issues. ``/mcp/sessions`` requires an operator credential or a
        verified attestation before it calls here, so the token is never easier
        to obtain than the identity it stands for.
        """
        with self._lock:
            token = self._auth.create_session(agent_id, user_id)
            session = self._auth.validate_token(token)
        return {
            "token": token,
            "agent_id": agent_id,
            "user_id": user_id,
            "expires_at": session.expires_at.isoformat() if session else None,
            "ttl_seconds": int(self._auth.session_ttl.total_seconds()),
        }

    def validate(self, agent_id: str, token: str) -> None:
        """Accept a token for this agent, or raise :class:`CallerRejected`.

        ``validate_session`` checks that the token is live *and* belongs to the
        named agent, so a valid token for agent A cannot be used to act as
        agent B. That binding is the whole point of the control.
        """
        with self._lock:
            session = self._auth.validate_session(agent_id, token)
        if session is None:
            raise CallerRejected(
                "MCP session token is invalid, expired, or belongs to a "
                "different agent.", "mcp_session:invalid")

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._auth.revoke_session(token)

    def revoke_all(self, agent_id: str) -> int:
        """Drop every session an agent holds.

        Called when an agent is killed or deleted: a suspended agent still
        holding a live token is a kill switch that does not switch anything off.
        """
        with self._lock:
            return self._auth.revoke_all_sessions(agent_id)

    def active_count(self) -> int:
        with self._lock:
            return self._auth.active_session_count

    def describe(self) -> dict:
        return {
            "control": "agent_os.mcp_session_auth.MCPSessionAuthenticator",
            "required": require_session(),
            "ttl_seconds": int(self._auth.session_ttl.total_seconds()),
            "max_concurrent_per_agent": self._auth.max_concurrent_sessions,
            "active": self.active_count(),
            "note": "Distinct from the Hypervisor sessions at /sessions, which "
                    "carry an execution ring and participants rather than "
                    "caller identity.",
        }

    def clear(self) -> None:
        with self._lock:
            self._auth = self._build()


# ── Replay protection over this platform's own call API ──────────────────────

def _load_or_create_key(path: Optional[Path]) -> bytes:
    """The HMAC key callers sign with, as raw bytes.

    Pinned with ``AGT_CALL_SIGNING_KEY`` (base64, at least 32 bytes decoded),
    otherwise generated. A generated key is persisted when ``AGT_STATE_DIR`` is
    set, so signatures keep verifying across a restart; without it the key is
    per-process and every caller has to fetch the new one. That mirrors how the
    receipt signer handles the same problem.
    """
    pinned = os.getenv("AGT_CALL_SIGNING_KEY", "").strip()
    if pinned:
        try:
            decoded = base64.b64decode(pinned.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
            raise ValueError(
                "AGT_CALL_SIGNING_KEY must be base64-encoded") from exc
        if len(decoded) < 32:
            raise ValueError(
                "AGT_CALL_SIGNING_KEY must decode to at least 32 bytes")
        return decoded
    if path and path.exists():
        try:
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                return base64.b64decode(stored.encode("ascii"), validate=True)
        except (OSError, binascii.Error, ValueError):
            pass
    key = secrets.token_bytes(32)
    if path:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(base64.b64encode(key).decode("ascii"),
                            encoding="utf-8")
        except OSError:
            pass
    return key


def canonical_payload(body: dict) -> str:
    """The exact bytes a caller signs.

    Every field of the request is included — the whole validated body, with
    sorted keys and no incidental whitespace — so there is no part of the call a
    signature leaves unprotected. Deriving it from the parsed model rather than
    from the raw request body keeps the endpoint synchronous and makes the
    canonical form something a client can reproduce without matching this
    server's JSON formatting byte for byte.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


class CallSigner:
    """AGT's ``MCPMessageSigner``, guarding this platform's call API."""

    def __init__(self, key_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._key_path = key_path
        self._key = _load_or_create_key(key_path)
        self._signer = self._build()

    def _build(self) -> MCPMessageSigner:
        return MCPMessageSigner(
            self._key,
            replay_window=timedelta(
                seconds=_int_env("AGT_CALL_REPLAY_WINDOW_SECONDS",
                                 DEFAULT_REPLAY_WINDOW_SECONDS)),
        )

    @property
    def public_parameters(self) -> dict:
        """What a client needs in order to sign, minus the key itself."""
        return {
            "algorithm": "HMAC-SHA256",
            "canonical_form": "nonce|timestamp_ms|sender_id|payload",
            "payload": "the request body as compact JSON with sorted keys",
            "headers": {"nonce": NONCE_HEADER, "timestamp": TIMESTAMP_HEADER,
                        "signature": SIGNATURE_HEADER},
            "replay_window_seconds": int(
                self._signer.replay_window.total_seconds()),
        }

    def sign(self, payload: str, sender_id: str) -> dict:
        """Produce the headers a caller would send. For tests and for clients."""
        with self._lock:
            envelope = self._signer.sign_message(payload, sender_id)
        return {
            NONCE_HEADER: envelope.nonce,
            TIMESTAMP_HEADER: str(int(envelope.timestamp.timestamp() * 1000)),
            SIGNATURE_HEADER: envelope.signature,
        }

    def verify(self, *, payload: str, sender_id: str, nonce: str,
               timestamp: str, signature: str) -> None:
        """Accept one signed call, or raise :class:`CallerRejected`.

        A nonce is spent on acceptance, so the identical request sent a second
        time is refused even though it verifies cryptographically. That is the
        control: the signature proves the request is authentic, and the nonce
        proves it is not the same authentic request twice.
        """
        if not (nonce and timestamp and signature):
            raise CallerRejected(
                "A signed call needs all three of "
                f"{NONCE_HEADER}, {TIMESTAMP_HEADER} and {SIGNATURE_HEADER}.",
                "call_signature:incomplete")
        try:
            moment = datetime.fromtimestamp(int(timestamp) / 1000.0,
                                            tz=timezone.utc)
        except (TypeError, ValueError, OSError, OverflowError):
            raise CallerRejected(
                f"{TIMESTAMP_HEADER} must be milliseconds since the epoch.",
                "call_signature:timestamp") from None

        envelope = MCPSignedEnvelope(payload=payload, nonce=nonce,
                                     timestamp=moment, signature=signature,
                                     sender_id=sender_id or None)
        with self._lock:
            result = self._signer.verify_message(envelope)
        if not result.is_valid:
            reason = result.failure_reason or "Signature verification failed."
            rule = ("call_signature:replay" if "Duplicate nonce" in reason
                    else "call_signature:invalid")
            raise CallerRejected(f"Signed call rejected — {reason}", rule)

    def describe(self) -> dict:
        return {
            "control": "agent_os.mcp_message_signer.MCPMessageSigner",
            "required": require_signature(),
            "applies_to": "this platform's own POST /tools/call",
            "replay_window_seconds": int(
                self._signer.replay_window.total_seconds()),
            "tracked_nonces": self._signer.cached_nonce_count,
            "note": "Not applied to outbound MCP traffic: the third-party "
                    "servers AgentGuard calls do not verify an AgentGuard "
                    "signature, and an unverified signature is not a control.",
        }

    def clear(self) -> None:
        """Rebuild the signer, dropping spent nonces.

        The key is deliberately kept: a test or a restart that invalidated every
        outstanding signature would make the control impossible to exercise
        across a reset, and the nonce cache is the part that must not leak
        between tests.
        """
        with self._lock:
            self._signer = self._build()
