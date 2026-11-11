"""Agent sessions — the ACS ``agent_startup`` and ``agent_shutdown`` points.

The Agent Control Specification evaluates policy at eight points in an agent's
loop. This platform is a tool-call control plane: it implements ``pre_tool_call``
fully and never sees a prompt, so the four model-adjacent points are outside its
architecture rather than missing from it. Two of the remaining ones were simply
absent — there was no session to start or finish. A call arrived, was decided,
and nothing bracketed it.

This supplies that bracket using AGT's own ``Hypervisor`` rather than a session
object invented here. What the toolkit gives, and this does not reimplement:

* a real state machine — CREATED, HANDSHAKING, ACTIVE, TERMINATING, ARCHIVED;
* a handshake that assigns each joining agent an execution ring, registers the
  actions it declares in a ``ReversibilityRegistry``, and forces strong
  consistency when any of them cannot be undone;
* teardown that releases vouching bonds, purges the session VFS and archives.

**On the audit chain, correcting a worry raised earlier in design.**
``terminate_session`` returns what its docstring calls a "hash chain root", which
read like a second, competing evidence chain beside this platform's Merkle log.
It is not. The root is computed over *deltas recorded in the session's own
DeltaEngine* — VFS edits and shared-object mutations — and AgentGuard records
none of those, so it is always ``None`` here and the toolkit's commitment engine
never fires. The two artefacts answer different questions, the way the signed
MCP receipts already do. Session open, join and close are written to this
platform's chain like any other governed event; there is one evidence chain.

**On async.** Every Hypervisor method is a coroutine and every handler here is
sync (FastAPI runs those in a thread pool). Rather than spin a loop per call —
which breaks the moment a handler becomes ``async def`` — this owns one loop on
a daemon thread and submits to it. The public surface is entirely synchronous.

Not used, and worth naming so the omission is a choice: ``verify_behavior`` and
``monitor_sessions`` detect behavioural drift from embeddings this platform does
not compute, so calling them would mean inventing the inputs.
"""

from __future__ import annotations

import asyncio
import threading
import time

import observability

from hypervisor.models import ExecutionRing
from agent_runtime import Hypervisor, SessionConfig

_log = observability.get_logger(__name__)

# AGT's own ceiling on a session, used as the default rather than a number
# chosen here.
DEFAULT_MAX_PARTICIPANTS = 10
DEFAULT_MAX_SECONDS = 3600


class SessionError(RuntimeError):
    """A session could not be opened, joined or closed."""


class _Loop:
    """One event loop on a daemon thread, for calling async AGT from sync code."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run, name="agentguard-sessions", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def call(self, coro, timeout: float = 30.0):
        """Run a coroutine on the loop and wait for it, on the caller's thread."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout)


class SessionManager:
    """AGT's Hypervisor, with a synchronous surface and a readable record.

    The Hypervisor holds the authoritative state; the rows kept here are what
    the API reports — who joined, at which ring, when — because reaching into
    its internals to render a page would couple this to a shape the toolkit is
    free to change.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop = _Loop()
        self._hypervisor = Hypervisor()
        self._rows: dict[str, dict] = {}

    # ── lifecycle ────────────────────────────────────────────────────────
    def open(self, *, creator: str, max_participants: int = DEFAULT_MAX_PARTICIPANTS,
             max_seconds: int = DEFAULT_MAX_SECONDS,
             min_eff_score: float = 0.6) -> dict:
        """ACS ``agent_startup``: begin a session. It is not usable until
        an agent has joined and it has been activated."""
        config = SessionConfig(
            max_participants=int(max_participants),
            max_duration_seconds=int(max_seconds),
            min_eff_score=float(min_eff_score),
        )
        try:
            managed = self._loop.call(
                self._hypervisor.create_session(config, creator_did=creator))
        except Exception as exc:
            raise SessionError(f"Could not open a session: {exc}")

        session_id = managed.sso.session_id
        with self._lock:
            self._rows[session_id] = {
                "session_id": session_id,
                "creator": creator,
                "opened_at": time.time(),
                "closed_at": None,
                "max_participants": config.max_participants,
                "max_duration_seconds": config.max_duration_seconds,
                "participants": {},
            }
        return self.get(session_id)

    def join(self, session_id: str, *, agent_did: str, agent_id: str,
             trust_score: float) -> ExecutionRing:
        """Admit an agent and return the ring AGT assigned it.

        The ring can only be at or below what the trust score alone would give:
        AGT computes it with the same ``from_eff_score`` this platform uses and
        then demotes to sandbox for an agent its history check distrusts. It
        never promotes, and the caller re-applies that floor anyway.
        """
        self._require(session_id)
        try:
            ring = self._loop.call(self._hypervisor.join_session(
                session_id, agent_did, sigma_raw=float(trust_score)))
        except Exception as exc:
            raise SessionError(f"Could not join '{agent_id}': {exc}")

        with self._lock:
            self._rows[session_id]["participants"][agent_id] = {
                "agent_id": agent_id,
                "did": agent_did,
                "trust_score": float(trust_score),
                "ring": ring.value,
                "ring_name": ring.name,
                "joined_at": time.time(),
            }
        return ring

    def activate(self, session_id: str) -> dict:
        """Move a handshaking session to ACTIVE, so calls may be bound to it."""
        self._require(session_id)
        try:
            self._loop.call(self._hypervisor.activate_session(session_id))
        except Exception as exc:
            raise SessionError(f"Could not activate the session: {exc}")
        return self.get(session_id)

    def terminate(self, session_id: str) -> dict:
        """ACS ``agent_shutdown``: archive the session and release what it held.

        AGT releases vouching bonds, garbage-collects the session VFS and
        archives the record. The returned delta root is reported as-is — it is
        ``None`` whenever no deltas were recorded, which is always here, and
        saying so is better than omitting a field that looks like evidence.
        """
        self._require(session_id)
        try:
            root = self._loop.call(self._hypervisor.terminate_session(session_id))
        except Exception as exc:
            raise SessionError(f"Could not terminate the session: {exc}")
        with self._lock:
            row = self._rows.get(session_id)
            if row is not None:
                row["closed_at"] = time.time()
                row["delta_hash_chain_root"] = root
        return self.get(session_id)

    # ── reads ────────────────────────────────────────────────────────────
    def _require(self, session_id: str) -> None:
        with self._lock:
            known = session_id in self._rows
        if not known:
            raise SessionError(f"No such session: {session_id}")

    def state(self, session_id: str) -> "str | None":
        """The toolkit's own state name, read from the Hypervisor."""
        managed = self._hypervisor.get_session(session_id)
        if managed is None:
            return None
        return managed.sso.state.name

    def get(self, session_id: str) -> dict:
        self._require(session_id)
        with self._lock:
            row = dict(self._rows[session_id])
            row["participants"] = list(row["participants"].values())
        row["state"] = self.state(session_id)
        return row

    def all(self) -> list[dict]:
        with self._lock:
            ids = list(self._rows)
        return [self.get(sid) for sid in ids]

    def ring_for(self, session_id: str, agent_id: str) -> "ExecutionRing | None":
        """The ring this session assigned an agent, or None if it never joined."""
        with self._lock:
            row = self._rows.get(session_id)
            member = (row or {}).get("participants", {}).get(agent_id)
        return ExecutionRing(member["ring"]) if member else None

    def is_active(self, session_id: str) -> bool:
        return self.state(session_id) == "ACTIVE"

    def clear(self) -> None:
        """Drop every session. Used by the test teardown."""
        with self._lock:
            ids = list(self._rows)
            self._rows.clear()
        for session_id in ids:
            try:
                self._loop.call(self._hypervisor.terminate_session(session_id))
            except Exception:
                # A session already archived, or one the Hypervisor never
                # accepted. Nothing here should fail a teardown.
                pass
        self._hypervisor = Hypervisor()
