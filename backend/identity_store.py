"""Real cryptographic agent identities backed by ``agentmesh.identity``.

Every agent is minted an Ed25519 keypair and a ``did:mesh`` DID at registration
(``AgentIdentity.create``). The platform retains only the *public* key, so it can
verify an agent's signatures but can never forge them. The private key is issued
to the agent exactly once, at mint time, like an API credential.

Attestation is a challenge-response: the platform issues a single-use nonce, the
agent signs it with its private key, and the platform verifies the signature
against the stored public key. A verified attestation proves the caller holds the
agent's private key, replacing the self-asserted ``agent_id`` string with
cryptographic possession. The first successful attestation is remembered,
because it is what promotes an agent from *registered* to *verified* when its
reputation is computed.

Each agent also gets a ``TrustedAgentCard`` -- AGT's signed, tamper-evident
identity document (name, capabilities, public key, DID) carrying an Ed25519
signature over its own contents. Only the *private* key can sign it, and this
platform holds that key for exactly one moment: inside ``mint()``. So the card
is created there and stored as the public artefact it is. Editing any field
afterwards makes ``verify_signature()`` return False, which is the point.
"""
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

import observability

from agentmesh.identity import AgentIdentity
from agentmesh.trust.cards import TrustedAgentCard

_log = observability.get_logger(__name__)


class IdentityStore:
    """Thread-safe registry of public-only agent identities plus a nonce store.

    When constructed with ``storage_path`` the public identities (DID + public
    JWK) are persisted to JSON and reloaded on startup, so an agent's DID is
    stable across restarts. Only public material is ever written — the private
    key was issued once, at mint time, and is never stored.
    """

    def __init__(self, challenge_ttl_seconds: float = 300.0,
                 storage_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._identities: dict[str, AgentIdentity] = {}   # name -> public-only identity
        self._dids: dict[str, str] = {}                   # name -> did
        self._challenges: dict[str, tuple[str, float]] = {}  # nonce -> (name, expires_at)
        self._cards: dict[str, dict] = {}                 # name -> signed TrustedAgentCard
        self._attested: dict[str, float] = {}             # name -> first attestation
        self._ttl = challenge_ttl_seconds
        self._path = Path(storage_path) if storage_path else None
        self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # Every agent is then silently re-minted with a new DID, breaking
            # attestations signed against the old keys. Starting empty is still
            # the right recovery; doing it quietly was not.
            observability.record_failure(
                observability.IDENTITY, _log,
                "identity: could not read %s; every persisted DID is "
                "unavailable and agents will be re-minted", self._path)
            return
        for name, rec in data.items():
            try:
                self._identities[name] = AgentIdentity.from_jwk(rec["public_jwk"])
                self._dids[name] = rec["did"]
                if isinstance(rec.get("card"), dict):
                    self._cards[name] = rec["card"]
                if rec.get("attested_at"):
                    self._attested[name] = float(rec["attested_at"])
            except Exception:
                observability.record_failure(
                    observability.IDENTITY, _log,
                    "identity: skipping an unreadable record for %r; that agent "
                    "loses its DID and its attestations stop verifying", name)
                continue

    def _save(self) -> None:
        if not self._path:
            return
        data = {
            name: {
                "did": self._dids.get(name),
                "public_jwk": ident.to_jwk(),
                # The card is public material: it is signed, not secret.
                "card": self._cards.get(name),
                "attested_at": self._attested.get(name),
            }
            for name, ident in self._identities.items()
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def mint(self, name: str, sponsor: str,
             capabilities: Optional[list[str]] = None,
             organization: Optional[str] = None) -> dict:
        """Create a real identity, retain only its public key, return the private JWK once."""
        full = AgentIdentity.create(
            name=name, sponsor=sponsor,
            capabilities=capabilities, organization=organization,
        )
        private_jwk = full.to_jwk(include_private=True)
        public_jwk = full.to_jwk()
        # Reconstructing from the public JWK drops the private key, so the stored
        # identity can verify but genuinely cannot sign as the agent.
        public_only = AgentIdentity.from_jwk(public_jwk)
        did = str(full.did)
        # The one moment the private key exists here is the one moment the card
        # can be signed. Everything stored below is public material.
        try:
            card = TrustedAgentCard.from_identity(full).to_dict()
        except Exception:
            # The private key exists for this one moment, so a card that is not
            # signed here can never be signed at all.
            observability.record_failure(
                observability.IDENTITY, _log,
                "identity: could not sign a trusted agent card for %r; it will "
                "have a DID but no signed card", name)
            card = None
        with self._lock:
            self._identities[name] = public_only
            self._dids[name] = did
            if card is not None:
                self._cards[name] = card
            self._save()
        return {"did": did, "private_jwk": private_jwk, "public_jwk": public_jwk,
                "card": card}

    def get(self, name: str) -> Optional[AgentIdentity]:
        with self._lock:
            return self._identities.get(name)

    def did(self, name: str) -> Optional[str]:
        with self._lock:
            return self._dids.get(name)

    def public_jwk(self, name: str) -> Optional[dict]:
        ident = self.get(name)
        return ident.to_jwk() if ident else None

    def did_document(self, name: str) -> Optional[dict]:
        ident = self.get(name)
        return ident.to_did_document() if ident else None

    def issue_challenge(self, name: str) -> Optional[dict]:
        """Mint a single-use nonce bound to ``name`` for the agent to sign."""
        if self.get(name) is None:
            return None
        nonce = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + self._ttl
        with self._lock:
            # Drop expired nonces so the store cannot grow without bound.
            self._challenges = {n: v for n, v in self._challenges.items() if v[1] > now}
            self._challenges[nonce] = (name, expires_at)
        return {"nonce": nonce, "expires_at": expires_at, "ttl_seconds": self._ttl}

    def verify_attestation(self, name: str, nonce: str, signature: str) -> bool:
        """Verify a signature over a challenge nonce against the agent's public key."""
        ident = self.get(name)
        if ident is None:
            return False
        with self._lock:
            entry = self._challenges.pop(nonce, None)   # single-use: consume either way
        if entry is None:
            return False
        agent_name, expires_at = entry
        if agent_name != name or time.time() > expires_at:
            return False
        try:
            ok = ident.verify_signature(nonce.encode("utf-8"), signature)
        except Exception:
            return False
        if ok:
            with self._lock:
                # First one only: this records *that* the agent proved key
                # possession, which is what promotes it to `verified`.
                self._attested.setdefault(name, time.time())
                self._save()
        return ok

    def card(self, name: str) -> "dict | None":
        """The agent's signed card, with its signature re-verified on read.

        Verification is recomputed every time rather than cached: a stored
        ``verified: true`` would be a claim, and the whole point of the card is
        that the claim can be checked.
        """
        with self._lock:
            raw = self._cards.get(name)
        if raw is None:
            return None
        try:
            verified = TrustedAgentCard.from_dict(dict(raw)).verify_signature()
        except Exception:
            verified = False
        return {**raw, "signature_valid": bool(verified)}

    def attested_at(self, name: str) -> "float | None":
        """When this agent first proved possession of its private key."""
        with self._lock:
            return self._attested.get(name)

    def remove(self, name: str) -> None:
        with self._lock:
            self._identities.pop(name, None)
            self._dids.pop(name, None)
            self._cards.pop(name, None)
            self._attested.pop(name, None)
            self._challenges = {n: v for n, v in self._challenges.items() if v[0] != name}
            self._save()

    def clear(self) -> None:
        # In-memory only: never wipes the backing file, so a normal app
        # shutdown (which clears state) does not destroy persisted identities.
        with self._lock:
            self._identities.clear()
            self._dids.clear()
            self._cards.clear()
            self._attested.clear()
            self._challenges.clear()
