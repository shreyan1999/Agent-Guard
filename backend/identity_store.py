"""Real cryptographic agent identities backed by ``agentmesh.identity``.

Every agent is minted an Ed25519 keypair and a ``did:mesh`` DID at registration
(``AgentIdentity.create``). The platform retains only the *public* key, so it can
verify an agent's signatures but can never forge them. The private key is issued
to the agent exactly once, at mint time, like an API credential.

Attestation is a challenge-response: the platform issues a single-use nonce, the
agent signs it with its private key, and the platform verifies the signature
against the stored public key. A verified attestation proves the caller holds the
agent's private key, replacing the self-asserted ``agent_id`` string with
cryptographic possession.
"""
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from agentmesh.identity import AgentIdentity


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
        self._ttl = challenge_ttl_seconds
        self._path = Path(storage_path) if storage_path else None
        self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for name, rec in data.items():
            try:
                self._identities[name] = AgentIdentity.from_jwk(rec["public_jwk"])
                self._dids[name] = rec["did"]
            except Exception:
                continue

    def _save(self) -> None:
        if not self._path:
            return
        data = {
            name: {"did": self._dids.get(name), "public_jwk": ident.to_jwk()}
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
        with self._lock:
            self._identities[name] = public_only
            self._dids[name] = did
            self._save()
        return {"did": did, "private_jwk": private_jwk, "public_jwk": public_jwk}

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
            return ident.verify_signature(nonce.encode("utf-8"), signature)
        except Exception:
            return False

    def remove(self, name: str) -> None:
        with self._lock:
            self._identities.pop(name, None)
            self._dids.pop(name, None)
            self._challenges = {n: v for n, v in self._challenges.items() if v[0] != name}
            self._save()

    def clear(self) -> None:
        # In-memory only: never wipes the backing file, so a normal app
        # shutdown (which clears state) does not destroy persisted identities.
        with self._lock:
            self._identities.clear()
            self._dids.clear()
            self._challenges.clear()
