"""Signed governance receipts for MCP tool calls (``mcp_receipt_governed``).

A receipt is a portable, independently verifiable proof that *this platform*
decided *this way* about *this tool call*. It differs from the audit chain in
what it is for: the Merkle chain proves the log has not been edited, and you
have to trust this instance to read it. A receipt carries its own Ed25519
signature and its signer's public key, so a third party can verify a single
decision offline, with no access to the platform at all. AGT can also render one
as SLSA provenance.

Receipts are hash-chained through ``parent_receipt_hash``, so
``verify_receipt_chain`` detects a removed or reordered receipt as well as a
forged one.

**Only the receipt primitives are used, deliberately not ``McpReceiptAdapter``.**
That adapter bundles a ``CedarPolicyEvaluator`` — a second, independent policy
evaluator with a Cedar grammar and a regex fallback. Wiring it in would mean two
evaluators deciding the same call, which is exactly how a dashboard ends up
reporting a verdict the runtime does not apply. The decision recorded here is
always the one the four gates and the MCP proxy already made; this module only
signs it.

**Who signs.** The platform, not the agent. A receipt attests to a decision the
platform made, so it is signed with a platform key; the agent's DID is a *field*
in the receipt, not its signer. This also keeps the identity model intact — the
platform never holds an agent's private key. Set ``AGT_RECEIPT_KEY`` (hex-encoded
32-byte seed) to pin the signer across restarts, or let one be generated. With
``AGT_STATE_DIR`` set a generated key is persisted, so receipts stay attributable
to the same platform after a restart. Every receipt embeds its signer's public
key, so verification never depends on that choice — pinning only lets an auditor
confirm two receipts came from the same instance.
"""

from __future__ import annotations

import os
import secrets
import threading
from pathlib import Path
from typing import Optional

from mcp_receipt_governed import (
    GovernanceReceipt, ReceiptStore, hash_tool_args, sign_receipt,
    verify_receipt, verify_receipt_chain,
)


def _load_or_create_key(path: Optional[Path]) -> str:
    """The platform's Ed25519 signing seed, as hex."""
    pinned = os.getenv("AGT_RECEIPT_KEY", "").strip()
    if pinned:
        return pinned
    if path and path.exists():
        try:
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                return stored
        except OSError:
            pass
    seed = secrets.token_hex(32)
    if path:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(seed, encoding="utf-8")
            # The signing key is a secret: keep it off group/other where the
            # platform allows it. Best-effort — Windows ignores the mode.
            os.chmod(path, 0o600)
        except OSError:
            pass
    return seed


class ReceiptLedger:
    """A hash-chained, Ed25519-signed ledger of MCP tool-call decisions."""

    def __init__(self, key_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._store = ReceiptStore()
        self._key = _load_or_create_key(key_path)
        self._last_hash: "str | None" = None
        self._durable_key = bool(key_path) or bool(os.getenv("AGT_RECEIPT_KEY", "").strip())

    @property
    def public_key(self) -> str:
        """The signer an auditor should pin, derived from the private seed."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self._key)).public_key().public_bytes_raw().hex()

    @property
    def durable_key(self) -> bool:
        return self._durable_key

    def record(self, *, tool_name: str, agent_did: str, policy: str,
               allowed: bool, arguments: "dict | None",
               session_id: "str | None" = None,
               error: "str | None" = None) -> dict:
        """Sign and append one decision. Returns the receipt as a dict."""
        with self._lock:
            receipt = GovernanceReceipt(
                tool_name=tool_name,
                agent_did=agent_did or "",
                cedar_policy_id=policy,
                cedar_decision="allow" if allowed else "deny",
                args_hash=hash_tool_args(arguments),
                session_id=session_id,
                parent_receipt_hash=self._last_hash,
                error=error,
            )
            sign_receipt(receipt, self._key)
            self._store.add(receipt)
            self._last_hash = receipt.payload_hash()
            return self._view(receipt)

    @staticmethod
    def _view(receipt: GovernanceReceipt) -> dict:
        data = receipt.to_dict()
        data["payload_hash"] = receipt.payload_hash()
        data["signature_valid"] = verify_receipt(receipt)
        return data

    # ReceiptStore.query() with no filter returns every receipt in order and
    # carries its own lock, so the reads below use only its public API.
    def all(self, limit: int = 100, tool_name: "str | None" = None) -> list:
        receipts = self._store.query(tool_name=tool_name)
        return [self._view(r) for r in receipts][-limit:][::-1]

    def verify(self) -> dict:
        """Re-verify every signature and the whole hash chain."""
        receipts = self._store.query()
        errors = verify_receipt_chain(receipts)
        return {
            "valid": not errors,
            "errors": errors,
            "count": len(receipts),
            "signer_public_key": self.public_key,
            "durable_key": self._durable_key,
        }

    def export(self) -> dict:
        receipts = self._store.query()
        return {
            "signer_public_key": self.public_key,
            "count": len(receipts),
            "receipts": [r.to_dict() for r in receipts],
            "slsa_provenance": [r.to_slsa_provenance() for r in receipts],
        }

    def count(self) -> int:
        return self._store.count

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._last_hash = None
