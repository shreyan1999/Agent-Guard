"""Durable, non-secret agent metadata: trust score, tenant, policy binding.

This backs the dashboard's per-agent working state so a restart restores a
coherent registry alongside AGT's own persisted lifecycle records. It holds no
secrets — private keys are issued once and never stored (see identity_store).

JSON-backed when constructed with a path, pure in-memory otherwise. With no
path the store is a no-op and the app behaves exactly as it did before
persistence existed.
"""

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Optional

import observability


_log = observability.get_logger(__name__)


class MetaStore:
    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._path = Path(storage_path) if storage_path else None

    @property
    def durable(self) -> bool:
        return self._path is not None

    def load(self) -> dict[str, dict]:
        """Return the persisted {name: {trust, tenant, policy}} map, or empty."""
        if not self._path or not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            # Falling back to {} resets every agent's trust to 0.0 (fails
            # closed, fine) *and* its tenant to the default (fails open, not
            # fine). An operator has to be told this happened.
            observability.record_failure(
                observability.STATE, _log,
                "state: could not read %s; trust, tenant and policy bindings "
                "fall back to defaults for every agent", self._path)
            return {}

    def save(self, meta: dict[str, dict]) -> None:
        """Write the sidecar atomically.

        Written to a temp file and moved into place, the same way PolicyStore
        writes a policy. A torn write here is not a lost file: load() falls back
        to {} on a JSONDecodeError, which resets every agent's trust to 0.0
        (fails closed, fine) *and* its tenant to the default (fails open, not
        fine) — so the half-written state is worse than no state, and os.replace
        is what makes it unreachable.
        """
        if not self._path:
            return
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f".{uuid.uuid4().hex}.tmp")
            try:
                tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
                os.replace(tmp, self._path)
            finally:
                tmp.unlink(missing_ok=True)

    def wipe(self) -> None:
        """Delete the backing file. For test isolation, never at app shutdown."""
        if self._path:
            self._path.unlink(missing_ok=True)
