"""Durable, non-secret agent metadata: trust score, tenant, policy binding.

This backs the dashboard's per-agent working state so a restart restores a
coherent registry alongside AGT's own persisted lifecycle records. It holds no
secrets — private keys are issued once and never stored (see identity_store).

JSON-backed when constructed with a path, pure in-memory otherwise. With no
path the store is a no-op and the app behaves exactly as it did before
persistence existed.
"""

import json
import threading
from pathlib import Path
from typing import Optional


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
            return {}

    def save(self, meta: dict[str, dict]) -> None:
        if not self._path:
            return
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def wipe(self) -> None:
        """Delete the backing file. For test isolation, never at app shutdown."""
        if self._path:
            self._path.unlink(missing_ok=True)
