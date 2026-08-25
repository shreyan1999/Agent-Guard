"""Real agent SLOs, backed by agent_sre — no simulated arithmetic.

Every agent gets an SLO composed of genuine agent_sre indicators. Measurements
are recorded from real governed tool calls (success, policy compliance and
latency), and agent_sre itself computes the compliance ratios, error-budget
burn rate and alerts. Nothing here fabricates a metric: if no calls have been
made, the SLO status is 'unknown' and every indicator reports no measurements.
"""

import hashlib
import threading
from pathlib import Path

from agent_sre.slo import (
    SLO, ErrorBudget, SLIRegistry, InMemoryMeasurementStore, SQLiteMeasurementStore,
)

_registry = SLIRegistry()

# The subset of agent_sre indicators this platform records from governed calls.
# Each maps to a signal we actually observe at the enforcement point.
_TASK_SLI = "TaskSuccessRate"        # call allowed and executed
_POLICY_SLI = "PolicyCompliance"     # call was not denied by policy/ring
_LATENCY_SLI = "ResponseLatency"     # measured gate-to-result latency (ms)


class _AgentSLO:
    """One agent's SLO plus references to the indicators it feeds."""

    __slots__ = ("slo", "task", "policy", "latency", "store")

    def __init__(self, agent_name: str, target: float, latency_target_ms: float,
                 store=None):
        # A private store per agent keeps measurements from colliding on the
        # shared SLI names (both agents would otherwise write 'task_success_rate').
        # When a durable SQLiteMeasurementStore is supplied the same measurements
        # survive a restart; otherwise an in-memory store is used.
        self.store = store if store is not None else InMemoryMeasurementStore()
        self.task = _registry.get_type(_TASK_SLI)(target=target, store=self.store)
        self.policy = _registry.get_type(_POLICY_SLI)(store=self.store)
        self.latency = _registry.get_type(_LATENCY_SLI)(
            target_ms=latency_target_ms, store=self.store
        )
        self.slo = SLO(
            name=f"{agent_name}-reliability",
            indicators=[self.task, self.policy, self.latency],
            error_budget=ErrorBudget(total=100.0),
            agent_id=agent_name,
        )


class SLOStore:
    """Thread-safe registry of per-agent SLOs, all backed by agent_sre.

    When constructed with a ``storage_dir`` each agent's measurements are
    written to a durable per-agent SQLite database (agent_sre's own
    ``SQLiteMeasurementStore``), so the recorded SLIs and their computed
    compliance survive a process restart. With no directory the stores are
    in-memory, matching the ephemeral playground default.
    """

    def __init__(self, storage_dir=None) -> None:
        self._slos: dict[str, _AgentSLO] = {}
        self._lock = threading.Lock()
        self._dir = Path(storage_dir) if storage_dir else None
        if self._dir is not None:
            self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def durable(self) -> bool:
        return self._dir is not None

    def _store_for(self, agent_name: str):
        """A durable per-agent store, or None for the in-memory default."""
        if self._dir is None:
            return None
        # Hash the agent name into a filesystem-safe, collision-resistant file
        # name so arbitrary agent ids map to one stable database each.
        safe = hashlib.sha256(agent_name.encode("utf-8")).hexdigest()[:16]
        return SQLiteMeasurementStore(db_path=str(self._dir / f"slo_{safe}.db"))

    @staticmethod
    def _replay_error_budget(entry: _AgentSLO) -> None:
        """Rebuild the error budget from durable task-success measurements so a
        reloaded SLO reports the same burn it had before the restart."""
        rows = entry.store.query(entry.task.name, 0.0)
        for row in rows:
            entry.slo.error_budget.record_event(bool(row.value))

    def ensure(self, agent_name: str, *, target: float = 0.95,
               latency_target_ms: float = 3000.0) -> _AgentSLO:
        with self._lock:
            entry = self._slos.get(agent_name)
            if entry is None:
                store = self._store_for(agent_name)
                entry = self._slos[agent_name] = _AgentSLO(
                    agent_name, target, latency_target_ms, store=store
                )
                if store is not None:
                    self._replay_error_budget(entry)
            return entry

    def record_call(self, agent_name: str, *, allowed: bool,
                    policy_denied: bool, latency_ms: float) -> None:
        """Record one real governed call into the agent's SLO.

        - task success: the call was allowed and executed;
        - policy compliance: the call was not denied by the policy/ring gates;
        - latency: measured milliseconds from gate entry to result.
        """
        entry = self.ensure(agent_name)
        entry.task.record(1.0 if allowed else 0.0)
        entry.policy.record(0.0 if policy_denied else 1.0)
        entry.latency.record(float(latency_ms))
        entry.slo.record_event(allowed)

    def signal(self, agent_name: str, success: bool) -> dict:
        """Record an out-of-band success/failure signal for an agent's SLO."""
        entry = self.ensure(agent_name)
        entry.task.record(1.0 if success else 0.0)
        entry.slo.record_event(success)
        return self._view(agent_name, entry)

    def set_target(self, agent_name: str, target: float,
                   latency_target_ms: float = 3000.0) -> dict:
        """Create or replace an agent's SLO with a new task-success target."""
        with self._lock:
            store = self._store_for(agent_name)
            entry = self._slos[agent_name] = _AgentSLO(
                agent_name, target, latency_target_ms, store=store
            )
            if store is not None:
                self._replay_error_budget(entry)
            return self._view(agent_name, entry)

    def view(self, agent_name: str) -> "dict | None":
        entry = self._slos.get(agent_name)
        return self._view(agent_name, entry) if entry else None

    def all(self) -> list[dict]:
        with self._lock:
            return [self._view(name, e) for name, e in self._slos.items()]

    def clear(self) -> None:
        with self._lock:
            self._slos.clear()

    @staticmethod
    def _view(agent_name: str, entry: "_AgentSLO") -> dict:
        doc = entry.slo.to_dict()
        doc["agent_id"] = agent_name
        return doc
