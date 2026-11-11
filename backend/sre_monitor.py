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

import observability

_log = observability.get_logger(__name__)

_registry = SLIRegistry()

# The subset of agent_sre indicators this platform records from governed calls.
# Each maps to a signal we actually observe at the enforcement point.
_TASK_SLI = "TaskSuccessRate"        # the call was allowed
_POLICY_SLI = "PolicyCompliance"     # call was not denied by policy/ring
_LATENCY_SLI = "ResponseLatency"     # measured gate-to-result latency (ms)
# Distinct from task success on purpose: task success says governance let the
# call through, accuracy says the tool that then ran actually worked. A tool
# with no endpoint executes nothing, so it is recorded against neither.
_ACCURACY_SLI = "ToolCallAccuracy"   # the dispatched tool call really succeeded

# Measurements produced by the panel's demo buttons rather than by a governed
# call. Tagged so the view can report how much of an SLO is theatre: AGT's
# compliance arithmetic counts them like any other measurement, so the only
# honest option is to disclose them loudly rather than hide the difference.
SYNTHETIC = {"synthetic": True}

# One budget unit per failed event, so "remaining" reads as a percentage.
_BUDGET_TOTAL = 100.0


def _budget_window(target: float) -> int:
    """The window that makes agent_sre's burn-rate arithmetic come out right.

    ``ErrorBudget.burn_rate`` computes::

        (errors in window / events in window) / (total / window_seconds)

    The numerator is a dimensionless fraction of events; the denominator, as
    configured by default, is budget units per *second*. Dividing one by the
    other is a unit mismatch, and with the shipped defaults (total=100,
    window=30 days) it multiplies the observed error rate by 25,920 — a single
    failure in three calls reported a burn of 8640x beside "99% of budget
    remaining", and tripped CRITICAL. Any error rate above 0.04% did.

    ``window_seconds`` is read in exactly one place, that denominator, and
    nowhere else in the class — not for retention, not for exhaustion. So
    setting it to ``total / (1 - target)`` makes the denominator the *allowed
    error rate* the SLO target implies, and the whole expression becomes the
    standard burn rate: observed error rate over sustainable error rate, where
    1.0 means the budget is being spent exactly as fast as it is earned.

    Correcting the input rather than overriding the output matters here,
    because agent_sre derives the firing alerts and the SLO status from its own
    burn_rate(). Patching only the number we display would leave a sane figure
    sitting beside a CRITICAL badge computed from the broken one.
    """
    allowed = max(1.0 - float(target), 1e-6)   # target 1.0 would divide by zero
    return max(1, int(round(_BUDGET_TOTAL / allowed)))


class _AgentSLO:
    """One agent's SLO plus references to the indicators it feeds."""

    __slots__ = ("slo", "task", "policy", "latency", "accuracy", "store")

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
        self.accuracy = _registry.get_type(_ACCURACY_SLI)(store=self.store)
        self.slo = SLO(
            name=f"{agent_name}-reliability",
            indicators=[self.task, self.policy, self.latency, self.accuracy],
            error_budget=ErrorBudget(total=_BUDGET_TOTAL,
                                     window_seconds=_budget_window(target)),
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
        """Rebuild the in-memory state a reloaded SLO cannot recompute.

        Two things do not survive a restart on their own. The error budget is
        derived from the sequence of task-success events rather than stored, so
        it is replayed from the durable measurements. The latency percentile is
        computed from a plain list on the indicator which nothing repopulates,
        so a restarted process reported "no data" next to a count of every
        persisted call — the same mismatch that made the panel unreadable
        before the record_latency fix above, returning after every restart.

        Appending to that list directly is deliberate: record_latency() is the
        only public way in and it would write each measurement to the durable
        store a second time, doubling the history on every restart.
        """
        for row in entry.store.query(entry.task.name, 0.0):
            entry.slo.error_budget.record_event(bool(row.value))
        try:
            entry.latency._latencies.extend(
                float(row.value)
                for row in entry.store.query(entry.latency.name, 0.0))
        except Exception:
            observability.record_failure(
                observability.SRE_SLO, _log,
                "slo: could not replay latency measurements for %r",
                entry.slo.agent_id)

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
                    policy_denied: bool, latency_ms: float,
                    executed: bool = False, execution_ok: bool = True) -> None:
        """Record one real governed call into the agent's SLO.

        - task success:      the call was allowed;
        - policy compliance: it was not denied by the policy/ring gates;
        - latency:           milliseconds from gate entry to result;
        - tool accuracy:     only when something actually ran, whether it worked.

        The last one is why ``executed`` matters. A decision-only tool that
        governance allowed did not *do* anything, and scoring it as an accurate
        tool call would inflate the indicator with calls that never happened.
        """
        entry = self.ensure(agent_name)
        entry.task.record(1.0 if allowed else 0.0)
        entry.policy.record(0.0 if policy_denied else 1.0)
        # record_latency, not record. ResponseLatency keeps the values it
        # computes its percentile from in a second list of its own, and only
        # record_latency appends to it — the inherited record() writes the
        # measurement store alone. Calling that one left the indicator
        # reporting a measurement_count with no current_value: the card showed
        # "no data" beside a count of every call ever made.
        entry.latency.record_latency(float(latency_ms))
        if executed:
            entry.accuracy.record(1.0 if execution_ok else 0.0)
        entry.slo.record_event(allowed)

    def signal(self, agent_name: str, success: bool) -> dict:
        """Record a hand-entered success/failure from the panel's demo buttons.

        Tagged synthetic. It still moves the error budget — that is the point of
        the button — but the view reports how many measurements were entered by
        hand, so an SLO built out of clicks cannot be mistaken for evidence.
        """
        entry = self.ensure(agent_name)
        entry.task.record(1.0 if success else 0.0, metadata=dict(SYNTHETIC))
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

    def agent_ids(self) -> set:
        """Which agents have an SLO, without building a document for each.

        /stats only needs to count them, and each view serialises the whole
        objective and walks its measurement window twice to do it.
        """
        with self._lock:
            return set(self._slos)

    def remove(self, agent_name: str) -> bool:
        """Drop one agent's SLO.

        Needed by the chaos runner: an adversarial run uses throwaway agents,
        and leaving their objectives behind would put attack traffic in the
        fleet's reliability picture.
        """
        with self._lock:
            return self._slos.pop(agent_name, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._slos.clear()

    @staticmethod
    def _synthetic_count(entry: "_AgentSLO") -> int:
        """How many of the task-success measurements were hand-entered."""
        try:
            return sum(1 for v in entry.task.values_in_window()
                       if (getattr(v, "metadata", None) or {}).get("synthetic"))
        except Exception:
            # Falling back to 0 makes an SLO read as pure evidence. Say so: the
            # whole point of this count is that clicks and real governed calls
            # are told apart, and a silent 0 quietly stops doing that.
            observability.record_failure(
                observability.SRE_SLO, _log,
                "slo: could not count synthetic measurements for %r; this SLO "
                "will read as fully evidence-backed when it may not be",
                getattr(entry.slo, "agent_id", "?"))
            return 0

    @staticmethod
    def _latency_compliance(entry: "_AgentSLO") -> "float | None":
        """The share of responses that met the latency target.

        agent_sre judges every measurement with one rule — ``value >= target``
        — held on ``SLIValue`` and shared by all four indicators. That is right
        for a success *rate*, where more is better, and backwards for a latency,
        where less is. A 15 ms response against a 3000 ms target was scored as
        failing, so the panel painted the fastest calls 0% in red and a
        five-second response would have shown 100%.

        There is no per-indicator direction to configure, so this is the one
        place the platform computes a compliance itself rather than reading
        agent_sre's. The measurements are still agent_sre's own, read from its
        store through its own window; only the comparison is reversed.
        """
        try:
            values = entry.latency.values_in_window()
        except Exception:
            observability.record_failure(
                observability.SRE_SLO, _log,
                "slo: could not read latency measurements for %r",
                entry.slo.agent_id)
            return None
        if not values:
            return None
        target = float(entry.latency.target)
        met = sum(1 for v in values if float(v.value) <= target)
        return met / len(values)

    @classmethod
    def _view(cls, agent_name: str, entry: "_AgentSLO") -> dict:
        doc = entry.slo.to_dict()
        doc["agent_id"] = agent_name
        # Every indicator says which window it is measured over. They differ —
        # 30d, 24h, 1h, 7d — so two counts shown side by side are not
        # necessarily over the same calls, and a card that does not say so
        # invites the reader to compare them as if they were.
        for indicator in doc.get("indicators", []):
            if indicator.get("name") == entry.latency.name:
                indicator["compliance"] = cls._latency_compliance(entry)
                indicator["direction"] = "lower_is_better"
                indicator["compliance_source"] = "agentguard"
                indicator["target_note"] = (
                    f"share of responses at or under {entry.latency.target:.0f} ms")
            else:
                indicator["direction"] = "higher_is_better"
                indicator["compliance_source"] = "agent_sre"
        synthetic = cls._synthetic_count(entry)
        try:
            total = len(entry.task.values_in_window())
        except Exception:
            observability.record_failure(
                observability.SRE_SLO, _log,
                "slo: could not read the measurement window for %r", agent_name)
            total = 0
        doc["synthetic_measurements"] = synthetic
        doc["task_measurements"] = total
        # Named rather than implied: a card can say "this SLO is not evidence"
        # without the panel having to work it out from two counts.
        doc["evidence_only"] = synthetic == 0
        return doc
