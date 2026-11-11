"""Behavioural anomaly detection, via ``agent_sre.anomaly``.

An SLO answers *how often does this agent fail*. It cannot answer *is this agent
behaving unlike itself*, because a compliant agent that suddenly starts calling
a different tool in a different order at a different rate is still compliant.
``AnomalyDetector`` builds a per-agent ``BehaviorBaseline`` and reports the
deviation:

    LATENCY_SPIKE   THROUGHPUT_DROP   ERROR_RATE_SURGE   UNUSUAL_TOOL_SEQUENCE
    TOKEN_USAGE_SPIKE   API_CALL_VOLUME   OUTPUT_DRIFT   RESOURCE_EXHAUSTION

``record_tool_call(agent_id, tool_name)`` takes exactly what ``/tools/call``
already knows, so this needs no new instrumentation — only that the governed
path tell the detector what it just did.

Detections are routed into the same ``AlertManager`` as everything else rather
than kept in a second list, so an operator has one feed to read and AGT's
deduplicator applies to anomalies too.

This is *advisory*. It never denies a call: a baseline is built from an agent's
own past behaviour, and a governance gate that started refusing calls because an
agent got busier would be a gate nobody could reason about.
"""

from __future__ import annotations

import threading

from agent_sre.anomaly import AnomalyDetector

import observability

_log = observability.get_logger(__name__)

# AGT grades anomalies on its own scale; map it onto the alert severities the
# dashboard already renders.
_SEVERITY = {
    "low": "info",
    "medium": "warning",
    "high": "critical",
    "critical": "critical",
}


class AnomalyWatch:
    """Per-agent behavioural baselines, raising alerts on deviation."""

    def __init__(self, hub=None) -> None:
        self._lock = threading.Lock()
        self._detector = AnomalyDetector()
        self._hub = hub
        self._seen: list = []

    def bind(self, hub) -> None:
        """Attach the alert hub. Kept separate from __init__ so module-level
        construction order does not dictate which store is built first."""
        self._hub = hub

    def _emit(self, alert) -> "dict | None":
        if alert is None:
            return None
        severity = getattr(alert.severity, "value", str(alert.severity)).lower()
        kind = getattr(alert.anomaly_type, "value", str(alert.anomaly_type))
        record = {
            "anomaly_type": kind,
            "severity": severity,
            "score": getattr(alert, "score", None),
            "message": alert.message,
            "agent_id": alert.agent_id,
            "details": dict(getattr(alert, "details", None) or {}),
        }
        with self._lock:
            self._seen.insert(0, record)
            del self._seen[100:]
        if self._hub is not None:
            self._hub.raise_alert(
                title=f"Anomaly: {kind.replace('_', ' ')}",
                message=alert.message,
                severity=_SEVERITY.get(severity, "warning"),
                source="anomaly",
                agent_id=alert.agent_id,
                # One key per agent per anomaly type: a baseline that stays
                # breached would otherwise alert on every single call.
                dedup_key=f"anomaly:{alert.agent_id}:{kind}",
                metadata={"score": record["score"]},
            )
        return record

    def record_call(self, agent_id: str, tool_name: str) -> "dict | None":
        """Feed one governed tool call into the agent's behavioural baseline."""
        try:
            with self._lock:
                alert = self._detector.record_tool_call(agent_id, tool_name)
        except Exception:
            # Swallowed on purpose — observing a call must never fail it. But a
            # detector that cannot take observations is not detecting anything,
            # so it also stops being reported as an enabled control.
            observability.record_failure(
                observability.SRE_ANOMALY, _log,
                "anomaly: could not record a tool call for %r (tool %r); "
                "behavioural baselines are no longer being built",
                agent_id, tool_name)
            return None
        return self._emit(alert)

    def record_metric(self, agent_id: str, metric: str, value: float,
                      metadata: "dict | None" = None) -> "dict | None":
        """Feed a numeric observation (latency, denial rate) into the baseline."""
        try:
            with self._lock:
                alert = self._detector.ingest(metric, float(value),
                                              agent_id=agent_id,
                                              metadata=metadata or {})
        except Exception:
            observability.record_failure(
                observability.SRE_ANOMALY, _log,
                "anomaly: could not ingest metric %r for %r; deviation on this "
                "series will not be reported", metric, agent_id)
            return None
        return self._emit(alert)

    def baseline(self, metric: str) -> "dict | None":
        """What 'normal' currently means for one *metric*.

        AGT keys baselines by metric name, not by agent — ``get_baseline`` takes
        the series (``latency_ms``, ``error_rate``), and returns None until it
        has seen enough samples to have an opinion. Reporting None honestly is
        better than reporting a baseline drawn from three points.
        """
        try:
            with self._lock:
                base = self._detector.get_baseline(metric)
        except Exception:
            observability.record_failure(
                observability.SRE_ANOMALY, _log,
                "anomaly: could not read the baseline for %r", metric)
            return None
        if base is None:
            return None
        return base.to_dict() if hasattr(base, "to_dict") else {
            k: v for k, v in vars(base).items() if not k.startswith("_")
        }

    def summary(self) -> dict:
        try:
            with self._lock:
                return dict(self._detector.summary() or {})
        except Exception:
            observability.record_failure(
                observability.SRE_ANOMALY, _log,
                "anomaly: could not read the detector summary")
            return {}

    def recent(self, limit: int = 25) -> list:
        with self._lock:
            return list(self._seen[:limit])

    def clear(self) -> None:
        """Drop every observation and start a fresh detector.

        Rebuilt rather than `reset()`: reset clears the data AGT holds but keeps
        the object, so anything attached to that *instance* outlives a teardown.
        In the test suite that meant a patched method survived `reset_state()`
        and leaked into every later test, silently disabling anomaly detection
        for the rest of the run — which is exactly the cross-test bleed the
        fixtures promise cannot happen.

        The hub binding lives on this object, not the detector, so it survives.
        Only `teardown_state()` calls this, so discarding the detector costs
        nothing a running instance would miss.
        """
        with self._lock:
            self._seen.clear()
            self._detector = AnomalyDetector()
