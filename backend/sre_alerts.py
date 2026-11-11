"""Real alerting for the SRE tab, via ``agent_sre.alerts``.

The panel used to render ``error_budget.firing_alerts`` — four bare strings with
no severity, no history, no deduplication and no route. AGT ships the rest of
that story and it was simply never wired up: ``AlertManager`` with an
``AlertSeverity`` scale, an ``AlertDeduplicator`` keyed on ``dedup_key``, and
pluggable channels.

The channel registered here is AGT's ``AlertChannel.CALLBACK``, so alerts land
in a ring buffer this process serves to the dashboard. No network, nothing to
configure, and the same ``AlertManager`` would fan out to Slack, PagerDuty,
Teams or a webhook by adding another ``ChannelConfig`` — which is the reason to
route through AGT rather than keep a list of strings.

Deduplication is the point of routing governance events through here at all. A
denied agent retries; a burning error budget stays burning. Without a dedup key
an alert feed becomes a log, and a log nobody reads is not an alert.
"""

from __future__ import annotations

import threading
import time
from collections import deque

import observability

from agent_sre.alerts import (
    Alert, AlertChannel, AlertManager, AlertSeverity, ChannelConfig,
)

# How many alerts the dashboard keeps. AlertManager holds its own history; this
# buffer is what the panel reads, oldest dropped first.
_MAX_ALERTS = 200

_log = observability.get_logger(__name__)

SEVERITY = {
    "info": AlertSeverity.INFO,
    "warning": AlertSeverity.WARNING,
    "critical": AlertSeverity.CRITICAL,
    "resolved": AlertSeverity.RESOLVED,
}


class AlertHub:
    """One ``AlertManager`` for the process, with an in-dashboard channel."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffer: deque = deque(maxlen=_MAX_ALERTS)
        self._manager = self._build()

    def _build(self) -> AlertManager:
        manager = AlertManager()
        # min_severity=INFO so the dashboard sees everything; a Slack channel
        # added later would set its own floor without changing this one.
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="dashboard",
            callback=self._capture,
            min_severity=AlertSeverity.INFO,
        ))
        return manager

    def _capture(self, alert: Alert) -> None:
        """The callback channel. Called by AGT once an alert survives dedup."""
        with self._lock:
            self._buffer.appendleft({
                "title": alert.title,
                "message": alert.message,
                "severity": getattr(alert.severity, "value", str(alert.severity)),
                "source": alert.source,
                "agent_id": alert.agent_id,
                "slo_name": alert.slo_name,
                "dedup_key": alert.dedup_key,
                "metadata": dict(alert.metadata or {}),
                "timestamp": getattr(alert, "timestamp", None) or time.time(),
            })

    def raise_alert(self, *, title: str, message: str, severity: str = "warning",
                    source: str = "governance", agent_id: str = "",
                    slo_name: str = "", dedup_key: str = "",
                    metadata: "dict | None" = None) -> None:
        """Send one alert through AGT. Suppressed duplicates never reach the buffer.

        Deliberately swallows delivery errors: an alert that fails to route must
        not take down the governed call that raised it.
        """
        alert = Alert(
            title=title,
            message=message,
            severity=SEVERITY.get(severity, AlertSeverity.WARNING),
            source=source,
            agent_id=agent_id or "",
            slo_name=slo_name or "",
            metadata=dict(metadata or {}),
            dedup_key=dedup_key or f"{source}:{agent_id}:{title}",
        )
        try:
            self._manager.send(alert)
        except Exception:
            # The alert is already in the local buffer, so the feed the panel
            # reads survives this. What is lost is delivery through AGT's
            # AlertManager — the half an on-call rota would depend on.
            observability.record_failure(
                observability.SRE_ALERTS, _log,
                "alerts: AGT AlertManager rejected %r from %r; the alert is "
                "buffered locally but was not dispatched", title, source)

    def all(self, limit: int = 50, severity: "str | None" = None) -> list:
        with self._lock:
            items = list(self._buffer)
        if severity:
            items = [a for a in items if a["severity"] == severity]
        return items[:limit]

    def stats(self) -> dict:
        with self._lock:
            buffered = len(self._buffer)
            by_severity: dict = {}
            for a in self._buffer:
                by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
        try:
            delivered = self._manager.get_stats()
        except Exception:
            observability.record_failure(
                observability.SRE_ALERTS, _log,
                "alerts: could not read AGT delivery stats")
            delivered = {}
        return {
            "buffered": buffered,
            "by_severity": by_severity,
            # AGT's own counters: how many were sent, and how many its
            # deduplicator swallowed. The second number is the useful one.
            "suppressed": delivered.get("suppressed", 0),
            "total_sent": delivered.get("total_sent", 0),
            "channels": delivered.get("channels", 0),
        }

    def clear(self) -> None:
        """Empty the feed *and* rearm the deduplicator.

        ``clear_history()`` alone leaves AGT's ``AlertDeduplicator`` holding
        every key it has already seen, so an alert cleared from the feed could
        never be raised again. Rebuilding the manager is what actually resets
        it — and it is also what makes each test start from silence.
        """
        with self._lock:
            self._buffer.clear()
            self._manager = self._build()
