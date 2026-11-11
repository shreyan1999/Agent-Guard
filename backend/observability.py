"""Operational logging, and the health of the subsystems that swallow errors.

This and the audit chain answer different questions, and they are deliberately
different channels. An audit entry records a governance *decision* — what the
platform decided, about whom, and why — and is hash-linked evidence a third
party can verify. A log line records what went wrong *inside* the platform
while it was deciding, and is for whoever is on call.

Every telemetry path in this app swallows its own exceptions on purpose: a
failed anomaly ingest must not fail the governed call it was observing, and a
trace that cannot be written must not take the decision down with it. That
policy is right and it stays. What was wrong was the silence around it.
``except Exception: return None`` meant a subsystem could be dead for weeks
while ``/compliance/owasp`` went on listing it as an enabled control and the
SOC 2 assessment counted it as evidence — a platform scoring itself on a
detector that was not running.

So a swallowed failure now does two things it did not before:

* it writes a log line **with the traceback**, so the failure is diagnosable;
* it marks its subsystem **degraded**, which ``_runtime_controls()`` reads, so
  the control that subsystem backs stops reporting itself as enabled.

The second is the one that matters. Logging a failure nobody reads would have
left the compliance report saying the same untrue thing.

Nothing here raises. Every entry point is called from inside an ``except``
block, and an observability layer that could fail the path it observes would
be worse than the silence it replaces.

Configuration
-------------
``AGT_LOG_LEVEL``   DEBUG | INFO | WARNING (default) | ERROR | CRITICAL
``AGT_LOG_FORMAT``  a ``logging`` format string, when the default does not
                    suit the collector reading it
"""

from __future__ import annotations

import logging
import os
import threading
import time

# Subsystem names, as constants so a call site and the control that reads it
# cannot drift apart on a typo.
SRE_ANOMALY = "sre.anomaly"
SRE_ALERTS = "sre.alerts"
SRE_SLO = "sre.slo"
CALL_TRACING = "call_tracing"
IDENTITY = "identity"
STATE = "state"
TOOL_REGISTRY = "tool_registry"

_DEFAULT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

_lock = threading.Lock()
_failures: dict[str, dict] = {}
_configured = False


def configure() -> None:
    """Install a root handler once, unless something already has.

    ``basicConfig`` is a no-op when the root logger already carries handlers,
    so this cooperates with uvicorn, pytest and any host that configures
    logging itself rather than fighting them for the root.
    """
    global _configured
    if _configured:
        return
    _configured = True
    level = os.getenv("AGT_LOG_LEVEL", "WARNING").strip().upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.WARNING),
        format=os.getenv("AGT_LOG_FORMAT") or _DEFAULT_FORMAT,
    )


def get_logger(name: str) -> logging.Logger:
    configure()
    return logging.getLogger(name)


def record_failure(subsystem: str, logger: logging.Logger,
                   message: str, *args) -> None:
    """Log a deliberately-swallowed failure and mark its subsystem degraded.

    Call this from the ``except`` block that is about to return a fallback.
    The traceback goes to the log; only the exception's *type* is retained in
    memory, because the retained part is surfaced through the API and an
    exception message can carry a path, a host or an argument.
    """
    try:
        logger.warning(message, *args, exc_info=True)
    except Exception:                       # pragma: no cover - logging is best effort
        pass
    try:
        import sys
        exc = sys.exc_info()[1]
        kind = type(exc).__name__ if exc is not None else "unknown"
        now = time.time()
        with _lock:
            record = _failures.setdefault(
                subsystem, {"failures": 0, "first_at": now, "last_at": now,
                            "last_error_type": kind})
            record["failures"] += 1
            record["last_at"] = now
            record["last_error_type"] = kind
    except Exception:                       # pragma: no cover
        pass


def degraded_names() -> list[str]:
    """Subsystems that have swallowed at least one failure since startup."""
    with _lock:
        return sorted(_failures)


def degraded_report() -> list[dict]:
    """Per-subsystem failure counts, for the runtime-controls snapshot.

    Carries the exception *type* and not its message: this is read back
    through ``/compliance/owasp``, and a message can name a filesystem path or
    a remote host that the caller has no business seeing.
    """
    with _lock:
        return [
            {"subsystem": name, **{k: v for k, v in record.items()}}
            for name, record in sorted(_failures.items())
        ]


def is_degraded(subsystem: str) -> bool:
    with _lock:
        return subsystem in _failures


def reset() -> None:
    """Forget every recorded failure.

    Used by ``teardown_state`` so one test's induced failure cannot demote a
    control in the next. Not called on a normal restart — the registry is
    process state and a fresh process starts empty anyway.
    """
    with _lock:
        _failures.clear()
