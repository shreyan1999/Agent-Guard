"""Replayable traces of governed calls (`agent_sre.replay` + `agent_sre.tracing`).

The audit chain records *that* a decision happened and proves the record has not
been edited. A trace records *how* it happened: which gate ran, in what order,
how long each took, and what it decided. They answer different questions, and
until now the second one had no answer at all.

AGT supplies both halves. ``agent_sre.replay`` has `Trace`, `Span`,
`SpanKind.POLICY_CHECK`/`TOOL_CALL`, a `TraceStore` that redacts on save, and a
`ReplayEngine` that diffs two traces into typed findings (`OUTPUT_MISMATCH`,
`STATUS_CHANGE`, `TOOL_SEQUENCE_DIFF`, …). ``agent_sre.tracing`` supplies the
semantic attribute names — and they line up with what `/tools/call` already
knows almost exactly: `agent.did`, `agent.trust_score`, `agent.policy.name`,
`agent.policy.decision`, `agent.tool.name`, `agent.task.success`. Emitting those
names rather than inventing our own is what makes a trace readable by anything
else that speaks AGT's vocabulary.

**On span timing, and what this cannot honestly measure.** The outer gates —
lifecycle, identity, tenant, trust — run in this handler, so each gets a span
covering the real elapsed time between checkpoints. Ring, policy and the MCP
proxy all run *inside* AGT's `govern()`, which decides them internally and
returns one outcome; this platform cannot time them separately without
re-implementing the gate order it deliberately delegates. So they share one
`govern` span, and the decision names which of them decided. Splitting that
span into three invented durations would make the timeline look more precise
and be less true.

Two consequences of the same rule. A remote call *is* measured separately — the
connector times the round trip — so it gets its own `TOOL_CALL` span and that
time is subtracted from `govern` rather than counted twice. And the audit,
alert and receipt writes that follow the decision get a `record:governance`
span of their own, because charging them to whichever gate happened to decide
would make that gate look slow and hide where the milliseconds actually go.
Between them the spans account for the whole trace, so nothing on the timeline
is left for the reader to guess at.
"""

from __future__ import annotations

import datetime as _dt
import threading
import time
from pathlib import Path

import observability

from agent_sre.replay import (
    ReplayEngine, SpanKind, TraceCapture, TraceStore,
)
from agent_sre.tracing import (
    AGENT_DID, AGENT_POLICY_DECISION, AGENT_POLICY_NAME, AGENT_TASK_NAME,
    AGENT_TASK_SUCCESS, AGENT_TOOL_NAME, AGENT_TOOL_RESULT, AGENT_TRUST_SCORE,
)

_log = observability.get_logger(__name__)


class _Recorder:
    """Builds one trace as a call proceeds through the gates."""

    def __init__(self, capture: TraceCapture) -> None:
        self._cap = capture
        # Each mark closes the interval opened by the previous one, so a span's
        # duration is the real time that gate took rather than a constant.
        self._checkpoint = time.time()

    def mark(self, gate: str, *, passed: bool, rule: str = "",
             reason: str = "", attributes: "dict | None" = None,
             ends_at: "float | None" = None,
             kind: SpanKind = SpanKind.POLICY_CHECK) -> None:
        """Record one gate's outcome as a span covering its real elapsed time.

        ``ends_at`` closes the span earlier than now, which the govern span uses
        to hand the measured remote round trip to `dispatched` instead of
        claiming it as governance overhead.
        """
        span = self._cap.start_span(f"gate:{gate}" if kind is SpanKind.POLICY_CHECK else gate,
                                    kind, attributes=dict(attributes or {}))
        # start_span stamps "now"; rewind it to when this gate actually began.
        # Span is a dataclass and both ends are public fields.
        span.start_time = self._checkpoint
        if passed:
            self._cap.end_span(output={"passed": True})
        else:
            self._cap.end_span(error=f"{rule or gate}: {reason}" if reason else (rule or gate))
        if ends_at is not None:
            span.end_time = max(float(ends_at), span.start_time)
        self._checkpoint = span.end_time or time.time()

    def dispatched(self, tool: str, outcome: dict) -> None:
        """The remote call itself, when one was actually made.

        Its span runs from the checkpoint the govern span left behind to now,
        which is the round trip the connector actually measured — not a slice of
        the governance window guessed at after the fact.
        """
        ok = bool(outcome.get("ok", True))
        span = self._cap.start_span(
            tool, SpanKind.TOOL_CALL,
            attributes={AGENT_TOOL_NAME: tool,
                        AGENT_TOOL_RESULT: "ok" if ok else "error"})
        span.start_time = self._checkpoint
        self._cap.end_span(output={"ok": ok} if ok else None,
                           error=None if ok else str(outcome.get("error") or "tool reported failure"))
        self._checkpoint = span.end_time or time.time()

    def recorded(self, what: str = "audit chain, SLO, alerts, receipt") -> None:
        """The governance write-down that follows the decision.

        Not a gate, and it never changes an outcome — but it is real time spent
        inside the request, and on a fast local deny it is most of it. Leaving
        it out would leave the difference between the trace duration and the
        spans unexplained, which invites the reader to assume a gate was slow.
        """
        span = self._cap.start_span("record:governance", SpanKind.INTERNAL,
                                    attributes={"writes": what})
        span.start_time = self._checkpoint
        self._cap.end_span(output={"recorded": True})
        self._checkpoint = span.end_time or time.time()

    def finish(self, *, allowed: bool, summary: str) -> "object":
        trace = self._cap.trace
        trace.finish(output=summary, success=bool(allowed))
        return trace


class CallTracer:
    """Captures and stores a replayable trace per governed call."""

    def __init__(self, storage_dir: "str | Path | None" = None) -> None:
        self._lock = threading.Lock()
        self._dir = Path(storage_dir) if storage_dir else None
        # Without a directory the tracer is off rather than writing into the
        # working tree: TraceStore's default path would litter wherever the
        # server happened to be started from.
        self._store = TraceStore(storage_dir=self._dir) if self._dir else None
        self._engine = ReplayEngine(store=self._store) if self._store else None

    @property
    def enabled(self) -> bool:
        return self._store is not None

    @property
    def directory(self) -> "str | None":
        return str(self._dir) if self._dir else None

    def begin(self, *, agent_id: str, tool: str, action: str, policy: str,
              did: str = "", trust_score: float = 0.0,
              input_text: str = "") -> "_Recorder | None":
        if not self.enabled:
            return None
        capture = TraceCapture(
            agent_id=agent_id,
            task_input=f"{action} {tool}".strip(),
            metadata={
                AGENT_TASK_NAME: action,
                AGENT_TOOL_NAME: tool,
                AGENT_POLICY_NAME: policy,
                AGENT_DID: did or "",
                AGENT_TRUST_SCORE: trust_score,
                # The text itself is not stored: TraceStore redacts on save, and
                # a trace is not the place to keep whatever an agent sent.
                "input_present": bool(input_text),
            },
        )
        return _Recorder(capture)

    def save(self, recorder, *, allowed: bool, summary: str,
             decision: str = "") -> "str | None":
        """Finish and persist a trace. Returns its id, or None when disabled."""
        if recorder is None or not self.enabled:
            return None
        trace = recorder.finish(allowed=allowed, summary=summary)
        trace.metadata[AGENT_POLICY_DECISION] = decision or ("allow" if allowed else "deny")
        trace.metadata[AGENT_TASK_SUCCESS] = bool(allowed)
        try:
            with self._lock:
                # redact=True is AGT's default and is left on deliberately.
                self._store.save(trace)
        except Exception:
            # A trace that fails to persist must never fail the governed call
            # it describes — but a tracer silently writing nothing is worse
            # than one that is off, because /compliance reports it as on.
            observability.record_failure(
                observability.CALL_TRACING, _log,
                "tracing: could not persist trace %r; the decision was made and "
                "audited, but there is no replayable record of how",
                getattr(trace, "trace_id", "?"))
            return None
        return trace.trace_id

    def all(self, limit: int = 50, agent_id: "str | None" = None,
            visible=None) -> list:
        """The most recently written traces, newest first.

        AGT's own ``list_traces`` walks the directory in filename order, and a
        trace id is random hex — so its "first 50" is an arbitrary 50, not the
        latest ones. Someone opening this list is almost always looking for the
        call that just failed, so the files are ordered by when they were
        written and only that many are loaded.

        ``visible`` is an optional predicate over the summary row, applied
        before the limit so a filtered listing still returns a full page. The
        tracer stays deliberately ignorant of what it means — who may read a
        trace is the app's question, not the store's.
        """
        if not self.enabled:
            return []
        rows = []
        with self._lock:
            try:
                paths = sorted(self._dir.glob("*.json"),
                               key=lambda p: p.stat().st_mtime, reverse=True)
            except OSError:
                return []
            for path in paths:
                if len(rows) >= limit:
                    break
                trace = self._store.load(path.stem)
                if trace is None or (agent_id and trace.agent_id != agent_id):
                    continue
                row = {**self._summary(trace),
                       "written_at": _dt.datetime.fromtimestamp(
                           path.stat().st_mtime,
                           _dt.timezone.utc).isoformat()}
                if visible is not None and not visible(row):
                    continue
                rows.append(row)
        return rows

    def get(self, trace_id: str) -> "dict | None":
        if not self.enabled:
            return None
        with self._lock:
            trace = self._store.load(trace_id)
        return self._view(trace) if trace else None

    def diff(self, trace_id_a: str, trace_id_b: str) -> "dict | None":
        """Diff two traces with AGT's ReplayEngine."""
        if not self.enabled:
            return None
        with self._lock:
            a = self._store.load(trace_id_a)
            b = self._store.load(trace_id_b)
        if a is None or b is None:
            return None
        diffs = self._engine.diff(a, b)
        return {
            "a": self._summary(a),
            "b": self._summary(b),
            "identical": not diffs,
            "diffs": [{
                "type": getattr(d.diff_type, "value", str(d.diff_type)),
                "span": d.span_name,
                "description": d.description,
                "original": d.original,
                "replayed": d.replayed,
            } for d in diffs],
        }

    def delete(self, trace_id: str) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            return bool(self._store.delete(trace_id))

    @staticmethod
    def _summary(trace) -> dict:
        return {
            "trace_id": trace.trace_id, "agent_id": trace.agent_id,
            "task_input": trace.task_input, "success": trace.success,
            "duration_ms": round(trace.duration_ms, 2),
            "span_count": len(trace.spans),
        }

    @classmethod
    def _view(cls, trace) -> dict:
        return {
            **cls._summary(trace),
            "task_output": trace.task_output,
            "metadata": dict(trace.metadata or {}),
            # AGT computes this over the trace's content, so two structurally
            # identical calls hash the same and a changed decision does not.
            "content_hash": trace.content_hash,
            "spans": [{
                "span_id": s.span_id,
                "name": s.name,
                "kind": getattr(s.kind, "value", str(s.kind)),
                "status": getattr(s.status, "value", str(s.status)),
                "duration_ms": round(((s.end_time or s.start_time) - s.start_time) * 1000, 3),
                "attributes": dict(s.attributes or {}),
                "error": s.error,
            } for s in trace.spans],
        }
