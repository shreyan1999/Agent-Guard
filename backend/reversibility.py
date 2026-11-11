"""Whether a governed call can be taken back — AGT's reversibility vocabulary.

AGT's ring model defines Ring 1 as the band for *non-reversible* actions:
"Ring 1 (Privileged): Non-reversible actions — requires eff_score > 0.95 +
consensus". This platform has only ever answered half of that. It derives the
ring from the agent's trust score and never asks the other half — whether the
action could be undone — so a search and a bucket purge land in the same ring
whenever the two callers are equally trusted.

This module supplies the missing half, and borrows rather than invents. The
vocabulary is AGT's own: ``ReversibilityLevel`` (FULL / PARTIAL / NONE),
``ActionDescriptor`` and ``ReversibilityRegistry`` from ``agent_runtime``,
including its risk weights (0.2 / 0.65 / 0.95) — which are the toolkit's
numbers, not ones chosen here. The *evidence* is the descriptor evaluation
``mcp_connector`` already computes, so nothing is graded twice.

Two things it deliberately does not do:

* **It does not block.** A classification lands on the tool as a policy facet
  (``tool.reversibility``, ``tool.risk_weight``), and an operator writes the
  rule. Wiring it straight to a denial would be this module setting policy,
  which is the policy engine's job.
* **It does not force Ring 1.** Ring 1 requires consensus, which this platform
  does not model — ``_ring_for`` says so plainly — so demanding it for every
  irreversible action would be a blanket ban wearing a ring's clothes.

One accommodation worth naming: AGT scopes a ``ReversibilityRegistry`` to a
single session, because it is populated from an IATP handshake. This platform
has no sessions, so there is one process-wide registry and its id says as much.
"""

from __future__ import annotations

import threading

import observability

from hypervisor.reversibility.registry import (
    ActionDescriptor, ReversibilityLevel, ReversibilityRegistry,
)

_log = observability.get_logger(__name__)

# The registry AGT would scope to a session. There is no session here, and the
# id records that rather than pretending otherwise.
REGISTRY_SCOPE = "agentguard:process"

# Findings that settle the question on their own: an action that executes code
# or destroys data has nothing to undo it with.
_IRREVERSIBLE_FINDINGS = frozenset({
    "capability.code_execution",
    "capability.destructive_action",
})

# Otherwise the capability category decides. Anything not named here falls to
# AGT's own default for an unregistered action, which is NONE — the toolkit
# fails closed on this and so does this table.
_BY_CATEGORY = {
    # Nothing un-sends a message, un-pays an invoice, or un-discloses a secret.
    "communication":  ReversibilityLevel.NONE,
    "finance":        ReversibilityLevel.NONE,
    "secrets":        ReversibilityLevel.NONE,
    "code_execution": ReversibilityLevel.NONE,
    # A write can usually be written back, given the old value.
    "data_write":     ReversibilityLevel.PARTIAL,
    "filesystem":     ReversibilityLevel.PARTIAL,
    # Egress covers both fetching and uploading; the second is not undoable, so
    # the pair is graded at the more consequential of the two.
    "network":        ReversibilityLevel.PARTIAL,
    # Reading leaves nothing behind to reverse.
    "data_read":      ReversibilityLevel.FULL,
    "search":         ReversibilityLevel.FULL,
}

DEFAULT_LEVEL = ReversibilityLevel.NONE


def classify(spec: dict) -> ReversibilityLevel:
    """Grade one registry entry's reversibility. Pure: no I/O, no side effects.

    The order is the order of authority:

    1. An operator's explicit setting on the tool. They know what their own
       webhook does; nothing here should argue.
    2. The MCP server's own annotation — but only when the descriptor does not
       contradict it. ``readOnlyHint`` is a claim, and the evaluation already
       knows when a claim disagrees with the tool's own wording; that is the
       one case where the server's word is worth less than its text.
    3. The capability findings, which are evidence rather than assertion.
    4. The category, then AGT's fail-closed default.
    """
    override = str(spec.get("reversibility") or "").strip().lower()
    if override:
        try:
            return ReversibilityLevel(override)
        except ValueError:
            # A bad value is reported and ignored rather than silently
            # downgrading the tool to the default.
            _log.warning("reversibility: tool %r carries an unknown level %r; "
                         "falling back to the derived grade",
                         spec.get("name"), override)

    evaluation = spec.get("evaluation") or {}
    finding_ids = {f.get("id") for f in evaluation.get("findings", [])}
    annotations = ((spec.get("mcp") or {}).get("descriptor") or {}).get("annotations")
    annotations = annotations if isinstance(annotations, dict) else {}
    contradicted = "annotations.contradicted" in finding_ids

    if annotations.get("destructiveHint") is True:
        return ReversibilityLevel.NONE
    if annotations.get("readOnlyHint") is True and not contradicted:
        return ReversibilityLevel.FULL

    if finding_ids & _IRREVERSIBLE_FINDINGS:
        return ReversibilityLevel.NONE

    return _BY_CATEGORY.get(spec.get("category"), DEFAULT_LEVEL)


def _execute_api(spec: dict) -> str:
    """Where the action actually goes, for the descriptor AGT stores."""
    mcp = spec.get("mcp") or {}
    if spec.get("kind") == "mcp":
        origin = mcp.get("server_url") or mcp.get("command") or "?"
        return f"mcp:{mcp.get('server', '?')}:{origin}"
    return spec.get("endpoint_url") or "decision-only"


class ReversibilityIndex:
    """AGT's registry, kept in step with this platform's tool registry.

    Thread-safe because FastAPI runs the sync handlers in a thread pool and a
    tool can be onboarded while a call is being decided.
    """

    def __init__(self, scope: str = REGISTRY_SCOPE) -> None:
        self._lock = threading.Lock()
        self._registry = ReversibilityRegistry(scope)

    def register(self, spec: dict) -> ReversibilityLevel:
        """Classify a tool and record it. Returns the level it was given."""
        name = spec.get("name") or ""
        level = classify(spec)
        descriptor = ActionDescriptor(
            action_id=name,
            name=name,
            execute_api=_execute_api(spec),
            reversibility=level,
            # No undo API is claimed, because none is known. AGT treats a
            # missing one as exactly that rather than as "not needed".
            undo_api=None,
            is_read_only=level is ReversibilityLevel.FULL,
        )
        with self._lock:
            self._registry.register(descriptor)
        return level

    def reseed(self, specs) -> int:
        """Re-grade the whole registry, e.g. after a restart.

        The grades live in memory only. Without this a durable instance would
        come back with every tool defaulting to "unknown", which AGT reads as
        NONE — safe, but it would report a search as unrepeatable and make the
        facet useless for writing policy against.
        """
        self.clear()
        count = 0
        for spec in specs:
            self.register(spec)
            count += 1
        return count

    def forget(self, name: str) -> None:
        """Drop a removed tool, so a stale entry cannot answer for a new one."""
        with self._lock:
            self._registry._entries.pop(name, None)

    def clear(self) -> None:
        with self._lock:
            self._registry = ReversibilityRegistry(REGISTRY_SCOPE)

    # ── reads ────────────────────────────────────────────────────────────
    def level(self, name: str) -> ReversibilityLevel:
        with self._lock:
            entry = self._registry.get(name)
        return entry.reversibility if entry else DEFAULT_LEVEL

    def risk_weight(self, name: str) -> float:
        """AGT's weight for the level: 0.2 full, 0.65 partial, 0.95 none."""
        with self._lock:
            return self._registry.get_risk_weight(name)

    def is_reversible(self, name: str) -> bool:
        with self._lock:
            return self._registry.is_reversible(name)

    def has_non_reversible_actions(self) -> bool:
        with self._lock:
            return self._registry.has_non_reversible_actions()

    def non_reversible(self) -> list[str]:
        with self._lock:
            return sorted(self._registry.non_reversible_actions)

    def facet(self, name: str) -> dict:
        """The two fields a policy rule can be written against."""
        return {
            "reversibility": self.level(name).value,
            "risk_weight": self.risk_weight(name),
        }
