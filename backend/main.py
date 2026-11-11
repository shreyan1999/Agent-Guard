"""
AgentGuard backend — FastAPI + real agent-governance-toolkit
Covers: Policy Engine, Trust, Audit, SRE, Compliance, govern()
"""

import warnings
# AGT 4.x consolidated its distributions into agent-governance-toolkit-*. The
# canonical import paths (agentmesh.*, agent_os.*, hypervisor.*) are preserved
# for backward compatibility but each emits a package-consolidation
# DeprecationWarning. Silence only that known upstream notice by message, so
# genuine deprecations from our own code or other libraries still surface.
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message=r".*is deprecated\. Use agent-governance-toolkit-",
)

import os, re, time, uuid, yaml, datetime
import difflib
from pathlib import Path
import threading
import contextvars
from typing import Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

# ── AGT imports ─────────────────────────────────────────────────────────────────
from agentmesh.governance import govern, PolicyEvaluator, AuditLog, AuditEntry
from agentmesh.governance.policy import PolicyDecision, PolicyEngine, PolicyRule
from agentmesh.governance.protocol_facets import default_registry
from agent_os.credential_redactor import CredentialRedactor
from agentmesh.governance.trust_policy import (
    TrustPolicy, TrustRule, TrustCondition, ConditionOperator, TrustDefaults,
)
from agentmesh.lifecycle import LifecycleManager, LifecyclePolicy, AgentLifecycleState
from agentmesh.lifecycle.manager import LifecycleError
from hypervisor.models import ExecutionRing
from hypervisor.rings import ResourceType, RingEnforcer
from agentmesh.governance.govern import (
    _get_shared_breach_detector, _reset_shared_breach_detectors,
)
from agent_compliance import PromptDefenseEvaluator, PromptDefenseConfig

from policy_store import (
    PolicyStore, PolicyError, CONFLICT_STRATEGIES, POLICY_SCOPES,
    DEFAULT_STRATEGY, API_VERSION,
)
from sre_monitor import SLOStore
from identity_store import IdentityStore
from state_store import MetaStore
from tool_registry import (
    ToolRegistry, ToolError, TOOL_CATEGORIES, DEFAULT_CATEGORY, MCP_TRANSPORTS,
    invoke as _invoke_tool,
)
from foundry_connector import run_steps_to_events
import mcp_connector
from mcp_gate import MCPGate, MCPGateDenied
from mcp_scanners import DescriptorMonitor, descriptor_of
from mcp_receipts import ReceiptLedger
import mcp_admission
import mcp_caller_auth
import mcp_limits
import mcp_security_config
import reputation
from sre_alerts import AlertHub
from sre_anomaly import AnomalyWatch
import chaos_runner
import policy_shadow
import audit_export
import compliance_report
from call_tracing import CallTracer
from auth import AuthProvider, Principal, ANONYMOUS, DEFAULT_TENANT
import observability
import demo_seed
import reversibility
import sessions

_log = observability.get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
# POLICY — context enrichment and condition linting
# ══════════════════════════════════════════════════════════════════════

def _pii_facets(sub_context: dict) -> dict:
    """Derive PII facets from a text-bearing context field.

    AGT's expression grammar has no regex operator, by design — conditions
    stay cheap and analysable, and anything richer belongs in the context.
    FacetRegistry is the documented extension point for that, and
    PolicyEngine.evaluate() runs it on every evaluation, so a rule written
    against these facets behaves identically in the Policy panel and at the
    enforcement point. Detection itself is AGT's CredentialRedactor.
    """
    text = sub_context.get("value")
    if not isinstance(text, str) or not text:
        return {}
    matches = CredentialRedactor.find_pii_matches(text)
    return {
        "has_pii": bool(matches),
        "pii_types": sorted({m.name for m in matches}),
        "has_credentials": CredentialRedactor.contains_credentials(text),
    }


# Registered once, on the registry PolicyEngine consults internally.
default_registry.register("input_text", _pii_facets)


# Every field a policy condition can read, and the single source of truth for
# both /policies/schema and the linter below. It used to live inside the
# endpoint, where the linter could not see it — so a condition naming a field
# that does not exist passed validation, saved, reported `enabled: true`, and
# never matched anything. The endpoint's own docstring claimed these were
# "served from the same constants the linter and store use"; that is now true.
_POLICY_FIELDS = (
    {"path": "action.type", "type": "string",
     "help": "The action passed to the governed tool."},
    {"path": "agent.id", "type": "string", "help": "Readable agent name."},
    {"path": "agent.agent_id", "type": "string", "help": "AGT lifecycle id."},
    {"path": "agent.state", "type": "string",
     "help": "AGT lifecycle state, e.g. active."},
    {"path": "agent.ring", "type": "number",
     "help": "Execution ring, derived from trust."},
    {"path": "agent.trust_score", "type": "number", "help": "0.0 to 1.0."},
    {"path": "tool.name", "type": "string", "help": "Registry name of the tool."},
    {"path": "tool.category", "type": "string",
     "help": "What the tool is for, e.g. code_execution or secrets."},
    {"path": "tool.risk", "type": "string",
     "help": "Risk tier on the registry entry: low to critical."},
    {"path": "tool.kind", "type": "string",
     "help": "webhook, or mcp for a tool imported from an MCP server."},
    {"path": "tool.reversibility", "type": "string",
     "help": "AGT ReversibilityLevel: full, partial or none. Whether "
             "the call could be undone, graded from the descriptor."},
    {"path": "tool.risk_weight", "type": "number",
     "help": "AGT's weight for that level: 0.2 full, 0.65 partial, "
             "0.95 none."},
    # Injected into the context by AGT's govern() itself, from the
    # ring's constraint table. Documented here because a path nobody
    # is told about is a path nobody writes a rule against.
    {"path": "ring.level", "type": "number",
     "help": "0 root to 3 sandbox. Set by AGT from the agent's ring."},
    {"path": "ring.network_allowed", "type": "boolean",
     "help": "AGT ring constraint, false in ring 3. Usable as bare "
             "truthiness only — AGT's grammar has no '== false', so "
             "write `ring.level > 2` to mean sandboxed."},
    {"path": "ring.subprocess_allowed", "type": "boolean",
     "help": "AGT ring constraint, false in ring 3. Same grammar "
             "caveat as ring.network_allowed."},
    {"path": "input_text.has_pii", "type": "boolean",
     "help": "Set by AGT CredentialRedactor via FacetRegistry."},
    {"path": "input_text.has_credentials", "type": "boolean",
     "help": "Set by AGT CredentialRedactor via FacetRegistry."},
    {"path": "sql.verb", "type": "string",
     "help": "AGT protocol facet, when the context carries sql."},
    {"path": "sql.target", "type": "string", "help": "AGT protocol facet."},
)

_POLICY_FIELD_PATHS = frozenset(f["path"] for f in _POLICY_FIELDS)

# The field a clause reads, i.e. everything up to the operator.
_FIELD_IN_ATOM = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)")


# The atom forms AGT's PolicyRule._eval_expression actually implements.
# Mirrored here only to *warn* about conditions AGT cannot parse — this
# never decides a verdict, so it cannot reintroduce a second evaluator.
_ATOM_PATTERNS = (
    re.compile(r"^\w+(?:\.\w+)*\s*==\s*['\"][^'\"]+['\"]$"),
    re.compile(r"^\w+(?:\.\w+)*\s*!=\s*['\"][^'\"]+['\"]$"),
    re.compile(r"^\w+(?:\.\w+)*\s+in\s+\[[^\]]*\]$"),
    re.compile(r"^\w+(?:\.\w+)*\s*(?:>=|<=|>|<)\s*\d+(?:\.\d+)?$"),
    re.compile(r"^\w+(?:\.\w+)*$"),
)

_GRAMMAR_HELP = (
    "AGT supports: field == 'v', field != 'v', field in ['a','b'], "
    "field > 0.5 (also >=, <, <=), and bare truthiness `field.flag`, "
    "combined with ` and ` / ` or `. There is no regex or substring operator — "
    "compute a flag into the context instead (see input_text.has_pii)."
)


def _condition_atoms(condition: str) -> list[str]:
    """Split a condition the way AGT does, into the clauses it evaluates."""
    atoms = [condition]
    for sep in (" or ", " and "):
        atoms = [piece for atom in atoms for piece in atom.split(sep)]
    return [atom.strip() for atom in atoms if atom.strip()]


def _lint_condition(condition: str) -> list[str]:
    """Return the atoms of *condition* that AGT's grammar cannot parse."""
    return [atom for atom in _condition_atoms(condition)
            if not any(p.match(atom) for p in _ATOM_PATTERNS)]


def _suggest_fields(path: str) -> list[str]:
    """The documented fields an operator probably meant by *path*.

    A prefix match comes first and is the case worth catching: `action` reads
    as a valid clause and is one dot away from `action.type`, which is the
    field that actually exists. Otherwise fall back to edit distance.
    """
    prefixed = sorted(f for f in _POLICY_FIELD_PATHS
                      if f.startswith(path + "."))
    if prefixed:
        return prefixed[:4]
    return difflib.get_close_matches(path, sorted(_POLICY_FIELD_PATHS),
                                     n=3, cutoff=0.6)


def _unknown_fields(condition: str) -> list[dict]:
    """Fields in *condition* that nothing documented puts in the context.

    Deliberately separate from :func:`_lint_condition`, and deliberately not
    part of the blocking check. An unparsable atom is something AGT *cannot*
    evaluate; an unrecognised field is something it will evaluate to nothing —
    almost always a typo, but not certainly one, because ``/tools/call``
    forwards its ``kwargs`` into the policy context verbatim and a caller may
    legitimately supply a field no schema here lists. Refusing to save those
    would trade a silent no-op for a wrongly rejected policy.
    """
    seen, unknown = set(), []
    for atom in _condition_atoms(condition):
        match = _FIELD_IN_ATOM.match(atom)
        if not match:
            continue
        path = match.group(1)
        if path in _POLICY_FIELD_PATHS or path in seen:
            continue
        seen.add(path)
        unknown.append({"path": path, "did_you_mean": _suggest_fields(path)})
    return unknown


def _lint_rules(rules: list) -> list[dict]:
    """Lint every rule in a policy, returning one warning per dead condition."""
    warnings_out = []
    for rule in rules:
        cond = rule.get("condition", "") if isinstance(rule, dict) else ""
        dead = _lint_condition(cond)
        if dead:
            warnings_out.append({
                "rule": rule.get("name", "?"),
                "condition": cond,
                "kind": "unparsable",
                "unparsable": dead,
                "effect": "This rule can never match and enforces nothing.",
            })
    return warnings_out


# ══════════════════════════════════════════════════════════════════════
# EVIDENCE — AGT AuditLog / MerkleAuditChain
# ══════════════════════════════════════════════════════════════════════

def _build_audit_log() -> AuditLog:
    """Construct an AGT AuditLog, optionally with a durable signed sink.

    Set AGT_AUDIT_FILE and AGT_AUDIT_KEY to stream entries to an append-only,
    HMAC-signed JSON-lines file. Opt-in, because re-verifying on-disk entries
    needs the same key across restarts and key management is out of scope here.
    """
    path, key = os.getenv("AGT_AUDIT_FILE"), os.getenv("AGT_AUDIT_KEY")
    if path and key:
        from agentmesh.governance.audit_backends import FileAuditSink
        return AuditLog(sink=FileAuditSink(path, key.encode("utf-8")))
    return AuditLog()


class AuditStore:
    """Thread-safe adapter over the AGT AuditLog.

    Everything routes through the public API — log(), query(),
    verify_integrity(), get_proof(), export(). The exceptions are root_hash()
    and _chain_entries(): AuditLog exposes no public accessor for the Merkle
    root short of export(), which serialises every entry, and no way to read
    the chain without copying it — query() slices, so counting N entries
    allocates a list of N. Both reaches into AGT internals are isolated here,
    so an AGT upgrade touches two methods rather than a dozen call sites.

    The lock matters because handlers are sync defs, so FastAPI runs them
    in a thread pool, and add_entry() links hashes and rebuilds the tree.

    Nothing here is counted from a side tally. Every number this class reports
    is read from the chain itself, because a derived counter would go on
    reporting the length of a chain somebody had just deleted an entry from,
    and detecting exactly that is what the chain is for.
    """

    _UNBOUNDED = 10 ** 9

    #: How long a verification may be reported before it is recomputed.
    #: verify_integrity() re-hashes every entry, and the dashboard polls
    #: /stats every few seconds per open browser, so verifying on each poll
    #: made the cost of leaving the page open grow with the chain, while
    #: holding the lock every append needs. On-demand callers bypass this.
    VERIFY_TTL_SECONDS = 30.0

    def __init__(self) -> None:
        self._log = _build_audit_log()
        self._lock = threading.Lock()
        self._verified = None

    def _chain_entries(self) -> list:
        """The live entry list. Callers must already hold the lock.

        AGT API gap, the sibling of the one root_hash() documents: query() is
        the only public reader and it slices, which copies the whole chain
        even when the caller only wants its length or the newest few.
        """
        return self._log._chain._entries

    def log(self, event_type: str, agent_id: str, details: dict, allowed: bool = True) -> None:
        with self._lock:
            self._log.log(
                event_type=event_type,
                agent_did=agent_id,
                action=str(details.get("action") or details.get("tool") or event_type),
                data=details,
                outcome="success" if allowed else "denied",
                policy_decision="allow" if allowed else "deny",
            )

    def entries(self, agent_id: Optional[str] = None, event_type: Optional[str] = None,
                limit: int = 50, visible=None) -> "list[AuditEntry]":
        """Newest-first entries. The AGT query() returns oldest-first.

        ``visible`` is an optional per-entry predicate, applied before the limit
        so a caller asking for 50 readable entries gets 50 of them rather than
        whatever survives filtering the newest 50.

        Unfiltered, this walks the chain backwards and stops at the limit, so
        the Audit panel's poll reads the newest 50 entries instead of copying
        every entry ever written in order to discard all but 50 of them.
        """
        with self._lock:
            if agent_id or event_type:
                found = self._log.query(agent_did=agent_id, event_type=event_type,
                                        limit=self._UNBOUNDED)
            else:
                found = self._chain_entries()
            out = []
            for entry in reversed(found):
                if len(out) >= limit:
                    break
                if visible is not None and not visible(entry):
                    continue
                out.append(entry)
        return out

    def count(self) -> int:
        with self._lock:
            return len(self._chain_entries())

    def tally(self, visible=None):
        """(entries, denials) over the chain, in one allocation-free pass.

        /stats used to materialise and reverse the whole chain to count it,
        then walk it again for the total. One pass now, and no copy.
        """
        total = denied = 0
        with self._lock:
            for entry in self._chain_entries():
                if visible is not None and not visible(entry):
                    continue
                total += 1
                if entry.outcome == "denied":
                    denied += 1
        return total, denied

    def root_hash(self) -> Optional[str]:
        # AGT API gap: no public Merkle-root accessor on AuditLog.
        with self._lock:
            return self._log._chain.get_root_hash()

    def verify(self) -> dict:
        """Re-hash every entry and re-walk the chain links. Always fresh.

        Returns the verdict together with the moment it was taken and the
        number of entries it covered — which is what makes a cached copy of it
        honest to report later.
        """
        with self._lock:
            valid, error = self._log.verify_integrity()
            entries = len(self._chain_entries())
        result = {"valid": bool(valid), "error": error,
                  "checked_at": time.time(), "entries": entries}
        self._verified = result
        return result

    def verification(self, max_age=None) -> dict:
        """The last verification, recomputed once it is older than *max_age*.

        For pollers. A verification is a point-in-time statement either way —
        even a fresh one is stale the instant it returns — so what makes this
        honest is not the interval but that the answer carries ``checked_at``
        and every caller surfaces it. On-demand endpoints (/audit/verify, the
        compliance report) call verify() and get a fresh walk.
        """
        ttl = self.VERIFY_TTL_SECONDS if max_age is None else max_age
        cached = self._verified
        if cached is not None and (time.time() - cached["checked_at"]) < ttl:
            return cached
        return self.verify()

    def proof(self, entry_id: str) -> Optional[dict]:
        with self._lock:
            return self._log.get_proof(entry_id)

    def export(self) -> dict:
        with self._lock:
            return self._log.export()

    def reset(self):
        """Open a new chain, returning the replaced chain root and size."""
        with self._lock:
            previous_root = self._log._chain.get_root_hash()
            previous_count = len(self._chain_entries())
            self._log = _build_audit_log()
            # The cached verdict described the chain that was just replaced.
            self._verified = None
        return previous_root, previous_count


_audit = AuditStore()


def _emit_audit(event_type: str, agent_id: str, details: dict, allowed: bool = True,
                tenant: "str | None" = None):
    """Write one entry, stamped with the tenant it belongs to.

    The stamp is what lets a tenant-scoped read be exact instead of inferred.
    Callers that know the owner — the policy endpoints, whose subject is a
    policy rather than an agent — pass it; everything else has it derived from
    the agent the entry names. An entry naming no registered agent is a
    platform event (a chain reset, a compliance report) and carries no tenant,
    which is what makes it readable by every authenticated caller.

    It lands in the entry's own ``data``, so the entry hash covers it: an
    attribution that could be edited after the fact would be worth nothing on a
    chain whose whole point is that it cannot be.
    """
    owner = tenant if tenant is not None else _agent_tenant.get(agent_id)
    if owner is not None:
        details = {**details, "tenant": owner}
    _audit.log(event_type, agent_id, details, allowed)


def _entry_tenant(entry: AuditEntry) -> "str | None":
    """The tenant an entry was stamped with, or None when it is platform-wide."""
    data = entry.data if isinstance(entry.data, dict) else {}
    owner = data.get("tenant")
    return owner if isinstance(owner, str) else None


def _audit_visible(entry: AuditEntry, principal: Principal) -> bool:
    """A tenant reads its own entries and the platform-wide ones, nothing else.

    Admins span tenants, exactly as they do on /agents and /policies.
    """
    if principal.is_admin:
        return True
    owner = _entry_tenant(entry)
    return owner is None or owner == principal.tenant


def _serialise_entry(e: AuditEntry) -> dict:
    """Project an AuditEntry into the dashboard event shape, hashes included."""
    return {
        "id": e.entry_id,
        "timestamp": e.timestamp.isoformat(),
        "event_type": e.event_type,
        "agent_id": e.agent_did,
        "allowed": e.outcome != "denied",
        "details": e.data,
        "entry_hash": e.entry_hash,
        "previous_hash": e.previous_hash,
    }


# ══════════════════════════════════════════════════════════════════════
# RUNTIME — the AGT LifecycleManager owns agent state and the kill switch
# ══════════════════════════════════════════════════════════════════════
# The kill switch is the AGT SUSPENDED lifecycle state, not a local flag:
# LifecycleManager enforces the state machine, rejects invalid transitions,
# attributes every change to an actor, and keeps its own audit trail.
def _state_dir() -> "Path | None":
    d = os.getenv("AGT_STATE_DIR")
    return Path(d) if d else None


def _state_file(name: str) -> "Path | None":
    d = _state_dir()
    return (d / name) if d else None


def _truthy(name: str) -> bool:
    """Read an env flag; true only for explicit affirmative values."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _require_attestation() -> bool:
    """When AGT_REQUIRE_ATTESTATION is set, every /tools/call must carry a
    signed attestation that verifies against the agent's registered key."""
    return _truthy("AGT_REQUIRE_ATTESTATION")


def _require_approval() -> bool:
    """When AGT_REQUIRE_APPROVAL is set, a newly registered agent lands in
    AGT's PENDING_APPROVAL state and cannot be activated until an admin
    approves it. The state machine enforces this, not application code:
    activating a pending agent raises LifecycleError."""
    return _truthy("AGT_REQUIRE_APPROVAL")


# A request-scoped override for _tool_allow_private(). The SSRF guard stays on
# by default; the demo seed sets this to True only for the duration of importing
# the platform's own loopback demo MCP server, so it never relaxes the guard for
# any other caller or endpoint (it is a ContextVar, not process state).
_allow_private_override: "contextvars.ContextVar[bool | None]" = \
    contextvars.ContextVar("allow_private_override", default=None)


def _register_reversibility(spec: dict) -> dict:
    """Grade a freshly registered tool and hand the spec back, annotated.

    Called on every onboarding path, so a re-import re-grades: a descriptor
    that changed from a search to a purge must not keep the old level.
    """
    try:
        level = _reversibility.register(spec)
        spec["reversibility"] = level.value
        spec["risk_weight"] = _reversibility.risk_weight(spec.get("name") or "")
    except Exception:       # pragma: no cover - grading must not fail an import
        observability.record_failure(
            observability.TOOL_REGISTRY, _log,
            "reversibility: could not grade %r; it keeps AGT's fail-closed "
            "default and no policy reading tool.reversibility will see it as "
            "undoable", spec.get("name"))
    return spec


def _tool_allow_private() -> bool:
    """Permit onboarded tool endpoints that resolve to private/loopback hosts.

    Off by default (SSRF-safe). Set AGT_TOOL_ALLOW_PRIVATE=1 to point tools at
    a local service, e.g. when developing against a webhook on localhost."""
    override = _allow_private_override.get()
    if override is not None:
        return override
    return _truthy("AGT_TOOL_ALLOW_PRIVATE")


def _slo_dir() -> "Path | None":
    """Durable SLO directory under AGT_STATE_DIR, or None for in-memory SLOs."""
    d = _state_dir()
    return (d / "slo") if d else None


def _runtime_controls() -> dict:
    """A live snapshot of the security controls enabled on this instance.

    Every value is read from the current process/environment, so the OWASP
    self-assessment reflects how the platform is actually configured rather
    than a static claim.

    A subsystem that has swallowed a failure is reported as **not** enabled.
    Three of these used to be the literal ``True`` — they were shipped, so they
    were on — which stayed true right up until the moment the thing behind them
    stopped working, at which point it went on being reported as evidence for
    SOC 2 CC7.2. A control nobody can confirm is running is not a control, and
    ``observability`` is what turns a silently-swallowed exception into that
    admission.
    """
    degraded = observability.degraded_names()
    return {
        "authentication": _auth.enabled,
        "jwt_validation": bool(os.getenv("AGT_JWT_SECRET", "").strip()),
        "attestation_required": _require_attestation(),
        "registration_approval_required": _require_approval(),
        "sre_alerting": observability.SRE_ALERTS not in degraded,
        "sre_anomaly_detection": observability.SRE_ANOMALY not in degraded,
        "call_tracing": _tracer.enabled and observability.CALL_TRACING not in degraded,
        "adversarial_evaluation": True,
        "durable_state": _state_dir() is not None,
        "durable_slo": _slo.durable,
        "durable_audit": bool(os.getenv("AGT_AUDIT_FILE") and os.getenv("AGT_AUDIT_KEY")),
        "cors_allowlist": list(_cors_origins),
        "kill_switch": True,          # lifecycle suspend is always available
        "merkle_audit_chain": True,   # audit chain is always hash-linked
        "mcp_tool_evaluation": True,  # imported MCP descriptors are graded
        # AGT's own mcp_trust_proxy.TrustProxy gates every MCP dispatch:
        # per-call argument scanning, per-tool rate limits and a trust floor
        # derived from the descriptor grade.
        "mcp_runtime_gate": True,
        # AGT's descriptor fingerprinting, response scanning and signed receipts.
        "mcp_rug_pull_detection": True,
        "mcp_response_scanning": True,
        "mcp_signed_receipts": True,
        "receipt_key_durable": _receipts.durable_key,
        "mcp_tools_onboarded": sum(1 for t in _tools.all()
                                   if t.get("kind") == "mcp"),
        # What has failed quietly since this process started, and how often.
        # Carries the exception type but never its message: this is read back
        # through /compliance/owasp, and a message can name a path or a host.
        "degraded_subsystems": observability.degraded_report(),
    }


_lifecycle = LifecycleManager(
    policy=LifecyclePolicy(require_approval=_require_approval(), require_owner=True),
    storage_path=_state_file("agents.json"),
)

# LifecycleManager mints its own IDs (agent:<hex>). The dashboard addresses
# agents by readable name, so keep a name -> AGT id index and resolve either.
_agent_ids: dict[str, str] = {}
_call_stats: dict[str, dict] = {}            # agent name -> {calls, denials}

# ── In-memory state ───────────────────────────────────────────────────────────
# Policies live in one directory so AGT can resolve `extends` between them;
# override with AGT_POLICY_DIR (the test suite points it at a temp dir).
_policies = PolicyStore(os.getenv("AGT_POLICY_DIR") or Path(__file__).parent / "policies")
_agent_policies: dict[str, str] = {}         # agent name -> policy name
_policy_tenant: dict[str, str] = {}          # policy name -> owning tenant (None = shared)
_trust_scores: dict[str, float] = {}         # agent name -> score
_slo = SLOStore(storage_dir=_slo_dir())      # real agent_sre SLOs, per agent


# ── Durable state ─────────────────────────────────────────────────────────────
# Set AGT_STATE_DIR to persist agents across restarts: AGT's LifecycleManager
# owns the agent records (agents.json), a MetaStore holds the non-secret
# trust/tenant/policy sidecar (agent_meta.json), and IdentityStore persists the
# public DIDs (identities.json). Unset — the shipped default — keeps everything
# in memory, exactly as before. Private keys are never written; a persisted
# agent keeps a stable DID but the caller retains its once-issued private key.
_identity = IdentityStore(storage_path=_state_file("identities.json"))
_meta = MetaStore(_state_file("agent_meta.json"))
_policy_meta = MetaStore(_state_file("policy_owners.json"))  # policy -> {tenant}
_tool_meta = MetaStore(_state_file("tools.json"))            # onboarded tool defs
_tools = ToolRegistry(_tool_meta)            # user-onboarded tools for evaluation
_governed_tools: dict[tuple, Any] = {}       # (tool, policy, agent, ring) -> GovernedCallable
_agent_tenant: dict[str, str] = {}           # agent name -> owning tenant
_agent_foundry: dict[str, dict] = {}         # agent name -> Foundry onboarding metadata
_agent_capabilities: dict[str, list] = {}    # agent name -> capabilities it holds

# AGT's own MCP trust proxy, enforced immediately before an MCP dispatch. See
# mcp_gate for why this is TrustProxy and deliberately not ProtocolBridge.
_mcp_gate = MCPGate()
# AGT's MCP scanners: descriptor fingerprints (rug pull). The response-content
# scanner is held by _mcp_response_policy below, which pairs it with the policy
# that decides what may be shown of an unsafe response.
_mcp_descriptors = DescriptorMonitor()
# Admission: may this platform open a connection to that server at all. AGT's
# McpAuthPolicy judges how the connection is authenticated, and its McpCveFeed
# judges whether the server's own package has a published vulnerability.
_mcp_admission = mcp_admission.ConnectionAdmission()
_mcp_vulns = mcp_admission.VulnerabilityIndex()
# Per-call limits: a sliding per-agent budget across every MCP tool, and AGT's
# MCPGateway for the parameter and response stages the other gates never saw.
_mcp_budget = mcp_limits.CallBudget()
_mcp_params = mcp_limits.ParameterGate()
_mcp_response_policy = mcp_limits.ResponseGate()
# Caller credentials: short-lived session tokens bound to an agent, and replay
# protection over this platform's own call API. Both inert until configured.
_mcp_callers = mcp_caller_auth.CallerSessions()
_call_signer = mcp_caller_auth.CallSigner(
    key_path=_state_file("call_signing_key.b64"))
# AGT's ReversibilityRegistry, kept in step with the tool registry. It answers
# the half of the ring model this platform never asked: not "how trusted is the
# caller" but "could this be undone".
_reversibility = reversibility.ReversibilityIndex()
# AGT's Hypervisor, wrapped synchronously. The two ACS points this platform had
# no answer for — agent_startup and agent_shutdown — are its session boundaries.
_sessions = sessions.SessionManager()
# Signed, hash-chained receipts for every MCP tool-call decision.
_receipts = ReceiptLedger(key_path=_state_file("receipt_key.hex"))
# AGT's alerting and behavioural anomaly detection. The watcher routes its
# findings into the same hub, so an operator reads one feed.
_alerts = AlertHub()
_anomaly = AnomalyWatch()
_anomaly.bind(_alerts)
# The most recent adversarial run, so the Compliance panel can put empirical
# evidence beside a declarative self-assessment without firing attacks of its
# own. Reset with the rest of the state; never persisted, because a stale grade
# from before a policy change would be worse than none.
_last_chaos: dict = {}
# Replayable traces of governed calls. Durable under AGT_STATE_DIR and off
# otherwise, because TraceStore's default path would write into whatever
# directory the server happened to be started from.
_tracer = CallTracer(storage_dir=_state_file("traces"))


# ══════════════════════════════════════════════════════════════════════
# AUTH — bearer API keys, role hierarchy, tenant scoping
# ══════════════════════════════════════════════════════════════════════
# Application-layer, not AGT: this decides who may call the API. Disabled
# unless AGT_API_KEYS / AGT_API_KEYS_FILE is set, in which case every request
# needs a bearer token and mutating endpoints demand a role.
_auth = AuthProvider()
_bearer = HTTPBearer(auto_error=False)

# Endpoints reachable without a token even when auth is on: liveness and the
# self-describing schema, so a browser can still load /docs to authenticate.
_PUBLIC_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}


def _principal_from(creds: Optional[HTTPAuthorizationCredentials]) -> Principal:
    """Resolve the caller. Anonymous local-admin when auth is disabled."""
    if not _auth.enabled:
        return ANONYMOUS
    token = creds.credentials if creds else None
    principal = _auth.authenticate(token)
    if principal is None:
        raise HTTPException(
            status_code=401, detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def current_principal(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Principal:
    """Any authenticated caller (viewer or above)."""
    return _principal_from(creds)


def _require(role: str):
    """Build a dependency that admits a caller only at or above `role`."""
    def _dep(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has_role(role):
            raise HTTPException(
                status_code=403,
                detail=f"Requires '{role}' role; '{principal.subject}' has {sorted(principal.roles)}",
            )
        return principal
    return _dep


require_operator = _require("operator")
require_admin = _require("admin")


def _authorize_agent(agent, principal: Principal) -> None:
    """Fail closed on cross-tenant access to a specific agent."""
    if principal.is_admin:
        return
    owner = _agent_tenant.get(agent.name, DEFAULT_TENANT)
    if owner != principal.tenant:
        raise HTTPException(status_code=403, detail="Agent belongs to another tenant")


# ── Per-tenant policy ownership ────────────────────────────────────────────
# A policy created through the API is stamped with its author's tenant. Only
# that tenant (and any admin) may see, edit, delete or enforce it. Policies
# with no owner — the seeded default-policy — are shared and usable by all,
# so single-tenant playground behaviour is unchanged (the anonymous caller is
# a local admin and every seeded agent lives in the default tenant).
def _policy_owner(name: str) -> "str | None":
    return _policy_tenant.get(name)


def _policy_visible(name: str, principal: Principal) -> bool:
    owner = _policy_owner(name)
    return owner is None or principal.is_admin or owner == principal.tenant


def _set_policy_owner(name: str, tenant: str) -> None:
    _policy_tenant[name] = tenant
    _persist_policy_owners()


def _drop_policy_owner(name: str) -> None:
    if _policy_tenant.pop(name, None) is not None:
        _persist_policy_owners()


def _persist_policy_owners() -> None:
    _policy_meta.save({n: {"tenant": t} for n, t in _policy_tenant.items()})


def _load_policy_owners() -> None:
    for name, rec in _policy_meta.load().items():
        if _safe_exists(name):
            _policy_tenant[name] = rec.get("tenant", DEFAULT_TENANT)


def _require_policy_visible(name: str, principal: Principal) -> None:
    if not _policy_visible(name, principal):
        raise HTTPException(status_code=403, detail="Policy belongs to another tenant")


async def enforce_authn(request: Request) -> None:
    """Global gate: a valid token is required for every non-public path."""
    if not _auth.enabled or request.method == "OPTIONS":
        return
    if request.url.path in _PUBLIC_PATHS:
        return
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or _auth.authenticate(token.strip()) is None:
        raise HTTPException(
            status_code=401, detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


def reload_auth() -> None:
    """Re-read key configuration from the environment (used by tests)."""
    _auth.load_from_env()



def _clear_breaker(agent_name: str) -> None:
    """Clear an agent's ring-violation budget.

    AGT trips a circuit breaker after repeated ring violations and then denies
    everything from that agent, which is the intended defence against a rogue
    agent probing its sandbox. Because a session here lasts as long as the
    agent, the trip would otherwise be permanent — so resuming a suspended
    agent, the operator's explicit "this one is cleared to run" action, also
    clears the budget.
    """
    detector = _get_shared_breach_detector(agent_name, agent_name)
    detector.reset_breaker(agent_name, agent_name)


def _ring_for(trust_score: float) -> ExecutionRing:
    """AGT derives the execution ring from the trust score.

    Ring 3 (sandbox) below 0.60 — no network, filesystem or subprocess.
    Ring 2 (standard) above it. Ring 1 needs > 0.95 *and* consensus, which
    this playground does not model, so it is never reached.

    What a ring *forbids* is enforced by AGT's own RingEnforcer — see
    :func:`_ring_resource` for the part this platform has to supply.
    """
    return ExecutionRing.from_eff_score(trust_score)


# AGT's own enforcer, so the constraint table (what each ring permits) is the
# toolkit's rather than a copy of it.
_ring_enforcer = RingEnforcer()

# Which of AGT's four resource types a tool actually reaches for. Only
# mappings that are literally true are listed; everything else falls to
# TOOL_EXECUTION, which every ring permits, so an uncertain guess never
# becomes a denial.
_CATEGORY_RESOURCE = {
    "code_execution": ResourceType.SUBPROCESS,
    "filesystem":     ResourceType.FILESYSTEM,
    "network":        ResourceType.NETWORK,
    # A message leaves this host over the network whatever it is carried by.
    "communication":  ResourceType.NETWORK,
}


def _agt_infers_resource(action: str) -> ResourceType:
    """What AGT's own inference makes of an action string.

    Imported rather than reimplemented so the two can never disagree about
    which verbs AGT already understands — the whole point of asking is to know
    when to leave the decision to it.
    """
    try:
        from agentmesh.governance.govern import _infer_resource_type
        return _infer_resource_type(action or "")
    except Exception:       # pragma: no cover - AGT internals moved
        # Unknown means "assume AGT has nothing", which makes this supplement
        # do more work rather than less. That is the safe direction.
        return ResourceType.TOOL_EXECUTION


def _ring_resource(spec: dict) -> ResourceType:
    """The resource a governed call will actually use.

    ``govern()`` already runs AGT's ring check — but it infers the resource
    type from the *action string* by exact token match, which is all a
    decorator has to work with. That inference is blind to most of this
    registry: every MCP tool arrives as ``invoke``, and ``execute_command``
    misses AGT's ``exec`` token entirely, so both are classed TOOL_EXECUTION,
    which every ring permits. The demo's ring denials only fire because their
    verbs — ``web_search``, ``shell_exec`` — happen to carry a matching token.

    The registry knows what the string cannot say. This supplies that, and
    hands it to the same ``RingEnforcer`` AGT uses; the decision stays the
    toolkit's, only the input improves.
    """
    if (spec.get("mcp") or {}).get("transport") == "stdio":
        # Not a guess: dispatching a local MCP tool starts a process on this
        # host. That is a subprocess by any reading of the word.
        return ResourceType.SUBPROCESS
    return _CATEGORY_RESOURCE.get(spec.get("category"), ResourceType.TOOL_EXECUTION)


def _resolve_agent(ref: str):
    """Look up a ManagedAgent by readable name or by AGT agent_id."""
    return _lifecycle.get(_agent_ids.get(ref, ref))


def _agent_view(agent) -> dict:
    """Shape a ManagedAgent for the dashboard API."""
    stats = _call_stats.get(agent.name, {})
    trust = _trust_scores.get(agent.name, 0.0)
    return {
        "id": agent.name,
        "agent_id": agent.agent_id,
        "name": agent.name,
        "owner": agent.owner,
        "trust_score": trust,
        "state": agent.state.value,
        "status": "active" if agent.state == AgentLifecycleState.ACTIVE else agent.state.value,
        "ring": _ring_for(trust).name,
        "policy": _agent_policies.get(agent.name, "default-policy"),
        "did": _identity.did(agent.name),
        "created_at": agent.created_at.isoformat(),
        "calls": stats.get("calls", 0),
        "denials": stats.get("denials", 0),
        "foundry": _agent_foundry.get(agent.name),
        "capabilities": _agent_capabilities.get(agent.name, []),
    }


def _bump(agent_name: str, field: str) -> None:
    _call_stats.setdefault(agent_name, {"calls": 0, "denials": 0})
    _call_stats[agent_name][field] = _call_stats[agent_name].get(field, 0) + 1


# ── Default built-in policy written on startup ──────────────────────────────
DEFAULT_POLICY = {
    "apiVersion": "governance.toolkit/v1",
    "name": "default-policy",
    "description": "Baseline guardrails applied to every agent.",
    "default_action": "allow",
    "scope": "global",
    "conflict_strategy": DEFAULT_STRATEGY,
    "rules": [
        {"name": "block-destructive", "condition": 'action.type in ["drop","delete","truncate","shell_exec"]',
         "action": "deny", "description": "Destructive DB/shell ops blocked", "priority": 10},
        {"name": "block-pii", "condition": "input_text.has_pii",
         "action": "deny", "description": "PII detected in tool input", "priority": 20},
        {"name": "flag-elevated", "condition": 'action.type in ["send_email","write_file"]',
         "action": "warn", "description": "Elevated ops flagged", "priority": 50},
    ]
}


class Denied:
    """Marker returned by the govern() on_deny callback.

    Using on_deny rather than catching GovernanceDenied means ring denials,
    policy denials and rejected approvals all arrive through one AGT-defined
    path, carrying a PolicyDecision we can report verbatim.
    """

    __slots__ = ("decision",)

    def __init__(self, decision: PolicyDecision):
        self.decision = decision


def _register_tool(tool_name: str, policy_name: str = "default-policy",
                   agent_id: str = "*", ring: "ExecutionRing | None" = None):
    """Wrap a tool with govern(), bound to one agent and one execution ring.

    Three AGT features do the work here:
      - agent_id  : the policy is evaluated as this agent, not the "*" wildcard.
      - ring      : AGT enforces ring resource constraints *before* policy and
                    fails closed, with a circuit breaker shared per session.
      - on_deny   : denials return a PolicyDecision instead of raising.

    Callables are cached per (tool, policy, agent, ring) because building one
    re-reads and re-parses the policy YAML.
    """
    if not _policies.exists(policy_name):
        raise ValueError(f"Policy '{policy_name}' not found")

    # The strategy is part of the identity of a governed callable: two policies
    # with identical rules but different strategies decide differently.
    strategy = _policies.read(policy_name).get("conflict_strategy", DEFAULT_STRATEGY)
    key = (tool_name, policy_name, agent_id, ring, strategy)
    cached = _governed_tools.get(key)
    if cached is not None:
        return cached

    def _tool(action: str = "read", input_text: str = "", **kwargs):
        # Real execution: if the onboarded tool declares an HTTP(S) endpoint or
        # an MCP origin, actually invoke it (SSRF-guarded) and report the true
        # outcome. With neither, the call is honestly a governance decision only
        # — nothing is executed and nothing is fabricated.
        spec = _tools.get(tool_name) or {}
        if spec.get("kind") == "mcp":
            mcp = spec.get("mcp") or {}
            arguments = kwargs.get("arguments")
            arguments = arguments if isinstance(arguments, dict) else {}
            # ── Gate 5: AGT's MCP trust proxy, the last check before dispatch ──
            # Ring and policy have already allowed the call. This is the only
            # gate that sees the *arguments*, so a tool that graded clean at
            # import cannot be used to smuggle a poisoned payload afterwards.
            # It also carries the per-tool rate limit and the trust floor
            # derived from the tool's own descriptor grade. Raising aborts the
            # dispatch before any byte leaves; /tools/call turns it into the
            # same denial shape the other gates produce.
            # A tool whose descriptor changed after import is quarantined until
            # an operator re-imports it deliberately. A rug-pull detector that
            # only reported would leave the tool running on a descriptor nobody
            # approved, so this is a refusal, not a warning.
            if spec.get("quarantined"):
                raise MCPGateDenied(
                    "Tool is quarantined — its descriptor changed on the server "
                    "after it was imported (rug pull). Re-import it to approve "
                    "the new descriptor.",
                    "mcp_proxy:quarantined")
            # ── Gate 5a: parameters (AGT MCPGateway) ──────────────────────
            # A different question from the proxy's argument scan below. That
            # one looks for instructions aimed at the model; this looks for a
            # national ID, a payment card, `; rm -rf`, `$(...)` — sensitive data
            # on its way out and shell metacharacters on their way in. Neither
            # check subsumes the other.
            _mcp_params.inspect(agent_id=agent_id, tool_name=tool_name,
                                params=arguments)
            _mcp_gate.enforce(
                tool_name=tool_name,
                spec=spec,
                did=_identity.did(agent_id),
                trust_score=_trust_scores.get(agent_id, 0.0),
                capabilities=_agent_capabilities.get(agent_id, []),
                arguments=arguments,
            )
            # ── Gate 5c: the agent's own budget (AGT sliding window) ──────
            # Spent here, immediately before dispatch, so a call the gates
            # above refused is never charged for. The proxy's limit is per
            # tool; this one bounds the agent across every MCP tool at once,
            # and its window slides, so an agent that pauses recovers.
            _mcp_budget.spend(agent_id)
            outcome = mcp_connector.call_tool(
                mcp.get("server_url"), mcp.get("remote_tool"), arguments,
                timeout_ms=int(spec.get("timeout_ms", 3000)),
                allow_private=_tool_allow_private(),
                auth_env=mcp.get("auth_env"),
                transport=mcp.get("transport") or "auto",
                # Only set for a local server; the connector ignores them for a
                # remote one. Note the ordering this sits in: the process is
                # started *after* lifecycle, identity, tenant, trust, ring and
                # policy have all allowed the call, and after the trust proxy
                # above has scanned these very arguments.
                command=mcp.get("command"), args=mcp.get("args"),
                cwd=mcp.get("cwd"),
                env_passthrough=mcp.get("env_passthrough"),
                label=mcp.get("server") or "mcp",
            )
            # Everything governed so far flowed outward. This is the bytes
            # coming back, which reach the model verbatim — as good a place to
            # hide "ignore your instructions" as a descriptor. What may be
            # shown of an unsafe one is the gateway's ResponsePolicy, and a
            # sanitize verdict is re-scanned before it is honoured.
            scan, _content = _mcp_response_policy.apply(
                agent_id=agent_id, tool_name=tool_name, outcome=outcome)
            if scan["withheld"]:
                # The call already ran and its side effects are real; only the
                # content is withheld. Saying otherwise would be a lie about
                # what happened.
                outcome = {**outcome, "content": [], "structured_content": None,
                           "response_withheld": True}
            elif scan["action"] == "sanitized":
                # Verified: the sanitizer really did remove something, so what
                # is left is one text block rather than the original mixture.
                outcome = {**outcome,
                           "content": [{"type": "text", "text": _content}],
                           "structured_content": None,
                           "response_sanitized": True}
            return {"tool": tool_name, "action": action, "executed": True,
                    "kind": "mcp", "response_scan": scan, **outcome}
        endpoint = spec.get("endpoint_url")
        if not endpoint:
            return {
                "tool": tool_name, "action": action, "executed": False,
                # No scan field at all: nothing ran, so there is no response to
                # have scanned, and reporting one would be the same false
                # reassurance this path exists to avoid.
                "note": "Governance allowed the call; no endpoint is bound to "
                        "this tool, so nothing was executed.",
            }
        outcome = _invoke_tool(
            endpoint,
            {"tool": tool_name, "action": action, "input_text": input_text},
            timeout_ms=int(spec.get("timeout_ms", 3000)),
            allow_private=_tool_allow_private(),
        )
        # ACS `post_tool_call`. An endpoint's response reaches the model the
        # same way an MCP server's does, so it is held to the same standard —
        # for a long time only the MCP half was, which made the claim that
        # responses are scanned true of some tools and not others. The same
        # policy decides both, for the same reason.
        scan, _content = _mcp_response_policy.apply(
            agent_id=agent_id, tool_name=tool_name, outcome=outcome)
        if scan["withheld"]:
            # The request was really sent and whatever it did is done; only the
            # body is withheld. The status and latency stay because they are
            # facts about a call that happened.
            outcome = {**outcome, "response": "", "response_withheld": True}
        elif scan["action"] == "sanitized":
            outcome = {**outcome, "response": _content,
                       "response_sanitized": True}
        return {"tool": tool_name, "action": action, "executed": True,
                "kind": "webhook", "response_scan": scan, **outcome}

    _tool.__name__ = tool_name
    governed = govern(
        _tool,
        policy=str(_policies.path(policy_name)),
        agent_id=agent_id,
        ring=ring,
        session_id=agent_id,
        conflict_strategy=strategy,
        on_deny=Denied,
    )
    _governed_tools[key] = governed
    return governed


def _invalidate_policy_cache(name: str) -> None:
    """Evict every governed callable compiled from *name* or anything under it.

    AGT loads and merges a policy exactly once, in ``GovernedCallable.__init__``,
    so a cached callable holds the rules as they were when it was built. Evicting
    only the edited policy's own callables is not enough: a policy that extends
    it is merged *through* it, and its cached callables would go on enforcing the
    pre-edit merge until the process restarted. That is a silent fail-open on
    precisely the edit an operator makes to tighten a shared base policy, so the
    whole inheritance subtree goes.
    """
    stale = {name, *_policies.descendants(name)}
    for key in [k for k in _governed_tools if k[1] in stale]:
        _governed_tools.pop(key, None)


# ── Trust gate ───────────────────────────────────────────────────────────────
# One TrustPolicy, built once, used by BOTH /trust/evaluate and the
# enforcement path in /tools/call. Two evaluators with two thresholds is
# how a dashboard ends up reporting a denial the runtime does not apply.
MIN_TRUST = 0.3

_TRUST_POLICY = TrustPolicy(
    name="trust-gate",
    rules=[
        TrustRule(
            name="deny-low-trust",
            description=f"Deny agents with trust below {MIN_TRUST}",
            condition=TrustCondition(
                field="trust_score", operator=ConditionOperator.lt, value=MIN_TRUST
            ),
            action="deny",
            priority=5,
        ),
        TrustRule(
            name="min-trust",
            description=f"Trust score of at least {MIN_TRUST} required",
            condition=TrustCondition(
                field="trust_score", operator=ConditionOperator.gte, value=MIN_TRUST
            ),
            action="allow",
            priority=10,
        ),
    ],
    defaults=TrustDefaults(action="allow"),
)
_TRUST_EVALUATOR = PolicyEvaluator(policies=[_TRUST_POLICY])


def _evaluate_trust(agent_id: str, trust_score: float,
                    delegation_depth: int = 0, namespace: str = "default"):
    """Evaluate one agent context against the shared trust policy."""
    context = {
        "trust_score": trust_score,
        "delegation_depth": delegation_depth,
        "namespace": namespace,
        "agent_id": agent_id,
    }
    return _TRUST_EVALUATOR.evaluate(context), context


# ── State seeding and teardown ──────────────────────────────────────────
DEMO_AGENTS = [
    ("research-agent", 0.92),
    ("data-agent", 0.75),
    ("email-agent", 0.55),
    ("untrusted-agent", 0.18),
]

DEMO_TOOLS = ["db_query", "send_email", "web_search", "write_file"]

# Built-in demo tools, seeded into the registry so the playground works out of
# the box. All decision-only (no endpoint): onboard your own via /tools/register
# to attach a real webhook. `builtin` marks them undeletable.
BUILTIN_TOOLS = [
    ("db_query", "Query a datastore", ["read", "write", "drop"], "high", "data_write"),
    ("send_email", "Send an email on the agent's behalf", ["send_email"], "medium", "communication"),
    ("web_search", "Search the public web", ["read", "web_search"], "low", "search"),
    ("write_file", "Write to the workspace filesystem", ["write"], "medium", "filesystem"),
]


def _persist_meta() -> None:
    """Snapshot the non-secret agent sidecar (trust/tenant/policy) to disk."""
    if not _meta.durable:
        return
    _meta.save({
        name: {
            "trust": _trust_scores.get(name, 0.0),
            "tenant": _agent_tenant.get(name, DEFAULT_TENANT),
            "policy": _agent_policies.get(name, "default-policy"),
            "foundry": _agent_foundry.get(name),
            # AgentIdentity carries capabilities, but they do not survive the
            # public-JWK round-trip the identity store persists through, so the
            # non-secret sidecar is their durable home.
            "capabilities": _agent_capabilities.get(name, []),
        }
        for name in _agent_ids
    })


def _rehydrate_state(agents) -> None:
    """Rebuild the in-memory maps from persisted lifecycle + sidecar records."""
    meta = _meta.load()
    for a in agents:
        record = meta.get(a.name, {})
        _agent_ids[a.name] = a.agent_id
        _trust_scores[a.name] = record.get("trust", 0.0)
        _agent_tenant[a.name] = record.get("tenant", DEFAULT_TENANT)
        _agent_policies[a.name] = record.get("policy", "default-policy")
        _agent_capabilities[a.name] = list(record.get("capabilities") or [])
        foundry = record.get("foundry")
        if foundry:
            _agent_foundry[a.name] = foundry
    # Identities were reloaded from disk when IdentityStore was constructed.


def _seed_demo_agents() -> None:
    for name, trust in DEMO_AGENTS:
        managed = _lifecycle.request_provisioning(
            name=name, owner="demo@localhost",
            purpose="Seeded demo agent", actor="system",
        )
        # Seeded fixtures are approved by the platform that seeded them; the
        # approval gate exists for agents a caller registers.
        if managed.state == AgentLifecycleState.PENDING_APPROVAL:
            _lifecycle.approve(managed.agent_id, actor="system")
        _lifecycle.activate(managed.agent_id, actor="system")
        _agent_ids[name] = managed.agent_id
        _agent_policies[name] = "default-policy"
        _trust_scores[name] = trust
        _agent_tenant[name] = DEFAULT_TENANT
        _agent_capabilities[name] = list(DEMO_TOOLS)
        _identity.mint(name, sponsor="demo@localhost", capabilities=DEMO_TOOLS)
    _persist_meta()


def seed_state() -> None:
    """Populate the default policy, agents, SLOs and governed tools.

    When AGT_STATE_DIR holds persisted agents, rehydrate them instead of
    seeding demos — re-provisioning would collide, and re-minting would mint a
    *new* keypair and DID over the persisted one.
    """
    # Policies persist on disk, so only write the default when it is absent.
    if not _policies.exists("default-policy"):
        _policies.write("default-policy", DEFAULT_POLICY)

    # Restore which tenant owns each persisted policy (the default is shared).
    _load_policy_owners()

    # Load onboarded tools, then ensure the built-in demo tools exist so the
    # playground works even before anything is registered. Registered tools
    # (durable mode) are preserved; only missing built-ins are (re)added.
    _tools.load()
    for name, desc, actions, risk, category in BUILTIN_TOOLS:
        if not _tools.exists(name):
            _tools.register(name, description=desc, actions=actions,
                            risk=risk, category=category, builtin=True)

    # MCPSecurityScanner keeps fingerprints in memory, so without this a
    # restart would silently forget every baseline and no rug pull could ever
    # be detected again — precisely the failure being defended against.
    _mcp_descriptors.reseed(_tools.all())
    # The reversibility grades are in-memory too, and for the same reason must
    # be rebuilt from the durable registry rather than assumed.
    _reversibility.reseed(_tools.all())

    persisted = list(_lifecycle.agents)
    if persisted:
        _rehydrate_state(persisted)
    elif not _meta.durable:
        # Demo agents are a playground convenience for the ephemeral in-memory
        # mode. A durable deployment (AGT_STATE_DIR set) starts empty and is
        # populated by real registrations, not fixtures.
        _seed_demo_agents()

    if _slo.durable:
        # Durable mode: reload every persisted agent's SLO so its stored
        # measurements and error-budget burn come back after a restart.
        for agent_id in _agent_ids:
            _slo.ensure(agent_id)
    else:
        for agent_id in list(_agent_ids.keys())[:2]:
            _slo.ensure(agent_id)

    for tool in DEMO_TOOLS:
        try:
            _register_tool(tool, "default-policy")
        except Exception:
            # Not fatal — the playground still starts — but the Tool panel will
            # be missing a tool its own demo buttons reference.
            _log.warning("seed: could not govern demo tool %r with the default "
                         "policy; it will be absent from the playground",
                         tool, exc_info=True)


def teardown_state(clear_policies: bool = False) -> None:
    """Drop in-memory state and rebuild the stores from the environment.

    Policies are deliberately left on disk: they persist across restarts,
    which is the point of the file-backed store. Only the test suite asks
    for them to be cleared, so each test starts from the default policy.

    The durable stores are reconstructed from AGT_STATE_DIR here, so this
    doubles as a restart: any persisted agents/identities are reloaded.
    """
    global _lifecycle, _audit, _identity, _meta, _slo, _policy_meta, _tool_meta, _tools
    global _tracer
    if clear_policies:
        for name in _policies.names():
            _policies.path(name).unlink(missing_ok=True)
    for store in (_agent_policies, _trust_scores,
                  _identity, _governed_tools, _agent_ids, _call_stats,
                  _agent_tenant, _agent_foundry, _policy_tenant, _tools,
                  # Rate-limit budgets and the proxy's audit log are process
                  # state; without this a throttled agent stays throttled into
                  # the next test.
                  _agent_capabilities, _mcp_gate, _mcp_descriptors, _receipts,
                  _alerts, _anomaly, _last_chaos,
                  # The six AGT MCP controls. Each holds process state a test
                  # could otherwise inherit: a spent call budget, a pinned auth
                  # policy, a live caller token, a nonce already burned.
                  _mcp_admission, _mcp_vulns, _mcp_budget, _mcp_params,
                  _mcp_response_policy, _mcp_callers, _call_signer):
        store.clear()
    # AGT keeps breach detectors in its own module globals, so clearing our
    # stores is not enough to give a test a clean process.
    _reset_shared_breach_detectors()
    # Degradation is process state like the breach detectors, so a test that
    # induces a subsystem failure cannot leave the next one reporting a
    # demoted control.
    observability.reset()
    # The grades are process state too: a torn-down instance must not answer
    # for the tools of the one before it.
    _reversibility.clear()
    _sessions.clear()
    _lifecycle = LifecycleManager(
        policy=LifecyclePolicy(require_approval=_require_approval(), require_owner=True),
        storage_path=_state_file("agents.json"),
    )
    _identity = IdentityStore(storage_path=_state_file("identities.json"))
    _meta = MetaStore(_state_file("agent_meta.json"))
    _policy_meta = MetaStore(_state_file("policy_owners.json"))
    _tool_meta = MetaStore(_state_file("tools.json"))
    _tools = ToolRegistry(_tool_meta)
    _audit = AuditStore()
    # Rebuilt from the environment too, so a durable SLO directory is picked
    # up (or dropped) exactly like the other state stores on a restart.
    _slo = SLOStore(storage_dir=_slo_dir())
    # Rebuilt, not cleared: a restart must not lose the trace of the call that
    # caused the incident being investigated. Tests isolate by pointing
    # AGT_STATE_DIR at a fresh directory, exactly as the other durable stores do.
    _tracer = CallTracer(storage_dir=_state_file("traces"))


def reset_state() -> None:
    """Return the process to a freshly-seeded state.

    Exists for the test suite: every module-level store is rebuilt, so one
    test killing an agent or rewriting a trust score cannot reach the next.
    The facet registration is deliberately left alone — it lives on AGT's
    default_registry and registering it twice would double-run the extractor.
    """
    teardown_state(clear_policies=True)
    seed_state()


# ── Lifespan ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    seed_state()
    yield
    teardown_state()


app = FastAPI(title="AgentGuard API", lifespan=lifespan,
              dependencies=[Depends(enforce_authn)])

# CORS is an allowlist, not "*". Override with AGT_CORS_ORIGINS (comma-separated);
# the default is the local React dev server. allow_credentials is on, which the
# browser forbids alongside a wildcard origin anyway.
_cors_origins = [
    o.strip() for o in
    os.getenv("AGT_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════
# REQUEST MODELS
# ═══════════════════════════════════════════════════════════════════════════

class PolicyRuleIn(BaseModel):
    name: str
    condition: str
    action: str = "deny"                 # allow | deny | warn | require_approval | log
    description: str = ""
    priority: int = 50
    # govern() always evaluates at pre_tool; anything else never fires here.
    stage: str = "pre_tool"
    limit: Optional[str] = None          # rate limit, e.g. "100/hour"
    approvers: list[str] = []            # used when action == require_approval
    enabled: bool = True


class PolicyIn(BaseModel):
    name: str
    description: str = ""
    version: str = "1.0"
    default_action: str = "allow"
    rules: list[PolicyRuleIn] = []
    # Parent policy names. AGT merges parents first, additive-only.
    extends: list[str] = []
    # Only consulted by the most_specific_wins strategy.
    scope: str = "global"
    conflict_strategy: str = DEFAULT_STRATEGY
    agents: list[str] = []               # empty means all agents


class PolicyUpdateIn(PolicyIn):
    """Same shape as create; the name in the path wins."""
    name: str = ""

class ShadowIn(BaseModel):
    """Dry-run a candidate policy against the one currently in force."""
    # Either an unsaved draft, or the name of a policy already stored.
    candidate: "PolicyIn | None" = None
    candidate_name: str = ""
    # What is live today. The comparison is policy against policy.
    baseline: str = "default-policy"
    # How many recent governed calls to replay the contexts of.
    limit: int = 200


class EvaluateIn(BaseModel):
    policy_name: str = "default-policy"
    agent_id: str = "*"
    # Supply call arguments and the context is built exactly as /tools/call
    # builds it. Supply a raw context instead to debug rules directly.
    action: Optional[str] = None
    input_text: str = ""
    # Name a registered tool and its facet is built the same way too, so a rule
    # on tool.category is testable here before it is enforced.
    tool_name: Optional[str] = None
    kwargs: dict[str, Any] = {}
    context: Optional[dict[str, Any]] = None

class AttestationIn(BaseModel):
    nonce: str
    signature: str

class ToolCallIn(BaseModel):
    # Bind this call to an open session. Optional: without one the call is
    # decided exactly as before, which is what every existing caller does.
    session_id: Optional[str] = None
    # A caller credential from POST /mcp/sessions, proving the agent_id below
    # is not merely self-asserted. Unrelated to session_id above: that one is
    # an AGT Hypervisor workspace, this one is identity. Optional, but a token
    # that is presented must verify — see the identity gate in /tools/call.
    mcp_session_token: Optional[str] = None
    tool_name: str
    policy_name: str = "default-policy"
    action: str = "read"
    input_text: str = ""
    agent_id: str = "research-agent"
    kwargs: dict[str, Any] = {}
    # When present, the caller proves possession of the agent's private key.
    # When absent, the agent_id is self-asserted (legacy) and flagged as such.
    attestation: Optional[AttestationIn] = None

class ToolRegisterIn(BaseModel):
    name: str
    description: str = ""
    actions: list[str] = []
    risk: str = "medium"
    # What the tool is for. Policies target this rather than a tool name, so a
    # rule keeps holding as tools are added and removed.
    category: str = DEFAULT_CATEGORY
    # Optional HTTP(S) webhook. When set, an allowed call really invokes it
    # (SSRF-guarded); when absent the tool is governance-decision-only.
    endpoint_url: Optional[str] = None
    timeout_ms: int = 3000

class SessionOpenIn(BaseModel):
    # AGT's own ceilings are the defaults; both are its numbers, not ones
    # chosen here.
    max_participants: int = sessions.DEFAULT_MAX_PARTICIPANTS
    max_seconds: int = sessions.DEFAULT_MAX_SECONDS
    # The floor AGT applies when it resolves a joining agent's score. It never
    # promotes above what the trust score gives.
    min_eff_score: float = 0.6


class SessionJoinIn(BaseModel):
    agent_id: str


class MCPDiscoverIn(BaseModel):
    # A remote server is addressed by URL, a local one by the command that
    # launches it. Exactly one form is used, decided by `transport`.
    server_url: str = ""
    # "http" is Streamable HTTP, "sse" the legacy 2024-11-05 HTTP+SSE transport,
    # "auto" tries the former then the latter. "stdio" launches a local server
    # and speaks to it over the child's stdin/stdout — "auto" never chooses it.
    transport: str = "auto"
    # stdio only. The command is validated against AGT's own allowlist inside
    # its client at spawn time; `env_passthrough` names AGT_MCP_* variables to
    # hand the child, never their values.
    command: str = ""
    args: list[str] = []
    cwd: Optional[str] = None
    env_passthrough: list[str] = []
    # Used for this request only and never persisted: the registry holds no
    # secrets. An imported tool names an AGT_MCP_* variable instead.
    auth_token: Optional[str] = None
    timeout_ms: int = 8000

class MCPImportIn(MCPDiscoverIn):
    # Label the imported tools are namespaced under; defaults to the name the
    # server reports for itself.
    server_name: str = ""
    # Which discovered tools to onboard. Empty means every one of them.
    tools: list[str] = []
    # Refuse to onboard anything the descriptor evaluation grades above this
    # tier. None imports everything, each carrying its evaluation.
    max_risk: Optional[str] = None
    # Only onboard tools in these capability categories. Empty means all.
    categories: list[str] = []
    # Name of the environment variable holding the server's bearer token.
    auth_env: Optional[str] = None
    # Capabilities an agent must hold to dispatch any tool from this import.
    # Enforced by AGT's trust proxy at call time; empty gates nothing.
    required_capabilities: list[str] = []
    timeout_ms: int = 8000
    call_timeout_ms: int = 5000

class MCPSessionIn(BaseModel):
    agent_id: str
    # Carried into the session's rate_limit_key, so a multi-tenant caller can
    # be budgeted per user rather than per agent.
    user_id: Optional[str] = None
    # Optional proof the caller holds the agent's key. When present it must
    # verify, which is what lets an agent mint its own token instead of asking
    # an operator for one.
    attestation: Optional["AttestationIn"] = None


class MCPRulesIn(BaseModel):
    # A candidate rule file, checked without installing it.
    content: str
    # "mcp" for the descriptor rules, "injection" for the prompt-injection set.
    kind: str = "mcp"


class MCPAdvisoryIn(BaseModel):
    package: str
    version: str
    cve_id: str
    severity: str = "HIGH"
    summary: str = ""
    fixed_version: str = ""


class ChallengeIn(BaseModel):
    agent_id: str

class AttestIn(BaseModel):
    agent_id: str
    nonce: str
    signature: str

class AgentIn(BaseModel):
    id: str
    name: str
    trust_score: float = 0.8
    policy: str = "default-policy"
    # LifecycleManager requires an owner: every agent must be attributable.
    owner: str = "unassigned@localhost"
    purpose: str = ""
    # Capabilities the agent holds. An onboarded MCP tool may require some, in
    # which case AGT's trust proxy denies the dispatch unless the agent has
    # every one of them. Empty is the default and gates nothing.
    capabilities: list[str] = []
    # Optional link to a Microsoft Foundry (Azure AI Agents) agent, recorded so
    # the dashboard twin can be traced back to its source and fed run-step
    # telemetry. Purely descriptive: the backend never calls the Foundry SDK.
    project_endpoint: str = ""
    foundry_agent_id: str = ""

class TrustEvalIn(BaseModel):
    agent_id: str
    trust_score: float
    delegation_depth: int = 0
    namespace: str = "default"

class ChaosRunIn(BaseModel):
    """Options for one adversarial run."""
    # AGT's eight built-in vectors, and the four aimed at this platform's gates.
    include_builtin: bool = True
    include_local: bool = True
    policy_name: str = "default-policy"
    # The attacker's trust. High by default on purpose: a weak attacker is
    # stopped at the trust gate and tells you nothing about what lies behind it.
    attacker_trust: float = chaos_runner.STRONG_TRUST


class SLOIn(BaseModel):
    agent_id: str
    slo_name: str
    target: float = 0.99

class ComplianceIn(BaseModel):
    prompt: str
    agent_id: str = "test-agent"


# One execution event an agent reports after the fact. Unlike /tools/call
# (a decision the platform makes and authoritatively audits), these are
# self-reported telemetry: they feed the observational SLOs and a summarised
# audit note, never an authoritative allow/deny verdict.
class IngestEvent(BaseModel):
    tool: str
    action: str = "read"
    allowed: bool = True
    policy_denied: bool = False
    latency_ms: float = 0.0
    error: Optional[str] = None
    timestamp: Optional[str] = None   # agent clock, informational only


class IngestIn(BaseModel):
    agent_id: str
    events: list[IngestEvent]


class FoundrySyncIn(BaseModel):
    # Raw Microsoft Foundry RunStep dicts, as produced by
    # `[s.as_dict() for s in project.agents.run_steps.list(...)]`. The backend
    # maps them to telemetry events; it never calls the Foundry SDK itself.
    run_steps: list[dict]



# ═══════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0", "agents": len(_lifecycle.agents), "policies": len(_policies.names())}


# ═══════════════════════════════════════════════════════════════════════════
# POLICY ENGINE  /policies
# ═══════════════════════════════════════════════════════════════════════════

def _policy_doc(body: "PolicyIn | PolicyUpdateIn", name: str) -> dict:
    """Turn a request body into the document that will be written."""
    return {
        "apiVersion": API_VERSION,
        "name": name,
        "description": body.description,
        "version": body.version,
        "default_action": body.default_action,
        "scope": body.scope,
        "conflict_strategy": body.conflict_strategy,
        "agents": body.agents,
        "extends": body.extends,
        "rules": [r.model_dump() for r in body.rules],
    }


def _policy_view(name: str) -> dict:
    """Authored document plus everything the editor needs to render it."""
    doc = _policies.read(name)
    return {
        **doc,
        "owner_tenant": _policy_owner(name),
        "warnings": _policy_warnings(doc),
        "dependents": _policies.dependents(name),
    }


def _policy_warnings(doc: dict) -> list[dict]:
    """Every way a rule in this document can silently fail to fire.

    Four classes, all of which AGT accepts without complaint:
      1. a condition its grammar cannot parse;
      2. a condition naming a field nothing puts in the context;
      3. a stage other than pre_tool, which govern() never evaluates;
      4. a rule disabled outright.
    Only the first is also a hard rejection — see :func:`_unknown_fields` for
    why the second warns instead. Inheritance drops are reported separately by
    /policies/{name}/resolved, because detecting them needs the merged policy.

    Every entry carries `kind`, `unparsable` and `effect`, including when
    `unparsable` is empty, so a reader cannot assume the reason from the shape.
    """
    out = list(_lint_rules(doc.get("rules", [])))
    for rule in doc.get("rules", []):
        name, cond = rule.get("name", "?"), rule.get("condition", "")
        for unknown in _unknown_fields(cond):
            hint = (" Did you mean "
                    + ", ".join(f"`{f}`" for f in unknown["did_you_mean"])
                    + "?") if unknown["did_you_mean"] else ""
            out.append({
                "rule": name,
                "condition": cond,
                "kind": "unknown_field",
                "unparsable": [],
                "unknown_field": unknown["path"],
                "did_you_mean": unknown["did_you_mean"],
                "effect": (
                    f"`{unknown['path']}` is not a field this platform puts in "
                    f"the policy context, so the clause has nothing to compare "
                    f"and the rule will not match — unless the caller supplies "
                    f"it through the call's own kwargs.{hint}"
                ),
            })
        if rule.get("stage", "pre_tool") != "pre_tool":
            out.append({
                "rule": name,
                "condition": cond,
                "kind": "stage",
                "unparsable": [],
                "effect": (
                    f"Stage is {rule.get('stage')!r}, but govern() evaluates at "
                    "'pre_tool' — this rule never fires in this dashboard."
                ),
            })
        if rule.get("enabled", True) is False:
            out.append({
                "rule": name,
                "condition": cond,
                "kind": "disabled",
                "unparsable": [],
                "effect": "Rule is disabled.",
            })
    return out


def _reject(err: "PolicyError | str", warnings: "list | None" = None):
    raise HTTPException(400, {
        "error": str(err),
        "warnings": warnings or [],
        "grammar": _GRAMMAR_HELP,
    })


def _save_policy(name: str, body, *, creating: bool, tenant: "str | None" = None):
    """Validate, then persist. Nothing is written unless AGT can parse it.

    ``tenant`` is the tenant that will own (or already owns) the policy, so the
    audit entry is scoped the same way the policy itself is. It is passed in
    rather than looked up because on creation the ownership stamp is applied by
    the caller *after* this returns, and a shared policy legitimately has none.
    """
    doc = _policy_doc(body, name)

    dead = _lint_rules(doc["rules"])
    if dead:
        _reject("Policy contains conditions AGT cannot evaluate", dead)

    try:
        _policies.validate(name, doc)
    except PolicyError as e:
        _reject(e)

    _policies.write(name, doc)
    # Cached callables carry the old rules and strategy — this policy's own,
    # and those of everything that inherits from it.
    _invalidate_policy_cache(name)
    _emit_audit("policy.created" if creating else "policy.updated", "system", {
        "policy": name, "rules": len(doc["rules"]), "extends": doc["extends"],
    }, tenant=tenant)
    return _policy_view(name)


@app.get("/policies/schema")
def policy_schema():
    """Everything the editor needs to build a valid policy.

    Served from the same constants the linter and store use, so the UI cannot
    offer an operator or field the backend would then reject.
    """
    return {
        # Each operator carries both directions: `template` renders a clause,
        # `pattern` reads one back. The editor uses only these, so it cannot
        # emit a form the backend would reject, nor fail to re-open its own
        # output. Capture groups are (field, value); `truthy` has no value.
        "operators": [
            {"id": "eq", "label": "equals", "value": "single", "types": ["string"],
             "template": "{field} == '{value}'",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s*==\s*['\"]([^'\"]+)['\"]$"},
            {"id": "ne", "label": "does not equal", "value": "single", "types": ["string"],
             "template": "{field} != '{value}'",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s*!=\s*['\"]([^'\"]+)['\"]$"},
            {"id": "in", "label": "is one of", "value": "list", "types": ["string"],
             "template": "{field} in [{value}]",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s+in\s+\[([^\]]*)\]$"},
            {"id": "gt", "label": "greater than", "value": "number", "types": ["number"],
             "template": "{field} > {value}",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s*>\s*(\d+(?:\.\d+)?)$"},
            {"id": "gte", "label": "at least", "value": "number", "types": ["number"],
             "template": "{field} >= {value}",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s*>=\s*(\d+(?:\.\d+)?)$"},
            {"id": "lt", "label": "less than", "value": "number", "types": ["number"],
             "template": "{field} < {value}",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s*<\s*(\d+(?:\.\d+)?)$"},
            {"id": "lte", "label": "at most", "value": "number", "types": ["number"],
             "template": "{field} <= {value}",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)\s*<=\s*(\d+(?:\.\d+)?)$"},
            {"id": "truthy", "label": "is true", "value": "none", "types": ["boolean"],
             "template": "{field}",
             "pattern": r"^([A-Za-z_][A-Za-z0-9_.]*)$"},
        ],
        # Characters and substrings that must never reach a clause value.
        # AGT has no escaping: a quote breaks the atom regex, a "]" truncates
        # an `in` list, and " and " / " or " are split before atoms are read,
        # so any of them silently turns the rule into one that never matches.
        "value_forbidden": {
            # Break any clause: the atom regexes bound values with quotes, and
            # " and " / " or " are split off before atoms are ever read.
            "characters": ["'", "\"", "\\n"],
            "substrings": [" and ", " or "],
            # Breaks only the bracketed list form, whose regex stops at "]".
            "by_operator": {"in": {"characters": ["]"]}},
            "note": (
                "AGT provides no escaping. A value containing any of these "
                "produces a rule that parses as nonsense and never fires."
            ),
        },
        "joiners": [" and ", " or "],
        "fields": list(_POLICY_FIELDS),
        "actions": ["allow", "deny", "warn", "require_approval", "log"],
        "stages": ["pre_input", "pre_tool", "post_tool", "pre_output"],
        "enforced_stage": "pre_tool",
        "scopes": list(POLICY_SCOPES),
        "conflict_strategies": list(CONFLICT_STRATEGIES),
        "default_conflict_strategy": DEFAULT_STRATEGY,
        "scope_note": (
            "scope is only consulted by the most_specific_wins strategy; "
            "under any other strategy it has no effect."
        ),
        "grammar": _GRAMMAR_HELP,
    }


@app.get("/policies")
def list_policies(principal: Principal = Depends(current_principal)):
    return [_policy_view(n) for n in _policies.names()
            if _policy_visible(n, principal)]


@app.post("/policies")
def create_policy(body: PolicyIn, principal: Principal = Depends(require_operator)):
    try:
        if _policies.exists(body.name):
            raise HTTPException(400, f"Policy '{body.name}' already exists")
        view = _save_policy(body.name, body, creating=True,
                            tenant=principal.tenant)
        # Stamp the new policy with its author's tenant so only that tenant
        # (or an admin) can later see, edit, delete or enforce it.
        _set_policy_owner(body.name, principal.tenant)
        view["owner_tenant"] = _policy_owner(body.name)
        return view
    except PolicyError as e:
        _reject(e)


@app.post("/policies/validate")
def validate_policy(body: PolicyIn):
    """Check a draft without saving it. Used by the editor on every keystroke."""
    try:
        return _validate_policy(body)
    except PolicyError as e:
        return {"valid": False, "error": str(e), "warnings": [],
                "grammar": _GRAMMAR_HELP}


def _validate_policy(body: PolicyIn):
    doc = _policy_doc(body, body.name or "draft")
    warnings = _policy_warnings(doc)
    dead = _lint_rules(doc["rules"])
    try:
        resolved = _policies.validate(body.name or "draft", doc)
    except PolicyError as e:
        return {"valid": False, "error": str(e), "warnings": warnings,
                "grammar": _GRAMMAR_HELP}
    return {
        "valid": not dead,
        "error": None,
        "warnings": warnings,
        "resolved_rule_count": len(resolved.rules),
        "grammar": _GRAMMAR_HELP,
    }


@app.get("/policies/{name}")
def get_policy(name: str, principal: Principal = Depends(current_principal)):
    try:
        if not _policies.exists(name):
            raise HTTPException(404, "Policy not found")
    except PolicyError:
        raise HTTPException(404, "Policy not found")
    _require_policy_visible(name, principal)
    try:
        return _policy_view(name)
    except PolicyError:
        raise HTTPException(404, "Policy not found")


@app.put("/policies/{name}")
def update_policy(name: str, body: PolicyUpdateIn,
                  principal: Principal = Depends(require_operator)):
    try:
        if not _policies.exists(name):
            raise HTTPException(404, "Policy not found")
        _require_policy_visible(name, principal)
        return _save_policy(name, body, creating=False,
                            tenant=_policy_owner(name))
    except PolicyError as e:
        _reject(e)


@app.get("/policies/{name}/yaml")
def get_policy_yaml(name: str, principal: Principal = Depends(current_principal)):
    """The policy exactly as it sits on disk, for the read-only YAML pane."""
    if not _safe_exists(name):
        raise HTTPException(404, "Policy not found")
    _require_policy_visible(name, principal)
    return {"name": name, "yaml": _policies.yaml_text(name)}


def _safe_exists(name: str) -> bool:
    """exists() that treats an invalid name as simply absent."""
    try:
        return _policies.exists(name)
    except PolicyError:
        return False


@app.get("/policies/{name}/resolved")
def get_policy_resolved(name: str, principal: Principal = Depends(current_principal)):
    """The merged policy AGT enforces, with each rule's origin.

    Differs from the authored document whenever `extends` is used: inherited
    rules appear here, and child rules AGT dropped are listed separately.
    """
    if not _safe_exists(name):
        raise HTTPException(404, "Policy not found")
    _require_policy_visible(name, principal)
    try:
        return _policies.resolved_detail(name)
    except PolicyError as e:
        raise HTTPException(400, str(e))


@app.delete("/policies/{name}")
def delete_policy(name: str, principal: Principal = Depends(require_admin)):
    if name == "default-policy":
        raise HTTPException(400, "Cannot delete the default policy")
    if not _safe_exists(name):
        raise HTTPException(404, "Policy not found")
    _require_policy_visible(name, principal)
    try:
        _policies.delete(name)
    except PolicyError as e:
        raise HTTPException(409, str(e))
    owner = _policy_owner(name)
    _drop_policy_owner(name)
    _invalidate_policy_cache(name)
    _emit_audit("policy.deleted", "system", {"policy": name}, tenant=owner)
    return {"status": "deleted"}


@app.post("/policies/shadow")
def shadow_policy(body: ShadowIn, principal: Principal = Depends(require_operator)):
    """Report what a candidate policy would change, without enforcing it.

    Contexts come from the audit chain, so the replay is over calls this
    platform really saw. The production verdict is the *baseline policy
    re-evaluated now*, not the verdict recorded at the time — a call denied at
    the trust gate never reached policy, and counting it as a policy decision
    would credit a rule with a gate's work.

    A draft is compiled through a throwaway policy file because AGT resolves
    `extends` relative to the policy directory; it is removed in `finally`.
    """
    if not _policies.exists(body.baseline):
        raise HTTPException(404, f"Baseline policy '{body.baseline}' not found")
    _require_policy_visible(body.baseline, principal)

    temp_name = ""
    try:
        if body.candidate is not None:
            temp_name = policy_shadow.draft_name()
            doc = _policy_doc(body.candidate, temp_name)
            dead = _lint_rules(doc["rules"])
            if dead:
                _reject("Candidate contains conditions AGT cannot evaluate", dead)
            try:
                _policies.validate(temp_name, doc)
            except PolicyError as e:
                _reject(e)
            _policies.write(temp_name, doc)
            candidate_name = temp_name
            candidate_doc = doc
        elif body.candidate_name:
            if not _policies.exists(body.candidate_name):
                raise HTTPException(404, f"Policy '{body.candidate_name}' not found")
            _require_policy_visible(body.candidate_name, principal)
            candidate_name = body.candidate_name
            candidate_doc = _policies.read(body.candidate_name)
        else:
            raise HTTPException(400, "Provide either a candidate draft or a candidate_name")

        # Both engines are obtained the way the enforcement path obtains one, so
        # a shadow verdict is produced by the same machinery a real call meets.
        baseline_engine = _register_tool("__shadow_baseline__", body.baseline).engine
        candidate_engine = _register_tool("__shadow_candidate__", candidate_name).engine

        baseline_doc = _policies.read(body.baseline)
        text_rules = policy_shadow.text_dependent_rules(baseline_doc, candidate_doc)
        uncertain = {r["rule"] for r in text_rules}

        entries = _audit.entries(limit=max(1, min(int(body.limit), 1000)) * 4)
        contexts = policy_shadow.contexts_from_audit(
            [_serialise_entry(e) for e in entries],
            limit=max(1, min(int(body.limit), 1000)),
        )

        def facets_for(agent_id, tool):
            agent = _resolve_agent(agent_id or "")
            trust = _trust_scores.get(agent_id or "", 0.0)
            agent_facet = {
                "id": agent_id, "agent_id": getattr(agent, "agent_id", agent_id),
                "trust_score": trust,
                "state": agent.state.value if agent is not None else "unknown",
                "ring": _ring_for(trust).value,
            }
            spec = _tools.get(tool or "") or {}
            tool_facet = {
                "name": tool, "category": spec.get("category", DEFAULT_CATEGORY),
                "risk": spec.get("risk", "medium"), "kind": spec.get("kind", "webhook"),
                "builtin": bool(spec.get("builtin")),
                **_reversibility.facet(tool or ""),
            }
            return agent_facet, tool_facet

        report = policy_shadow.compare(
            baseline_engine=baseline_engine,
            candidate_engine=candidate_engine,
            contexts=contexts,
            facets_for=facets_for,
            uncertain_rules=uncertain,
        )
    finally:
        if temp_name:
            _policies.path(temp_name).unlink(missing_ok=True)
            for key in [k for k in _governed_tools if k[1] == temp_name]:
                _governed_tools.pop(key, None)

    report["baseline"] = body.baseline
    report["candidate"] = body.candidate_name or "(unsaved draft)"
    # Named, not implied: a rule the replay could not feed is a caveat on the
    # number above it.
    report["text_dependent_rules"] = text_rules
    report["replay_limitation"] = (
        "The audit chain records the agent, tool and action of a governed call "
        "but not its input_text, so rules reading input_text (has_pii, "
        "has_credentials) cannot be replayed faithfully. Comparisons resting on "
        "one are reported as uncertain rather than counted."
    ) if text_rules else None
    _emit_audit("policy.shadow", principal.subject or "system", {
        "baseline": body.baseline, "candidate": report["candidate"],
        "replayed": report["replayed"], "diverged": report["diverged"],
        "would_newly_deny": report["would_newly_deny"],
        "would_newly_allow": report["would_newly_allow"],
    }, tenant=None if principal.is_admin else principal.tenant)
    return report


@app.post("/policies/evaluate")
def evaluate_policy(body: EvaluateIn,
                    principal: Principal = Depends(current_principal)):
    """Evaluate a context against a stored policy.

    This runs the *same* PolicyEngine instance that enforces the policy in
    /tools/call — obtained from the governed callable itself — so the two
    cannot report different verdicts for the same policy and input.

    It evaluates the policy gate only. A call that this endpoint allows can
    still be stopped by the lifecycle, trust or ring gates that run first;
    the response lists them so the difference is never a surprise.
    """
    if not _policies.exists(body.policy_name):
        raise HTTPException(404, "Policy not found")
    # Reading a policy is gated by tenant; probing one has to be too. Without
    # this, a caller who cannot GET another tenant's policy could still recover
    # its rules by evaluating contexts against it and watching the verdicts
    # flip — the same disclosure, taken a question at a time.
    _require_policy_visible(body.policy_name, principal)

    # Reuse the enforcement callable so the engine, the loaded policy and the
    # agent binding are identical to the ones a real tool call would hit.
    try:
        governed = _register_tool("__policy_probe__", body.policy_name, body.agent_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if body.context is not None:
        context = dict(body.context)
    else:
        # Built by AGT from call arguments, exactly as /tools/call does —
        # including the agent facet, or a rule using agent.trust_score would
        # behave differently here than at the enforcement point.
        extra = dict(body.kwargs)
        agent = _resolve_agent(body.agent_id)
        if agent is not None and "agent" not in extra:
            trust = _trust_scores.get(agent.name, 0.0)
            extra["agent"] = {
                "id": agent.name,
                "agent_id": agent.agent_id,
                "trust_score": trust,
                "state": agent.state.value,
                "ring": _ring_for(trust).value,
            }
        if "ring" not in extra:
            # govern() injects this during a real call; the evaluator builds
            # its own context and would otherwise predict a ring.* rule as
            # never matching. Same source — AGT's constraint table.
            _ring = _ring_for(_trust_scores.get(body.agent_id, 0.0))
            _constraints = _ring_enforcer.get_constraints(_ring)
            extra["ring"] = {
                "level": _ring.value,
                "network_allowed": _constraints.network_allowed,
                "subprocess_allowed": _constraints.subprocess_allowed,
                "filesystem_writable": _constraints.filesystem_writable,
            }
        if body.tool_name and "tool" not in extra:
            spec = _tools.get(body.tool_name)
            if spec is None:
                raise HTTPException(404, f"Tool '{body.tool_name}' is not registered")
            extra["tool"] = {
                "name": body.tool_name,
                "category": spec.get("category", DEFAULT_CATEGORY),
                "risk": spec.get("risk", "medium"),
                "kind": spec.get("kind", "webhook"),
                "builtin": bool(spec.get("builtin")),
                **_reversibility.facet(body.tool_name),
            }
        context = _build_call_context(governed, body.action or "read",
                                      body.input_text, extra)

    decision = governed.engine.evaluate(body.agent_id, context)

    return {
        "allowed": decision.allowed,
        "rule_name": decision.matched_rule,
        "action": decision.action,
        "reason": decision.reason,
        "policy": body.policy_name,
        "evaluated_by": "agentmesh.governance.PolicyEngine",
        "gate": "policy",
        "other_gates": ["lifecycle", "trust", "ring"],
        # Post-enrichment context: what the rules were actually evaluated against.
        "context": context,
        "warnings": _policy_warnings(_policies.read(body.policy_name)),
    }


def _build_call_context(governed, action: str, input_text: str, extra: dict) -> dict:
    """Build a policy context the way govern() does for a real call.

    AGT keeps this on GovernedCallable as a private method; calling it here
    is deliberate, because reimplementing the shaping rules is exactly how
    the Policy panel and the enforcement path drifted apart before.
    """
    kwargs = {"action": action, "input_text": input_text, **(extra or {})}
    context = governed._build_context((), kwargs)
    # PolicyEngine.evaluate() enriches internally; do it here too so the
    # context we return matches what the rules see.
    from agentmesh.governance.protocol_facets import extract_protocol_facets
    return extract_protocol_facets(context)


# ═══════════════════════════════════════════════════════════════════════════
# GOVERNED TOOL EXECUTION  /tools
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/tools")
def list_tools():
    """The onboarded tool registry plus the governed callables built so far.

    `available` and `registered` are driven by the registry, not a hardcoded
    list: onboard a tool via POST /tools/register and it appears here.
    """
    # The trust proxy derives a tool's runtime policy from its own descriptor
    # grade, and does it deterministically — so reporting it here is surfacing
    # what will happen at dispatch, not predicting it. The UI shows it beside
    # the findings that produced it, which is the question an operator is
    # actually asking when they open a grade: "and what does that *do*?"
    registered = _tools.all()
    for spec in registered:
        # Graded in memory from the descriptor, so it is reported rather than
        # stored — the same treatment the runtime policy below gets.
        spec.update(_reversibility.facet(spec["name"]))
        if spec.get("kind") == "mcp":
            try:
                spec["runtime_policy"] = _mcp_gate.describe(spec["name"], spec)
            except Exception:       # pragma: no cover - reporting must not fail
                spec["runtime_policy"] = None

    return {
        "tools": sorted({k[0] for k in _governed_tools}),
        "available": _tools.names(),
        "registered": registered,
        "categories": list(TOOL_CATEGORIES),
        "mcp_transports": list(MCP_TRANSPORTS),
        "allow_private_endpoints": _tool_allow_private(),
    }


@app.post("/tools/register")
def register_tool(body: ToolRegisterIn,
                  principal: Principal = Depends(require_operator)):
    """Onboard (or update) a tool the platform will govern and evaluate.

    A tool with an `endpoint_url` is really invoked on an allowed call; without
    one it is a governance-decision-only tool. Endpoints are SSRF-validated at
    registration: non-HTTP schemes and private/loopback targets are rejected
    unless AGT_TOOL_ALLOW_PRIVATE is set for local development.
    """
    try:
        spec = _register_reversibility(_tools.register(
            body.name, description=body.description, actions=body.actions,
            risk=body.risk, endpoint_url=body.endpoint_url,
            timeout_ms=body.timeout_ms, created_by=principal.subject or None,
            category=body.category, allow_private=_tool_allow_private(),
        ))
    except ToolError as e:
        raise HTTPException(400, str(e))
    # Drop any cached governed callables for this tool so the new endpoint takes
    # effect immediately rather than through a stale wrapper.
    for key in [k for k in _governed_tools if k[0] == spec["name"]]:
        _governed_tools.pop(key, None)
    _emit_audit("tool.registered", principal.subject or "system", {
        "tool": spec["name"], "risk": spec["risk"],
        "category": spec["category"],
        "endpoint": bool(spec.get("endpoint_url")),
    }, allowed=True)
    return spec


@app.delete("/tools/{name}")
def delete_tool(name: str, principal: Principal = Depends(require_admin)):
    """Remove an onboarded tool. Built-in demo tools are protected."""
    spec = _tools.get(name)
    if spec is None:
        raise HTTPException(404, f"Tool '{name}' not found")
    if spec.get("builtin"):
        raise HTTPException(400, "Built-in demo tools cannot be removed")
    _tools.remove(name)
    for key in [k for k in _governed_tools if k[0] == name]:
        _governed_tools.pop(key, None)
    _reversibility.forget(name)
    _mcp_gate.forget(name)
    _emit_audit("tool.removed", principal.subject or "system",
                {"tool": name}, allowed=True)
    return {"removed": name}


def _deny(agent_name: str, tool: str, action: str, policy: str,
          event: str, reason: str, gate: str, start: float, rule: str = "",
          slo_agent: "str | None" = None, arguments: "dict | None" = None,
          receipt: bool = False, trace=None, tenant: "str | None" = None):
    """Record a denial and shape the response.

    ``tenant`` is only needed for the one denial that names no registered
    agent — an unregistered caller has no tenant binding to derive the audit
    stamp from, and the attempt belongs to whoever made it.
    """
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    # Close the gate's span before the denial bookkeeping below, so the span
    # measures the gate rather than the audit write and alert that follow it.
    if trace is not None:
        trace.mark(gate, passed=False, rule=rule, reason=reason)
    _emit_audit(event, agent_name, {
        "tool": tool, "action": action, "policy": policy,
        "reason": reason, "rule": rule,
    }, allowed=False, tenant=tenant)
    _bump(agent_name, "denials")
    # Feed the real SLO when the agent exists (skip unregistered callers).
    if slo_agent is not None:
        _slo.record_call(slo_agent, allowed=False,
                         policy_denied=gate in ("policy", "ring", "mcp_proxy"),
                         latency_ms=latency_ms)
        # A denial the agent can retry is exactly what a deduplicated alert is
        # for: one entry per agent per rule, however many times it is attempted.
        _alerts.raise_alert(
            title=f"Call denied at the {gate} gate",
            message=f"{agent_name} → {tool}: {reason}",
            severity="critical" if gate in ("ring", "mcp_proxy") else "warning",
            source="governance", agent_id=agent_name,
            dedup_key=f"deny:{agent_name}:{rule or gate}",
            metadata={"tool": tool, "rule": rule, "gate": gate},
        )
        _anomaly.record_metric(agent_name, "error_rate", 1.0,
                               {"gate": gate, "tool": tool})
    body = {
        "allowed": False, "reason": reason, "denied_by": gate,
        "rule": rule or None,
        "latency_ms": latency_ms, "policy": policy,
    }
    # The trace ends on the gate that actually stopped the call, so the
    # timeline shows where the decision was made rather than trailing off.
    if trace is not None:
        trace.recorded()
        body["trace_id"] = _tracer.save(
            trace, allowed=False, summary=f"denied at {gate}", decision="deny")
    # A receipt proves a *decision*, so a denial earns one exactly as an allow
    # does — a governance record that only kept the yeses would be worth little.
    if receipt:
        body["receipt"] = _receipts.record(
            tool_name=tool, agent_did=_identity.did(agent_name) or "",
            policy=policy, allowed=False, arguments=arguments,
            session_id=agent_name, error=reason)
    return body


async def _raw_body(request: Request) -> bytes:
    """The exact bytes of the request, for the signature to cover.

    A signature has to be over what the client actually sent. Re-serialising
    the parsed model would fold in every field default, which no client can
    reproduce without knowing this server's defaults, so the raw body is read
    instead. Starlette caches it on the request, so the model parsing that
    follows reads the same bytes rather than a second consumption of the
    stream — this is why the dependency is async while the handler stays sync.
    """
    return await request.body()


@app.post("/tools/call")
def call_tool(body: ToolCallIn,
              principal: Principal = Depends(require_operator),
              # Annotated bare rather than Optional[Request]: FastAPI
              # special-cases the exact `Request` annotation and tries to build
              # a Pydantic field from anything else. The default is what lets
              # the in-process callers omit it.
              request: Request = None,
              raw_body: bytes = Depends(_raw_body)):
    """Execute a governed tool call.

    Gates run in order, each backed by an AGT primitive:

      1. Lifecycle — LifecycleManager state must be ACTIVE. A kill switch that
         policy could override is not a kill switch, so this precedes policy.
      2. Trust     — the shared TrustPolicy, the same object /trust/evaluate uses.
      3. Ring      — AGT derives the ring from trust and enforces resource
                     constraints before policy evaluation (inside govern()).
      4. Policy    — AGT PolicyEngine, evaluating as this specific agent.

    Gates 3 and 4 both run inside govern() and report through on_deny.
    """
    start = time.perf_counter()

    # An MCP tool call earns a signed receipt whichever way it is decided, so
    # both facts are needed before the first gate can deny.
    _spec = _tools.get(body.tool_name) or {}
    _is_mcp = _spec.get("kind") == "mcp"
    _args = body.kwargs.get("arguments")
    _args = _args if isinstance(_args, dict) else {}

    # One replayable trace per call, spanning the gates below. None when
    # tracing is off, and every use of it is guarded accordingly.
    trace = _tracer.begin(
        agent_id=body.agent_id, tool=body.tool_name, action=body.action,
        policy=body.policy_name, did=_identity.did(body.agent_id) or "",
        trust_score=_trust_scores.get(body.agent_id, 0.0),
        input_text=body.input_text)

    # ── Gate 0: request integrity (AGT MCPMessageSigner) ───────────────
    # Runs before every other gate because it asks a question about the
    # request rather than about the agent: is this the first time this exact
    # call has arrived. A replayed request is otherwise indistinguishable from
    # a legitimate one — every gate below would pass it again, correctly, and
    # the side effects would happen twice.
    #
    # Inert unless a caller presents the headers or AGT_REQUIRE_CALL_SIGNATURE
    # is set. A signature that is offered must verify: a broken credential is
    # worse evidence than none, which is the position the identity gate below
    # already takes for attestations.
    # `request` is None for the in-process callers (the chaos runner, the demo
    # seeder, /policies/evaluate). They never crossed a network, so there is no
    # captured request to replay and nothing here to check — the gate guards the
    # HTTP surface, which is the only place the threat exists.
    _signature = (request.headers.get(mcp_caller_auth.SIGNATURE_HEADER, "")
                  if request is not None else "")
    if request is not None and (_signature
                                or mcp_caller_auth.require_signature()):
        try:
            _call_signer.verify(
                payload=(raw_body.decode("utf-8", errors="replace")
                         if isinstance(raw_body, bytes) else ""),
                sender_id=body.agent_id,
                nonce=request.headers.get(mcp_caller_auth.NONCE_HEADER, ""),
                timestamp=request.headers.get(
                    mcp_caller_auth.TIMESTAMP_HEADER, ""),
                signature=_signature)
        except mcp_caller_auth.CallerRejected as denial:
            return _deny(body.agent_id, body.tool_name, body.action,
                         body.policy_name, "tool.call.denied.signature",
                         denial.reason, "signature", start, rule=denial.rule,
                         receipt=_is_mcp, arguments=_args, trace=trace,
                         tenant=principal.tenant)

    # ── Gate 1: lifecycle state (AGT LifecycleManager) ─────────────────
    agent = _resolve_agent(body.agent_id)
    if agent is None:
        return _deny(body.agent_id, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.unregistered",
                     f"Agent '{body.agent_id}' is not registered — unknown agents are untrusted",
                     "lifecycle", start, rule="lifecycle:unregistered",
                     receipt=_is_mcp, arguments=_args, trace=trace,
                     tenant=principal.tenant)

    if agent.state != AgentLifecycleState.ACTIVE:
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.lifecycle",
                     f"Agent '{agent.name}' is {agent.state.value}, not active",
                     "lifecycle", start, rule=f"lifecycle:{agent.state.value}",
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args, trace=trace)

    _authorize_agent(agent, principal)
    if trace is not None:
        trace.mark("lifecycle", passed=True)

    # ── Identity attestation (AGT agentmesh.identity) ──────────────────
    # A self-asserted agent_id is only honoured when no attestation is offered.
    # If the caller presents one it must verify against the agent's public key,
    # or the call is a forgery attempt and is denied before trust or policy run.
    identity_verified = False
    if body.attestation is not None:
        identity_verified = _identity.verify_attestation(
            agent.name, body.attestation.nonce, body.attestation.signature)
        if not identity_verified:
            return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                         "tool.call.denied.identity",
                         "Attestation failed — signature does not match the agent's key",
                         "identity", start, rule="identity:attestation_failed",
                         slo_agent=agent.name, receipt=_is_mcp, arguments=_args, trace=trace)

    if _require_attestation() and not identity_verified:
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.identity",
                     "Attestation required — present a signed attestation "
                     "(AGT_REQUIRE_ATTESTATION is enabled)",
                     "identity", start, rule="identity:attestation_required",
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args, trace=trace)

    # A session token stands in for re-attesting on every call: the agent
    # proved itself once at POST /mcp/sessions and carries the short-lived
    # token afterwards. Validated against the agent it names, so a live token
    # for one agent cannot be used to act as another.
    if body.mcp_session_token:
        try:
            _mcp_callers.validate(agent.name, body.mcp_session_token)
        except mcp_caller_auth.CallerRejected as denial:
            return _deny(agent.name, body.tool_name, body.action,
                         body.policy_name, "tool.call.denied.identity",
                         denial.reason, "identity", start, rule=denial.rule,
                         slo_agent=agent.name, receipt=_is_mcp,
                         arguments=_args, trace=trace)
        identity_verified = True
    elif _is_mcp and mcp_caller_auth.require_session():
        # Scoped to MCP tools, which is what the flag name says. A webhook
        # tool is decided by the gates it always was.
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.identity",
                     "An MCP session token is required "
                     "(AGT_REQUIRE_MCP_SESSION is enabled). Obtain one from "
                     "POST /mcp/sessions.",
                     "identity", start, rule="mcp_session:required",
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args,
                     trace=trace)

    if trace is not None:
        trace.mark("identity", passed=True,
                   attributes={"identity_verified": identity_verified})

    # ── Per-tenant policy isolation ────────────────────────────────────
    # An agent may only be governed by a shared policy or one owned by its own
    # tenant. Reaching for another tenant's policy is denied before any gate.
    policy_owner = _policy_owner(body.policy_name)
    agent_tenant = _agent_tenant.get(agent.name, DEFAULT_TENANT)
    if policy_owner is not None and policy_owner != agent_tenant:
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.policy",
                     f"Policy '{body.policy_name}' belongs to another tenant",
                     "policy", start, rule="policy:tenant_isolation",
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args, trace=trace)

    if trace is not None:
        trace.mark("tenant", passed=True, attributes={"tenant": agent_tenant})

    # ── Gate 2: trust (AGT TrustPolicy / PolicyEvaluator) ──────────────
    trust_score = _trust_scores.get(agent.name, 0.0)
    trust_decision, _ = _evaluate_trust(agent.name, trust_score)
    if not trust_decision.allowed:
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.trust",
                     f"Trust {trust_score} below minimum {MIN_TRUST}",
                     "trust", start, rule=trust_decision.rule_name or "deny-low-trust",
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args, trace=trace)

    if trace is not None:
        trace.mark("trust", passed=True, attributes={"trust_score": trust_score})

    # ── Gates 3 and 4: ring enforcement then policy, both inside govern() ──
    ring = _ring_for(trust_score)

    # A call may be bound to an open session (ACS agent_startup ... shutdown).
    # When it is, the ring is the *more restrictive* of the two: AGT's handshake
    # derives it from the same trust score and can only demote, but taking the
    # stricter of the pair means a future change to either side can never turn
    # binding a session into a way to gain privilege.
    if body.session_id:
        if not _sessions.is_active(body.session_id):
            return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                         "tool.call.denied.session",
                         f"Session '{body.session_id}' is not active",
                         "session", start, rule="session:inactive",
                         slo_agent=agent.name, receipt=_is_mcp,
                         arguments=_args, trace=trace)
        session_ring = _sessions.ring_for(body.session_id, agent.name)
        if session_ring is None:
            return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                         "tool.call.denied.session",
                         f"Agent '{agent.name}' has not joined this session",
                         "session", start, rule="session:not_a_participant",
                         slo_agent=agent.name, receipt=_is_mcp,
                         arguments=_args, trace=trace)
        # Higher value = less privilege, so max() is the restrictive choice.
        ring = ExecutionRing(max(ring.value, session_ring.value))

    tool_spec = _tools.get(body.tool_name) or {}

    # The half of the ring check govern() cannot make. It runs its own — this
    # does not replace it — but it can only read the action verb, so a tool
    # whose resource use lives in the registry rather than in its verb slips
    # through as TOOL_EXECUTION. The verdict below is still AGT's enforcer's.
    #
    # It stands aside whenever AGT's own inference already has the answer.
    # Deciding here first would deny the same calls under a different rule
    # name *and* keep those violations away from AGT's breach detector, so an
    # agent could probe forbidden resources forever without tripping the
    # circuit breaker that exists to stop exactly that.
    _resource = (_ring_resource(tool_spec)
                 if _agt_infers_resource(body.action) is ResourceType.TOOL_EXECUTION
                 else ResourceType.TOOL_EXECUTION)
    if _resource is not ResourceType.TOOL_EXECUTION:
        _ring_check = _ring_enforcer.check_resource(ring, _resource)
        if not _ring_check.allowed:
            return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                         "tool.call.denied.ring", _ring_check.reason,
                         "ring", start, rule=f"ring:{_resource.value}",
                         slo_agent=agent.name, receipt=_is_mcp,
                         arguments=_args, trace=trace)
    try:
        governed = _register_tool(body.tool_name, body.policy_name, agent.name, ring)
    except ValueError as e:
        raise HTTPException(400, str(e))

    try:
        outcome = governed(
            action=body.action,
            input_text=body.input_text,
            # Passed as a dict so AGT forwards it verbatim into the policy
            # context, letting rules say `agent.trust_score < 0.8`.
            agent={
                "id": agent.name,
                "agent_id": agent.agent_id,
                "trust_score": trust_score,
                "state": agent.state.value,
                "ring": ring.value,
            },
            # The same trick for the tool being called: a rule written against
            # `tool.category` keeps holding as tools are onboarded and removed,
            # which is what makes an imported MCP catalogue governable at all.
            tool={
                "name": body.tool_name,
                "category": tool_spec.get("category", DEFAULT_CATEGORY),
                "risk": tool_spec.get("risk", "medium"),
                "kind": tool_spec.get("kind", "webhook"),
                "builtin": bool(tool_spec.get("builtin")),
                # AGT's reversibility grade, so a rule can ask whether the call
                # could be taken back rather than only how trusted the caller
                # is — the half of the ring model the trust score cannot answer.
                **_reversibility.facet(body.tool_name),
            },
            **body.kwargs,
        )
    except MCPGateDenied as denial:
        # Raised from inside the governed callable by AGT's MCP trust proxy,
        # after ring and policy allowed the call but before anything was
        # dispatched to the remote server.
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.mcp_proxy", denial.reason,
                     "mcp_proxy", start, rule=denial.rule, slo_agent=agent.name,
                     receipt=_is_mcp, arguments=_args, trace=trace)
    except mcp_limits.MCPParametersRejected as denial:
        # AGT's MCPGateway refused the arguments: sensitive data on its way out
        # or shell metacharacters on their way in. Reported under its own gate
        # name rather than folded into mcp_proxy, because the two scans look
        # for different things and an operator reading a denial needs to know
        # which one fired.
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.mcp_parameters", denial.reason,
                     "mcp_parameters", start, rule=denial.rule,
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args,
                     trace=trace)
    except mcp_limits.MCPLimitExceeded as denial:
        # The agent's sliding budget across every MCP tool. Nothing was
        # dispatched, and the budget was not charged for this call.
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.mcp_budget", denial.reason,
                     "mcp_budget", start, rule=denial.rule,
                     slo_agent=agent.name, receipt=_is_mcp, arguments=_args,
                     trace=trace)
    except Exception:
        # The traceback goes to the log, not to the caller: this endpoint is
        # reachable anonymously in the shipped configuration, and str(e) on an
        # arbitrary exception leaks paths and library internals.
        _log.exception("tools/call: %r failed unexpectedly for agent %r",
                       body.tool_name, body.agent_id)
        raise HTTPException(500, "The governed call failed unexpectedly. "
                                 "See the server log for the cause.")

    latency_ms = round((time.perf_counter() - start) * 1000, 2)

    if isinstance(outcome, Denied):
        d = outcome.decision
        # AGT labels ring denials with these rule names; everything else is policy.
        gate = "ring" if d.matched_rule in ("ring_enforcement", "ring_breaker") else "policy"
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     f"tool.call.denied.{gate}", d.reason or "Denied",
                     gate, start, rule=d.matched_rule or "", slo_agent=agent.name,
                     receipt=_is_mcp, arguments=_args, trace=trace)

    # Governance allowed the call. If a real endpoint ran, task success reflects
    # the actual HTTP outcome; a decision-only tool (no endpoint) counts as a
    # successful governed call.
    executed = isinstance(outcome, dict) and outcome.get("executed") is True
    execution_ok = bool(outcome.get("ok")) if executed else True

    if trace is not None:
        # Ring, policy and the MCP proxy all decided inside govern(), which
        # returns a single outcome; splitting that into three invented
        # durations would make the timeline look more precise and be less true.
        # The one thing that *was* measured separately is the remote round
        # trip, so it is handed to its own span rather than counted as
        # governance overhead. Both marks happen here, before the audit and SLO
        # writes below, so neither span absorbs work that ran after the call.
        _dispatch_ms = float(outcome.get("latency_ms") or 0.0) if executed else 0.0
        trace.mark("govern", passed=True,
                   attributes={"ring": ring.name,
                               "mcp_proxy": tool_spec.get("kind") == "mcp"},
                   ends_at=time.time() - _dispatch_ms / 1000.0)
        if executed:
            trace.dispatched(body.tool_name, outcome)

    _emit_audit("tool.call.allowed", agent.name, {
        "tool": body.tool_name, "action": body.action,
        "policy": body.policy_name, "ring": ring.name, "latency_ms": latency_ms,
        "did": _identity.did(agent.name), "identity_verified": identity_verified,
        "executed": executed, "execution_ok": execution_ok,
    }, allowed=True)
    _bump(agent.name, "calls")
    _slo.record_call(agent.name, allowed=execution_ok, policy_denied=False,
                     latency_ms=latency_ms, executed=executed,
                     execution_ok=execution_ok)
    # Behavioural baseline: what this agent calls, in what order, how fast.
    # Advisory only — an anomaly never denies, it reports.
    _anomaly.record_call(agent.name, body.tool_name)
    _anomaly.record_metric(agent.name, "latency_ms", latency_ms,
                           {"tool": body.tool_name})
    _check_error_budget(agent.name)
    # Built, not fixed: reporting a gate that did not run would be the same
    # lie as hiding one that did. `signature` only appears when a signature was
    # actually presented or required, and the three MCP gates only for a tool
    # imported from an MCP server.
    gates_passed = ["lifecycle", "trust", "ring", "policy"]
    if _signature or mcp_caller_auth.require_signature():
        gates_passed.insert(0, "signature")
    receipt = None
    if tool_spec.get("kind") == "mcp":
        # In dispatch order: parameters, then the trust proxy, then the budget
        # spent immediately before the call left.
        gates_passed.extend(["mcp_parameters", "mcp_proxy", "mcp_budget"])
        receipt = _receipts.record(
            tool_name=body.tool_name, agent_did=_identity.did(agent.name) or "",
            policy=body.policy_name, allowed=True, arguments=_args,
            session_id=agent.name)

    if trace is not None:
        trace.recorded()
    trace_id = _tracer.save(trace, allowed=True, summary="allowed",
                            decision="allow")

    return {
        "allowed": True, "result": outcome,
        "executed": executed, "execution_ok": execution_ok,
        "passed_gates": gates_passed,
        "receipt": receipt, "trace_id": trace_id,
        "trust_score": trust_score, "ring": ring.name,
        "did": _identity.did(agent.name), "identity_verified": identity_verified,
        "latency_ms": latency_ms, "policy": body.policy_name,
    }


# ═══════════════════════════════════════════════════════════════════════════
# MCP CONNECTOR  /mcp — govern the tools a Model Context Protocol server offers
# ═══════════════════════════════════════════════════════════════════════════
# An MCP server hands an agent tools described in natural language the model is
# expected to obey, which makes the *descriptor* the attack surface. Discovery
# grades every descriptor before anything is onboarded; import turns the ones an
# operator accepts into ordinary registry tools, so an MCP call is decided by the
# same four gates as any other. Nothing about an MCP tool bypasses governance.

# Namespaced so two servers offering a `search` tool stay distinguishable, and
# so an operator reading the audit log can see the origin of a governed call.
_MCP_LABEL_RE = re.compile(r"[^A-Za-z0-9_\-]+")


def _mcp_label(name: str) -> str:
    label = _MCP_LABEL_RE.sub("-", (name or "").strip()).strip("-").lower()
    return label[:24] or "server"


def _import_label(body, discovery: dict) -> str:
    """The server label this discovery would be imported under.

    Computed in one place because AGT's cross-server checks key on it: the
    scan at discovery has to use the same label ``/mcp/import`` will register
    under, or a tool would appear to impersonate itself on re-import while a
    genuine impersonation from a differently-labelled server went unnoticed.
    """
    named = getattr(body, "server_name", "") or ""
    return _mcp_label(named or (discovery.get("server_info") or {}).get("name") or "")


def _escalate(risk: str, floor: str) -> str:
    """The higher of two risk tiers, on the registry's own ordering."""
    order = mcp_connector.RISK_ORDER
    if floor not in order:
        return risk
    if risk not in order:
        return floor
    return max(risk, floor, key=order.index)


def _mcp_tool_name(server: str, remote_tool: str) -> str:
    """The registry name for an imported tool: mcp.<server>.<tool>."""
    tool = _MCP_LABEL_RE.sub("-", remote_tool.strip()).strip("-")[:32]
    if not tool:
        raise HTTPException(400, f"MCP tool name '{remote_tool}' is unusable")
    return f"mcp.{server}.{tool}"[:64]


def _mcp_stdio_hint(detail: str) -> str:
    """Add the AgentGuard-side reading of a refusal AGT worded for its CLI.

    The toolkit tells a CLI user to pass --unsafe-allow-all-commands. There is
    no CLI here, and repeating that advice unqualified would send an operator
    looking for a flag this server does not have. The toolkit's reason is kept
    verbatim — it is the accurate part — and what it means here is added.
    """
    if "not on the allowed command list" in detail:
        return (f"{detail} (AgentGuard applies the Agent Governance Toolkit's "
                f"command allowlist as-is and has no override for it: a local "
                f"MCP server must be launched by one of the runtimes on that "
                f"list, such as python, node, npx, uvx or docker.)")
    return detail


def _mcp_discover(body: MCPDiscoverIn) -> dict:
    """Run discovery, translating connector failures into HTTP status codes."""
    if body.transport not in MCP_TRANSPORTS:
        raise HTTPException(
            400, f"transport must be one of {', '.join(MCP_TRANSPORTS)}")
    if body.transport == "stdio":
        if not mcp_connector.STDIO_AVAILABLE:
            raise HTTPException(
                501, "Local (stdio) MCP servers are unavailable: "
                     + mcp_connector.STDIO_UNAVAILABLE_REASON)
        if not body.command.strip():
            raise HTTPException(
                400, "A local (stdio) MCP server needs the command that "
                     "launches it")
    elif not body.server_url.strip():
        raise HTTPException(400, "A remote MCP server needs server_url")

    # Admission, before a byte is sent. AGT's McpAuthPolicy judges how this
    # connection is authenticated; an unauthenticated public server is refused
    # here rather than after its descriptors have been read, because reading
    # them is already the thing being protected against.
    admission = _mcp_admission.check(
        server_name=body.server_name if hasattr(body, "server_name") else "",
        url=body.server_url, transport=body.transport,
        has_token=bool(body.auth_token))
    if not admission["allowed"]:
        raise HTTPException(400, admission["reason"])

    try:
        discovery = mcp_connector.discover(
            body.server_url or None, timeout_ms=body.timeout_ms,
            allow_private=_tool_allow_private(), auth_token=body.auth_token,
            transport=body.transport,
            command=body.command.strip() or None, args=body.args,
            cwd=body.cwd, env_passthrough=body.env_passthrough,
            label=_mcp_label(body.server_url or body.command or "mcp"),
        )
    except ToolError as e:
        raise HTTPException(400, _mcp_stdio_hint(str(e)))
    except mcp_connector.MCPError as e:
        raise HTTPException(502, _mcp_stdio_hint(str(e)))
    # Carried on the result so an operator sees how the connection that
    # produced these descriptors was authenticated, not merely that it worked.
    discovery["admission"] = admission
    # The server's own implementation, as opposed to its tool text. Offline
    # unless AGT_MCP_CVE_ONLINE is set, and honest about which packages it
    # could not check — see mcp_admission.VulnerabilityIndex.
    discovery["vulnerabilities"] = _mcp_vulns.check(
        mcp_admission.packages_from_launch(body.command, body.args))

    # AGT's own descriptor scan, running the rule files in backend/config/.
    # This is what makes those files matter: MCPSecurityConfig patterns are
    # only ever consulted by scan_tool, so a config loaded without this call
    # would configure nothing.
    #
    # It is additive to the connector's grading, not a replacement — the two
    # catch different things, which is checkable: the connector catches the
    # canonical poisoning payload AGT's built-in set misses, and AGT catches
    # cross-server impersonation and typosquatting, which the connector cannot
    # see because it grades each descriptor in isolation.
    label = _import_label(body, discovery)
    for entry in discovery.get("tools") or []:
        findings = _mcp_descriptors.scan(
            label, entry["name"], entry.get("description") or "",
            entry.get("input_schema"))
        entry["security_scan"] = findings
        if findings:
            # The grade is what the import ceiling and the trust proxy's
            # per-tool policy both read, so a finding that only appeared in a
            # report would change no decision. Escalation only ever raises.
            floor = max((f["risk"] for f in findings),
                        key=mcp_connector.RISK_ORDER.index)
            evaluation = entry.get("evaluation") or {}
            before = evaluation.get("risk", "low")
            after = _escalate(before, floor)
            if after != before:
                evaluation["risk"] = after
                evaluation["escalated_by"] = "agt_descriptor_scan"
                evaluation["escalated_from"] = before
    return discovery


@app.post("/mcp/discover")
def mcp_discover(body: MCPDiscoverIn,
                 principal: Principal = Depends(require_operator)):
    """Connect to an MCP server, list its tools and evaluate every descriptor.

    Read-only: nothing is onboarded and no tool is invoked. Each descriptor is
    graded for the attacks MCP is actually exposed to — instructions aimed at
    the model, characters that hide them from a human reviewer, destructive or
    executing capability, credentials embedded in the text, and schemas too open
    to constrain an argument — and sorted into a capability category. The
    findings are what an operator decides on.

    `transport` selects Streamable HTTP (`http`), the legacy HTTP+SSE transport
    (`sse`), or `auto` to try the first and fall back to the second. Whichever
    answered is reported back.
    """
    discovery = _mcp_discover(body)
    summary = discovery["summary"]
    _emit_audit("mcp.server.discovered", principal.subject or "system", {
        "server_url": discovery["server_url"],
        "server": (discovery["server_info"] or {}).get("name", ""),
        "transport": discovery["transport"],
        "tools": summary["tools"], "flagged": summary["flagged"],
        "risk": summary["risk"],
    }, allowed=summary["risk"] not in ("high", "critical"))
    return discovery


@app.post("/mcp/import")
def mcp_import(body: MCPImportIn,
               principal: Principal = Depends(require_operator)):
    """Onboard an MCP server's tools into the governed registry.

    Discovery is re-run so the imported definition matches what the server
    advertises *now* rather than what a stale UI is showing. A tool graded above
    `max_risk`, or outside the requested `categories`, is skipped with its
    reason; everything imported keeps its evaluation on the registry entry, and
    is invoked through the connector only after the lifecycle, trust, ring and
    policy gates have allowed the call.
    """
    if body.max_risk and body.max_risk not in mcp_connector.RISK_ORDER:
        raise HTTPException(
            400, f"max_risk must be one of {', '.join(mcp_connector.RISK_ORDER)}")
    unknown = [c for c in body.categories if c not in TOOL_CATEGORIES]
    if unknown:
        raise HTTPException(
            400, f"Unknown categories: {', '.join(unknown)}. "
                 f"Valid: {', '.join(TOOL_CATEGORIES)}")

    discovery = _mcp_discover(body)
    server_label = _import_label(body, discovery)

    # A published vulnerability in the server's own implementation is a
    # different fact from a hostile descriptor, and it stops the import rather
    # than annotating it. Only a CRITICAL does: anything lower is recorded on
    # the tools and left to the operator, because an import ceiling that fires
    # on every MEDIUM is one people learn to bypass.
    vulnerabilities = discovery.get("vulnerabilities") or {}
    if vulnerabilities.get("blocking"):
        worst = [v for v in vulnerabilities["vulnerabilities"]
                 if v["severity"] in mcp_admission.BLOCKING_SEVERITIES]
        raise HTTPException(
            400, f"Refusing to import from '{server_label}': its package has "
                 f"{len(worst)} critical advisory/advisories — "
                 + "; ".join(f"{v['package']} {v['version']} {v['cve_id']}"
                             for v in worst[:3]))

    wanted = set(body.tools)
    catalogue = [t for t in discovery["tools"]
                 if not wanted or t["name"] in wanted]
    missing = sorted(wanted - {t["name"] for t in discovery["tools"]})
    if missing:
        raise HTTPException(
            404, f"Server does not offer: {', '.join(missing)}")

    imported, skipped = [], []
    wanted_categories = set(body.categories)
    for entry in catalogue:
        evaluation = entry["evaluation"]
        if wanted_categories and evaluation["category"] not in wanted_categories:
            skipped.append({
                "tool": entry["name"], "risk": evaluation["risk"],
                "category": evaluation["category"],
                "reason": f"Category '{evaluation['category']}' was not among "
                          f"the requested categories",
                "findings": evaluation["findings"],
            })
            continue
        if mcp_connector.risk_exceeds(evaluation["risk"], body.max_risk):
            skipped.append({
                "tool": entry["name"], "risk": evaluation["risk"],
                "category": evaluation["category"],
                "reason": f"Risk '{evaluation['risk']}' exceeds the import "
                          f"ceiling '{body.max_risk}'",
                "findings": evaluation["findings"],
            })
            continue
        name = _mcp_tool_name(server_label, entry["name"])
        try:
            spec = _tools.register(
                name,
                description=entry["description"][:500],
                # The remote name is kept as an action so AGT infers the same
                # resource type it would for a native tool of that name.
                actions=["invoke", entry["name"]],
                risk=evaluation["risk"],
                category=evaluation["category"],
                timeout_ms=body.call_timeout_ms,
                created_by=principal.subject or None,
                kind="mcp",
                mcp={
                    "server": server_label,
                    "server_url": discovery["server_url"],
                    "remote_tool": entry["name"],
                    "transport": discovery["transport"],
                    "auth_env": body.auth_env,
                    # How the connection that discovered this tool was
                    # authenticated, and how a dispatch will be. They differ:
                    # discovery may carry a one-off token while a dispatch
                    # reads auth_env, so a tool imported over an authenticated
                    # connection can still dispatch unauthenticated.
                    "auth_method": (discovery.get("admission") or {}).get(
                        "auth_method", "unknown"),
                    "dispatch_auth_method": mcp_admission.auth_method_for(
                        transport=discovery["transport"],
                        has_token=bool(body.auth_env)),
                    "protocol_version": discovery["protocol_version"],
                    # How to start a local server again at dispatch time. Empty
                    # for a remote one, and never any environment *value*.
                    **(discovery.get("launch") or {}),
                    # The descriptor exactly as advertised at import. Kept in
                    # full (not the truncated description) because it is the
                    # baseline a rug-pull check fingerprints against, and
                    # MCPSecurityScanner holds its registry in memory only.
                    "descriptor": {
                        "description": entry["description"],
                        "input_schema": entry.get("input_schema"),
                        "annotations": entry.get("annotations") or {},
                    },
                    # What AGT's scan said about this descriptor at import,
                    # kept beside the evaluation it may have escalated so the
                    # reason for a tier is readable after the fact.
                    "security_scan": entry.get("security_scan") or [],
                },
                evaluation=evaluation,
                required_capabilities=body.required_capabilities,
                allow_private=_tool_allow_private(),
            )
        except ToolError as e:
            raise HTTPException(400, str(e))
        # Drop stale governed wrappers so a re-import takes effect at once.
        for key in [k for k in _governed_tools if k[0] == name]:
            _governed_tools.pop(key, None)
        # And the cached proxy policy, so a re-graded tool is re-derived.
        _mcp_gate.forget(name)
        # Baseline the descriptor: a later change to it is a rug pull.
        _mcp_descriptors.register(server_label, entry["name"],
                                  entry["description"], entry.get("input_schema"))
        # Re-graded on every import, so a descriptor that changed from a search
        # into a purge cannot keep the level it was onboarded with.
        _register_reversibility(spec)
        # What the trust proxy will enforce at dispatch, reported at import so
        # an operator sees up front that (say) a critical-risk tool is onboarded
        # but will never actually run.
        spec["runtime_policy"] = _mcp_gate.describe(name, spec)
        _emit_audit("mcp.tool.imported", principal.subject or "system", {
            "tool": name, "server": server_label,
            "remote_tool": entry["name"], "risk": evaluation["risk"],
            "category": evaluation["category"],
            "score": evaluation["score"], "findings": len(evaluation["findings"]),
        }, allowed=evaluation["risk"] not in ("high", "critical"))
        imported.append(spec)

    _emit_audit("mcp.server.imported", principal.subject or "system", {
        "server": server_label, "server_url": discovery["server_url"],
        "transport": discovery["transport"],
        "imported": len(imported), "skipped": len(skipped),
        "max_risk": body.max_risk or "none",
        "categories": sorted(wanted_categories) or "all",
    }, allowed=not skipped)
    return {
        "server": server_label,
        "server_url": discovery["server_url"],
        "transport": discovery["transport"],
        "protocol_version": discovery["protocol_version"],
        "server_info": discovery["server_info"],
        "imported": imported,
        "skipped": skipped,
        "summary": discovery["summary"],
        "admission": discovery.get("admission"),
        "vulnerabilities": vulnerabilities,
    }


@app.get("/mcp/servers")
def mcp_servers():
    """Every MCP server this platform has imported tools from.

    Derived from the registry rather than kept as a second list, so a tool
    deleted through /tools/{name} cannot leave a phantom server behind.
    """
    servers: dict[str, dict] = {}
    for spec in _tools.all():
        if spec.get("kind") != "mcp":
            continue
        mcp = spec.get("mcp") or {}
        entry = servers.setdefault(mcp.get("server", ""), {
            "server": mcp.get("server", ""),
            "server_url": mcp.get("server_url"),
            "transport": mcp.get("transport"),
            "protocol_version": mcp.get("protocol_version"),
            "authenticated": bool(mcp.get("auth_env")),
            # A local server has no URL; showing how it is launched is the
            # equivalent thing to show, and the argv is not a secret.
            "local": mcp.get("transport") == "stdio",
            "command": mcp.get("command"),
            "args": mcp.get("args") or [],
            "cwd": mcp.get("cwd"),
            "env_passthrough": mcp.get("env_passthrough") or [],
            "tools": [],
            "risk": "low",
            "categories": [],
        })
        entry["tools"].append({
            "name": spec["name"], "remote_tool": mcp.get("remote_tool"),
            "risk": spec.get("risk"),
            "category": spec.get("category", DEFAULT_CATEGORY),
            "findings": len((spec.get("evaluation") or {}).get("findings", [])),
        })
        order = mcp_connector.RISK_ORDER
        if order.index(spec.get("risk", "low")) > order.index(entry["risk"]):
            entry["risk"] = spec.get("risk", "low")
    for entry in servers.values():
        present = {t["category"] for t in entry["tools"]}
        entry["categories"] = [c for c in TOOL_CATEGORIES if c in present]
    return {"servers": [servers[k] for k in sorted(servers)]}


@app.post("/mcp/servers/{server}/verify")
def mcp_verify_server(server: str, principal: Principal = Depends(require_operator)):
    """Re-discover a server and check every imported tool for a rug pull.

    The import-time grade is a point-in-time snapshot of static text. This
    re-fetches what the server advertises *now* and compares it, via AGT's
    MCPSecurityScanner fingerprints, against the descriptor each tool was
    onboarded with. A tool whose description or schema changed is quarantined:
    the dispatch gate refuses it until an operator re-imports it, because a
    descriptor nobody approved is not one to keep running on.
    """
    names = _tools.by_mcp_server(server)
    if not names:
        raise HTTPException(404, f"No tools imported from server '{server}'")

    first = _tools.get(names[0]) or {}
    origin = (first.get("mcp") or {})
    try:
        live = mcp_connector.discover(
            origin.get("server_url"),
            timeout_ms=8000,
            allow_private=_tool_allow_private(),
            transport=origin.get("transport") or "auto",
            command=origin.get("command"), args=origin.get("args"),
            cwd=origin.get("cwd"),
            env_passthrough=origin.get("env_passthrough"),
            label=server,
        )
    except (mcp_connector.MCPError, ToolError) as e:
        raise HTTPException(502, f"Cannot re-verify '{server}': {e}")

    advertised = {t["name"]: t for t in live["tools"]}
    checked, changed, withdrawn = [], [], []
    for name in names:
        spec = _tools.get(name) or {}
        remote = (spec.get("mcp") or {}).get("remote_tool")
        current = advertised.get(remote)
        if current is None:
            # The server no longer offers it. Not a rug pull, but the tool
            # cannot be re-verified, so it is quarantined rather than trusted.
            withdrawn.append(name)
            _tools.quarantine(name, True)
            checked.append({"tool": name, "remote_tool": remote,
                            "status": "withdrawn_by_server", "quarantined": True})
            continue
        rug = _mcp_descriptors.check(server, remote, current["description"],
                                     current.get("input_schema"))
        if rug is None:
            _tools.quarantine(name, False)
            checked.append({"tool": name, "remote_tool": remote,
                            "status": "unchanged", "quarantined": False})
            continue
        changed.append(name)
        _tools.quarantine(name, True)
        for key in [k for k in _governed_tools if k[0] == name]:
            _governed_tools.pop(key, None)
        checked.append({
            "tool": name, "remote_tool": remote, "status": "changed",
            "quarantined": True, "rug_pull": rug,
            # The new descriptor's own grade, so an operator can see whether it
            # merely drifted or turned hostile.
            "new_evaluation": current["evaluation"],
        })

    _emit_audit("mcp.server.verified", principal.subject or "system", {
        "server": server, "checked": len(checked),
        "changed": len(changed), "withdrawn": len(withdrawn),
    }, allowed=not changed and not withdrawn)
    return {
        "server": server,
        "server_url": origin.get("server_url"),
        "checked": checked,
        "changed": len(changed),
        "withdrawn": len(withdrawn),
        "clean": not changed and not withdrawn,
    }


# ═══════════════════════════════════════════════════════════════════════════
# MCP CALLER SESSIONS  /mcp/sessions — is the caller the agent it names
# ═══════════════════════════════════════════════════════════════════════════
# Not the sessions at /sessions. Those are AGT Hypervisor workspaces carrying an
# execution ring and a participant list. These are caller credentials: an agent
# attests once, receives a short-lived opaque token, and presents that on later
# calls instead of re-signing a challenge every time.

@app.post("/mcp/sessions")
def mcp_session_create(body: MCPSessionIn,
                       principal: Principal = Depends(require_operator)):
    """Issue a caller session token for an agent.

    A token must never be easier to obtain than the identity it stands for, so
    this is operator-gated, and an attestation offered alongside must verify —
    presenting a broken proof is worse evidence than presenting none.
    """
    agent = _resolve_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent '{body.agent_id}' is not registered")
    _authorize_agent(agent, principal)

    if body.attestation is not None:
        if not _identity.verify_attestation(agent.name, body.attestation.nonce,
                                            body.attestation.signature):
            raise HTTPException(
                403, "Attestation failed — signature does not match the "
                     "agent's key")
    try:
        minted = _mcp_callers.mint(agent.name, body.user_id)
    except RuntimeError as e:
        # AGT's concurrent-session ceiling. A 409 rather than a 500: the
        # request is well formed and the caller can act on it by revoking.
        raise HTTPException(409, str(e))

    _emit_audit("mcp.session.created", principal.subject or "system", {
        "agent": agent.name, "user_id": body.user_id or "",
        "attested": body.attestation is not None,
        "ttl_seconds": minted["ttl_seconds"],
    }, allowed=True)
    return minted


@app.delete("/mcp/sessions/{token}")
def mcp_session_revoke(token: str,
                       principal: Principal = Depends(require_operator)):
    """Revoke one caller session token."""
    if not _mcp_callers.revoke(token):
        raise HTTPException(404, "No such session token")
    _emit_audit("mcp.session.revoked", principal.subject or "system",
                {"scope": "token"}, allowed=True)
    return {"revoked": True}


@app.get("/mcp/signing-parameters")
def mcp_signing_parameters(principal: Principal = Depends(current_principal)):
    """Everything a client needs to sign a call, except the key.

    The key is shared out of band. Publishing the canonical form is not a
    weakness — an HMAC's strength is in the secret, and a client that cannot
    reproduce the exact bytes cannot produce a valid signature at all.
    """
    return _call_signer.public_parameters


# ═══════════════════════════════════════════════════════════════════════════
# MCP VULNERABILITIES  /mcp/servers/{server}/vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/mcp/servers/{server}/vulnerabilities")
def mcp_server_vulnerabilities(
        server: str, principal: Principal = Depends(require_operator)):
    """Check an imported server's own package against known advisories.

    Separate from the descriptor grade, which reads the tool *text*. This reads
    the *implementation*: the package and version its launch command names. A
    remote server names no package, and that is reported as unchecked rather
    than clean — an unknown is not a pass.
    """
    names = _tools.by_mcp_server(server)
    if not names:
        raise HTTPException(404, f"No tools imported from server '{server}'")
    origin = (_tools.get(names[0]) or {}).get("mcp") or {}
    packages = mcp_admission.packages_from_launch(
        origin.get("command") or "", origin.get("args") or [])
    report = _mcp_vulns.check(packages)
    report["server"] = server
    if not packages:
        report["note"] = (
            "No package could be determined from this server's origin. A "
            "remote (HTTP) server is reached by URL and names no package; a "
            "local one launched from a script path runs code no public "
            "database has an entry for.")
    _emit_audit("mcp.server.vulnerability_scan", principal.subject or "system", {
        "server": server, "packages": len(packages),
        "vulnerabilities": len(report["vulnerabilities"]),
        "highest_severity": report["highest_severity"] or "none",
    }, allowed=not report["blocking"])
    return report


@app.post("/mcp/advisories")
def mcp_advisory_add(body: MCPAdvisoryIn,
                     principal: Principal = Depends(require_operator)):
    """Record an advisory this deployment knows about, with no network call.

    The CVE feed is offline unless AGT_MCP_CVE_ONLINE is set, so this is how an
    air-gapped deployment tells the platform about a vulnerable MCP package.
    """
    severity = body.severity.upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        raise HTTPException(
            400, "severity must be one of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    _mcp_vulns.add_advisory(
        package=body.package, version=body.version, cve_id=body.cve_id,
        severity=severity, summary=body.summary,
        fixed_version=body.fixed_version)
    _emit_audit("mcp.advisory.added", principal.subject or "system", {
        "package": body.package, "version": body.version,
        "cve_id": body.cve_id, "severity": severity,
    }, allowed=severity not in mcp_admission.BLOCKING_SEVERITIES)
    return {"recorded": True, "package": body.package, "cve_id": body.cve_id,
            "severity": severity}


@app.get("/mcp/controls")
def mcp_controls(agent_id: str = "",
                 principal: Principal = Depends(current_principal)):
    """Every AGT MCP control this platform runs, and where each one sits.

    Computed from the live objects rather than from a fixed table, so a control
    that was reconfigured or switched off reports what it actually is. The gate
    names match the ones a denial carries, which is what lets an audit entry be
    traced back to the control that produced it.
    """
    return {
        "toolkit": "Microsoft Agent Governance Toolkit",
        # The spread comes first in each entry so `stage` and `gate` below
        # always win: a describe() carrying its own key of the same name would
        # otherwise replace the ACS point silently, since a later key wins.
        "controls": [
            {**_mcp_descriptors.rules(),
             "stage": "connect", "gate": "mcp_descriptor_rules"},
            {**_mcp_admission.describe(),
             "stage": "connect", "gate": "mcp_admission"},
            {**_mcp_vulns.describe(),
             "stage": "connect", "gate": "mcp_vulnerabilities"},
            {**_mcp_callers.describe(),
             "stage": "authenticate", "gate": "identity"},
            {**_call_signer.describe(),
             "stage": "authenticate", "gate": "signature"},
            {**_mcp_params.describe(),
             "stage": "pre_tool_call", "gate": "mcp_parameters"},
            {**_mcp_budget.describe(agent_id),
             "stage": "pre_tool_call", "gate": "mcp_budget"},
            {"stage": "pre_tool_call", "gate": "mcp_proxy",
             "control": "mcp_trust_proxy.TrustProxy",
             "note": "Argument injection scan, per-tool rate limit, and a "
                     "trust floor derived from the descriptor grade."},
            {"stage": "pre_tool_call", "gate": "mcp_proxy",
             "control": "agent_os.mcp_security.MCPSecurityScanner",
             "note": "Descriptor fingerprints; a tool whose text changed after "
                     "import is quarantined until re-imported. The same "
                     "scanner runs the configured rule set over every "
                     "descriptor at discovery, which is where cross-server "
                     "impersonation and typosquatting are caught."},
            {**_mcp_response_policy.describe(),
             "stage": "post_tool_call", "gate": "response"},
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# MCP DETECTION RULES  /mcp/security-rules — the rule set, as a file
# ═══════════════════════════════════════════════════════════════════════════
# AGT asks for these explicitly: constructing its scanner without a config warns
# that the built-in rules "may not cover all MCP tool poisoning techniques".
# backend/config/ holds them, and they are what AGT's scan_tool actually runs.

@app.get("/mcp/security-rules")
def mcp_security_rules(principal: Principal = Depends(current_principal)):
    """Which detection rules are in force, and where they came from.

    Reports per-section counts and, in particular, how many rules the toolkit
    ships that the loaded file does *not* carry. A rule set that is quietly
    narrower than the library default is the failure worth surfacing: it
    reports healthy while detecting less.
    """
    return _mcp_descriptors.rules()


@app.post("/mcp/security-rules/validate")
def mcp_security_rules_validate(
        body: MCPRulesIn, principal: Principal = Depends(require_operator)):
    """Check a candidate rule file without installing it.

    Every pattern is compiled with the flags the scanner uses. AGT's own loader
    accepts a file and lets the scanner skip bad patterns with a log line, so a
    typo there removes a detection silently; here it fails the file.
    """
    if body.kind not in ("mcp", "injection"):
        raise HTTPException(400, "kind must be 'mcp' or 'injection'")
    return mcp_security_config.validate_text(body.content, body.kind)


@app.post("/mcp/security-rules/reload")
def mcp_security_rules_reload(
        principal: Principal = Depends(require_operator)):
    """Re-read the rule files and rebuild the scanner around them.

    The file on disk is the source of truth — the rules are version-controlled
    code, not state this API edits — so this applies an edit without a restart
    rather than accepting new rules over HTTP. A file that fails validation
    leaves the running rule set untouched and says so.
    """
    status = _mcp_descriptors.reload_rules()
    # Fingerprints live on the scanner that was just replaced, so the baselines
    # are re-seeded from the persisted descriptors — the same path a restart
    # takes. Without this every imported tool would lose its rug-pull baseline.
    reseeded = _mcp_descriptors.reseed(_tools.all())
    loaded = all(half.get("loaded") for half in status.values())
    _emit_audit("mcp.security_rules.reloaded", principal.subject or "system", {
        "loaded": loaded,
        "files": [half.get("path") for half in status.values()],
        "reseeded": reseeded,
    }, allowed=loaded)
    return {"reloaded": loaded, "status": status,
            "baselines_reseeded": reseeded,
            "rules": _mcp_descriptors.rules()}


# ═══════════════════════════════════════════════════════════════════════════
# RECEIPTS  /mcp/receipts — signed, portable proof of one governance decision
# ═══════════════════════════════════════════════════════════════════════════
# Distinct from the audit chain in purpose: the Merkle chain proves this log has
# not been edited, and you must trust this instance to read it. A receipt is
# self-contained — it carries its signature and its signer's public key, so a
# third party verifies a single decision offline.

@app.get("/mcp/receipts")
def list_receipts(limit: int = 50, tool_name: Optional[str] = None,
                  principal: Principal = Depends(current_principal)):
    """Signed decision receipts, scoped to the caller's tenant.

    A receipt names the agent it was issued for, so it inherits that agent's
    tenant. One whose agent is gone is admin-only, for the same reason a trace
    of a purged agent is.
    """
    receipts = _receipts.all(limit=limit, tool_name=tool_name)
    if not principal.is_admin:
        receipts = [r for r in receipts
                    if _agent_tenant.get(r.get("session_id") or "")
                    == principal.tenant]
    return {
        "receipts": receipts,
        "total": len(receipts) if not principal.is_admin else _receipts.count(),
        "signer_public_key": _receipts.public_key,
        "durable_key": _receipts.durable_key,
    }


@app.get("/mcp/receipts/verify")
def verify_receipts():
    """Re-verify every signature and the parent-hash chain."""
    return _receipts.verify()


@app.get("/mcp/receipts/export")
def export_receipts(principal: Principal = Depends(require_admin)):
    """The full ledger, plus each receipt rendered as SLSA provenance.

    Admin-only for the same reason /audit/export is: the receipts are a hash
    chain, and a tenant-filtered ledger would not verify against itself. A
    tenant gets its own receipts from /mcp/receipts.
    """
    return _receipts.export()


@app.delete("/mcp/servers/{server}")
def mcp_remove_server(server: str, principal: Principal = Depends(require_admin)):
    """Withdraw a whole MCP server: every tool imported from it is removed."""
    names = _tools.by_mcp_server(server)
    if not names:
        raise HTTPException(404, f"No tools imported from MCP server '{server}'")
    for name in names:
        _tools.remove(name)
        for key in [k for k in _governed_tools if k[0] == name]:
            _governed_tools.pop(key, None)
        _reversibility.forget(name)
        _mcp_gate.forget(name)
    _emit_audit("mcp.server.removed", principal.subject or "system",
                {"server": server, "tools": len(names)}, allowed=True)
    return {"server": server, "removed": names}


# ═══════════════════════════════════════════════════════════════════════════
# TRUST ENGINE  /trust
# ═══════════════════════════════════════════════════════════════════════════

def _reputation_for(name: str) -> dict:
    """AGT's computed reputation for one agent, from its own call record."""
    stats = _call_stats.get(name, {})
    agent = _resolve_agent(name)
    card = _identity.card(name)
    return reputation.compute(
        agent_did=_identity.did(name) or "",
        calls=stats.get("calls", 0),
        denials=stats.get("denials", 0),
        created_at=getattr(agent, "created_at", None),
        has_identity=_identity.did(name) is not None,
        attested=_identity.attested_at(name) is not None,
        card_valid=bool(card and card.get("signature_valid")),
    )


@app.get("/trust")
def trust_overview(principal: Principal = Depends(current_principal)):
    """Every agent this caller may see, with the score, the ring it buys, and
    AGT's independently computed reputation.

    Three numbers used to be conflated here. They are now reported separately
    because they answer different questions: `trust_score` is what the gate
    enforces, `ring` is the capability that score actually buys, and
    `reputation` is what AGT computes from the agent's behaviour — advisory
    until an operator promotes it.
    """
    agents = []
    for name, score in _trust_scores.items():
        # Scoped like /agents: a caller sees only its own tenant, admins span.
        if not principal.is_admin and \
                _agent_tenant.get(name, DEFAULT_TENANT) != principal.tenant:
            continue
        ring = _ring_for(score)
        agents.append({
            "agent_id": name,
            "trust_score": score,
            # Bands named after what they buy, not an opinion: the boundary is
            # the one AGT's ExecutionRing actually uses.
            "level": "high" if score >= 0.8 else "medium" if score > 0.6 else "low",
            "ring": ring.name,
            "ring_grants": "network, scoped filesystem, subprocess"
                           if ring.name == "RING_2_STANDARD"
                           else "no network, filesystem or subprocess",
            "passes_trust_gate": score >= MIN_TRUST,
            "reputation": _reputation_for(name),
        })
    return {
        "agents": agents,
        # The panel showed a hardcoded threshold that was never the real one.
        "min_trust": MIN_TRUST,
        "ring_threshold": 0.6,
    }


@app.post("/trust/promote/{agent_id}")
def promote_reputation(agent_id: str,
                       principal: Principal = Depends(require_operator)):
    """Adopt AGT's computed reputation as the agent's enforced trust score.

    Deliberately an operator action rather than a background job: a score that
    moved on its own, changing which execution ring an agent sits in, with no
    one seeing why, would be worse than a stale one.
    """
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    rep = _reputation_for(agent.name)
    if not rep["evidenced"]:
        raise HTTPException(
            409, "This agent has made no governed calls, so its reputation "
                 "rests on identity alone. Nothing to promote yet.")
    before = _trust_scores.get(agent.name, 0.0)
    after = rep["score_normalised"]
    _trust_scores[agent.name] = after
    for key in [k for k in _governed_tools if k[2] == agent.name]:
        _governed_tools.pop(key, None)
    _persist_meta()
    _emit_audit("trust.reputation.promoted", agent.name, {
        "from": before, "to": after, "tier": rep["tier"],
        "verification_level": rep["verification_level"],
    })
    return {"agent_id": agent.name, "previous": before, "trust_score": after,
            "reputation": rep, "ring": _ring_for(after).name}


@app.post("/trust/evaluate")
def evaluate_trust(body: TrustEvalIn):
    """Evaluate an agent context against the trust policy.

    This is the *same* policy object /tools/call enforces with, so a verdict
    shown here is the verdict the runtime applies.
    """
    decision, context = _evaluate_trust(
        body.agent_id, body.trust_score, body.delegation_depth, body.namespace,
    )
    _emit_audit("trust.evaluated", body.agent_id, {
        "trust_score": body.trust_score, "allowed": decision.allowed,
        "rule": decision.rule_name,
    }, allowed=decision.allowed)
    return {
        "allowed": decision.allowed,
        "rule_name": decision.rule_name,
        "action": decision.action,
        "reason": decision.reason,
        "min_trust": MIN_TRUST,
        "enforced": True,
        "context": context,
    }


@app.post("/trust/update")
def update_trust(agent_id: str, score: float,
                 principal: Principal = Depends(require_operator)):
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    _trust_scores[agent.name] = max(0.0, min(1.0, score))
    # Trust drives the execution ring, so cached callables for this agent
    # are bound to the old ring and must be discarded.
    for key in [k for k in _governed_tools if k[2] == agent.name]:
        _governed_tools.pop(key, None)
    _persist_meta()
    agent_id = agent.name
    _emit_audit("trust.updated", agent_id, {
        "new_score": score, "ring": _ring_for(_trust_scores[agent_id]).name,
    })
    return {
        "agent_id": agent_id,
        "trust_score": _trust_scores[agent_id],
        "ring": _ring_for(_trust_scores[agent_id]).name,
    }


# ═══════════════════════════════════════════════════════════════════════════
# AUDIT LOG  /audit
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/audit")
def get_audit(limit: int = 50, agent_id: Optional[str] = None,
              event_type: Optional[str] = None,
              principal: Principal = Depends(current_principal)):
    """The chain, scoped to what this caller may read.

    ``total`` counts the readable entries, not the chain: reporting the whole
    length beside a filtered page would leak the size of everyone else's
    traffic. ``merkle_root`` is the real root over the whole chain, because it
    is a platform integrity property and discloses no entry content — the
    verification endpoints would be meaningless against a per-tenant root.
    """
    def visible(entry):
        return _audit_visible(entry, principal)
    entries = _audit.entries(agent_id=agent_id, event_type=event_type,
                             limit=limit, visible=visible)
    return {
        "events": [_serialise_entry(e) for e in entries],
        "total": _audit.tally(visible=visible)[0],
        "merkle_root": _audit.root_hash(),
    }


@app.get("/audit/verify")
def verify_audit():
    """Recompute every entry hash and re-walk the chain links.

    Always a fresh walk. This is the endpoint an operator reaches for when they
    want to know *now*, and the Audit panel's Verify button behind it, so it
    never answers from the cached verdict /stats polls. It refreshes that cache
    on the way past.
    """
    result = _audit.verify()
    return {
        "valid": result["valid"],
        "error": result["error"],
        "merkle_root": _audit.root_hash(),
        "entry_count": result["entries"],
        "verified_at": datetime.datetime.fromtimestamp(
            result["checked_at"], datetime.timezone.utc).isoformat(),
    }


@app.get("/audit/proof/{entry_id}")
def audit_proof(entry_id: str,
                principal: Principal = Depends(current_principal)):
    """Merkle inclusion proof for a single entry.

    A tree with one leaf has no sibling path, so AGT returns no proof for the
    only entry in a fresh chain. That is not the same as an unknown entry, and
    reporting both as 404 "Entry not found" told an operator their entry did not
    exist when it plainly did.
    """
    # A proof embeds the entry it proves, so the same tenant check the listing
    # applies has to run here — otherwise the proof endpoint hands back exactly
    # what the listing withheld. An entry this caller cannot read is reported as
    # absent rather than forbidden: whether it exists is itself another
    # tenant's business.
    entry = next((e for e in _audit.entries(limit=AuditStore._UNBOUNDED)
                  if getattr(e, "entry_id", None) == entry_id), None)
    if entry is None or not _audit_visible(entry, principal):
        raise HTTPException(404, "Entry not found")
    proof = _audit.proof(entry_id)
    if proof is not None:
        return proof
    return {
        "entry_id": entry_id,
        "merkle_proof": None,
        "merkle_root": _audit.root_hash(),
        "verified": None,
        "reason": "This is the only entry in the chain, so there is no sibling "
                  "path to prove inclusion against. Its own hash is the root.",
    }


# ═══════════════════════════════════════════════════════════════════════════
# TRACES  /traces — how a decision was made, span by span
# ═══════════════════════════════════════════════════════════════════════════
# The audit chain proves *that* a decision happened and that the record has not
# been edited. A trace answers the other question: *how* it happened — which
# gate ran, in what order, how long each took. AGT's ReplayEngine then diffs two
# of them into typed findings, which is how "the same call decided differently"
# becomes a fact rather than an impression.

def _trace_visible(row: dict, principal: Principal) -> bool:
    """A trace belongs to the tenant owning the agent whose call it traced.

    Fails closed on an agent that no longer exists — a decommissioned agent, or
    a purged adversarial one. Its tenant is no longer knowable, and a trace
    nobody can attribute is an admin's problem rather than something to hand to
    whichever tenant happens to ask.
    """
    if principal.is_admin:
        return True
    owner = _agent_tenant.get(row.get("agent_id") or "")
    return owner is not None and owner == principal.tenant


@app.get("/traces")
def list_traces(limit: int = 50, agent_id: Optional[str] = None,
                principal: Principal = Depends(current_principal)):
    return {
        "enabled": _tracer.enabled,
        "directory": _tracer.directory,
        "traces": _tracer.all(limit=max(1, min(int(limit), 500)), agent_id=agent_id,
                              visible=lambda row: _trace_visible(row, principal)),
        "note": None if _tracer.enabled else
                "Tracing is off. Traces are written under AGT_STATE_DIR; without "
                "it there is nowhere durable to put them, so none are captured.",
    }


@app.get("/traces/diff")
def diff_traces(a: str, b: str,
                principal: Principal = Depends(current_principal)):
    """Diff two traces with AGT's ReplayEngine.

    Both sides are checked: a diff is a read of two traces, and one readable
    side does not buy the other. A trace this caller may not read is reported
    as missing, the same way the single-trace read reports it.
    """
    if not _tracer.enabled:
        raise HTTPException(409, "Tracing is off — set AGT_STATE_DIR to capture traces")
    result = _tracer.diff(a, b)
    if result is None:
        raise HTTPException(404, "One or both traces were not found")
    if not all(_trace_visible(result[side], principal) for side in ("a", "b")):
        raise HTTPException(404, "One or both traces were not found")
    return result


@app.get("/traces/{trace_id}")
def get_trace(trace_id: str,
              principal: Principal = Depends(current_principal)):
    trace = _tracer.get(trace_id)
    if trace is None or not _trace_visible(trace, principal):
        raise HTTPException(404, "Trace not found")
    return trace


@app.delete("/traces/{trace_id}")
def delete_trace(trace_id: str, principal: Principal = Depends(require_admin)):
    if not _tracer.delete(trace_id):
        raise HTTPException(404, "Trace not found")
    _emit_audit("trace.deleted", "platform", {"trace_id": trace_id}, allowed=True)
    return {"status": "deleted", "trace_id": trace_id}


@app.get("/audit/verify-file")
def verify_audit_file(principal: Principal = Depends(require_admin)):
    """Re-verify the durable, HMAC-signed audit file on disk.

    Distinct from `/audit/verify`, which re-walks the chain held in memory. This
    reads what `FileAuditSink` actually wrote and checks every entry against the
    key it was written with — the half of durable audit AGT ships and this
    platform had never called. Admin-only because it names the configured path.
    """
    return audit_export.verify_durable_file()


@app.get("/audit/export/accountability")
def export_accountability(limit: int = 200, agent_id: Optional[str] = None,
                          event_type: Optional[str] = None,
                          principal: Principal = Depends(current_principal)):
    """The chain as external accountability records, not as a JSON dump.

    Each entry becomes an AGT accountability export — actor, subject, operation,
    a digest of the policy that decided it, the decision and its evidence refs —
    plus the EEOAP-profile statement AGT maps that onto.
    """
    entries = _audit.entries(agent_id=agent_id, event_type=event_type,
                             limit=max(1, min(int(limit), 1000)),
                             visible=lambda e: _audit_visible(e, principal))
    records = audit_export.accountability_records(entries)
    return {
        "profile": audit_export.EXPORT_PROFILE,
        "merkle_root": _audit.root_hash(),
        "count": len(records),
        "failed": sum(1 for r in records if r.get("error")),
        "records": records,
    }


@app.get("/audit/export")
def export_audit(principal: Principal = Depends(require_admin)):
    """Full chain export with its Merkle root, for offline verification.

    Admin-only, and deliberately not tenant-filtered. The value of this export
    is that it is complete — every entry, in order, verifiable against the root
    it ships with. A filtered chain would not verify, so handing a tenant a
    subset would be handing it something that looks like evidence and is not.
    Per-entry reads are what a tenant gets; see /audit and the accountability
    export, both of which are scoped.
    """
    return _audit.export()


@app.delete("/audit")
def reset_audit(principal: Principal = Depends(require_admin)):
    """Start a new chain.

    An append-only log cannot honestly support deletion, so this does not
    erase evidence in place — it opens a fresh chain whose first entry
    records the reset and the root hash of the chain it replaced. A verifier
    reading the new chain can see that a prior chain existed.
    """
    previous_root, previous_count = _audit.reset()
    _emit_audit("audit.chain.reset", "system", {
        "previous_merkle_root": previous_root,
        "previous_entry_count": previous_count,
    })
    return {"status": "reset", "previous_merkle_root": previous_root}


# ═══════════════════════════════════════════════════════════════════════════
# AGENTS  /agents
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/agents")
def list_agents(principal: Principal = Depends(current_principal)):
    agents = [_agent_view(a) for a in _lifecycle.agents]
    if principal.is_admin:
        return agents
    return [
        a for a in agents
        if _agent_tenant.get(a["name"], DEFAULT_TENANT) == principal.tenant
    ]


@app.post("/agents/{agent_id}/approve")
def approve_agent(agent_id: str, principal: Principal = Depends(require_admin)):
    """Admit a pending agent. Admin only, and audited with the approver.

    AGT's state machine owns the transition: an agent that is not pending
    cannot be approved, and one that is cannot be activated without this.
    """
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    try:
        _lifecycle.approve(agent.agent_id, actor=principal.subject or "admin")
        _lifecycle.activate(agent.agent_id, actor=principal.subject or "admin")
    except LifecycleError as e:
        raise HTTPException(409, str(e))
    _emit_audit("agent.approved", agent.name, {
        "agent_id": agent.agent_id, "approver": principal.subject,
    })
    return _agent_view(_lifecycle.get(agent.agent_id))


@app.post("/agents/{agent_id}/reject")
def reject_agent(agent_id: str, reason: str = "Not approved",
                 principal: Principal = Depends(require_admin)):
    """Refuse a pending agent. AGT records the rejection and decommissions it."""
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    try:
        _lifecycle.reject(agent.agent_id, actor=principal.subject or "admin",
                          reason=reason)
    except LifecycleError as e:
        raise HTTPException(409, str(e))
    name = agent.name
    # Taken before the cleanup below drops it: this entry belongs to the tenant
    # that owned the agent, and by the time it is written there is nothing left
    # to derive that from.
    owner = _agent_tenant.get(name)
    # Same cleanup as decommissioning: AGT keeps the record and its trail, the
    # dashboard stops listing it.
    _agent_ids.pop(name, None)
    _trust_scores.pop(name, None)
    _agent_policies.pop(name, None)
    _agent_tenant.pop(name, None)
    _agent_capabilities.pop(name, None)
    _identity.remove(name)
    _persist_meta()
    _emit_audit("agent.rejected", name, {
        "agent_id": agent.agent_id, "approver": principal.subject, "reason": reason,
    }, allowed=False, tenant=owner)
    return {"status": "rejected", "agent_id": name, "reason": reason}


@app.get("/agents/{agent_id}/lifecycle")
def agent_lifecycle(agent_id: str,
                    principal: Principal = Depends(current_principal)):
    """The AGT lifecycle audit trail for one agent.

    LifecycleManager records every state change with its actor and reason.
    This is separate from the governance audit chain: it tracks who changed
    the agent, not what the agent did.
    """
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    return {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "state": agent.state.value,
        "owner": agent.owner,
        "events": [
            {
                "event_type": e.event_type.value,
                "actor": e.actor,
                "timestamp": e.timestamp.isoformat(),
                # Both ends of the transition: a trail that named only the
                # destination could not show what an agent was moved *from*.
                "previous_state": e.previous_state.value if e.previous_state else None,
                "new_state": e.new_state.value if e.new_state else None,
                "details": e.details,
            }
            for e in _lifecycle.get_audit_trail(agent.agent_id)
        ],
    }


@app.post("/agents")
def create_agent(body: AgentIn, principal: Principal = Depends(require_operator)):
    if body.id in _agent_ids:
        raise HTTPException(400, "Agent already exists")
    if not _policies.exists(body.policy):
        raise HTTPException(400, f"Policy '{body.policy}' not found")
    try:
        managed = _lifecycle.request_provisioning(
            name=body.id, owner=body.owner, purpose=body.purpose, actor="dashboard",
        )
        # With the approval gate on, AGT leaves the agent in PENDING_APPROVAL
        # and refuses the transition to ACTIVE. The refusal is the state
        # machine's, so no application check can be forgotten around it.
        if managed.state != AgentLifecycleState.PENDING_APPROVAL:
            _lifecycle.activate(managed.agent_id, actor="dashboard")
    except LifecycleError as e:
        raise HTTPException(400, str(e))

    _agent_ids[body.id] = managed.agent_id
    _agent_policies[body.id] = body.policy
    _trust_scores[body.id] = body.trust_score
    _agent_tenant[body.id] = principal.tenant
    _agent_capabilities[body.id] = [c.strip() for c in body.capabilities if c.strip()]
    if body.project_endpoint or body.foundry_agent_id:
        _agent_foundry[body.id] = {
            "project_endpoint": body.project_endpoint,
            "foundry_agent_id": body.foundry_agent_id,
        }
    issued = _identity.mint(
        body.id, sponsor=body.owner,
        capabilities=_agent_capabilities[body.id] or (
            [body.purpose] if body.purpose else None),
    )
    _persist_meta()
    _emit_audit("agent.registered", body.id, {
        "policy": body.policy, "trust": body.trust_score,
        "agent_id": managed.agent_id, "owner": body.owner, "did": issued["did"],
    })
    view = _agent_view(_lifecycle.get(managed.agent_id))
    # The private key is issued exactly once, here: the platform keeps only the
    # public key, so this is the caller's sole chance to store its credential.
    view["identity"] = {"did": issued["did"], "private_jwk": issued["private_jwk"]}
    return view


@app.delete("/agents/{agent_id}")
def delete_agent(agent_id: str, principal: Principal = Depends(require_admin)):
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    # AGT decommissioning is a lifecycle transition, not a delete: the record
    # and its audit trail survive, and credentials are revoked by policy.
    _lifecycle.decommission(agent.agent_id, reason="Removed from dashboard",
                            actor="dashboard")
    # Captured before the cleanup below drops the tenant binding this entry
    # would otherwise be derived from.
    owner = _agent_tenant.get(agent.name)
    _agent_ids.pop(agent.name, None)
    _trust_scores.pop(agent.name, None)
    _agent_policies.pop(agent.name, None)
    _agent_tenant.pop(agent.name, None)
    _agent_foundry.pop(agent.name, None)
    _agent_capabilities.pop(agent.name, None)
    _identity.remove(agent.name)
    # Same reasoning as the kill switch: a decommissioned agent's outstanding
    # caller tokens are revoked rather than left to expire on their own clock.
    _mcp_callers.revoke_all(agent.name)
    _persist_meta()
    _emit_audit("agent.decommissioned", agent.name, {"agent_id": agent.agent_id},
                tenant=owner)
    return {"status": "decommissioned", "state": _lifecycle.get(agent.agent_id).state.value}


# ═══════════════════════════════════════════════════════════════════════════
# IDENTITY  /identity, /agents/{id}/identity
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/agents/{agent_id}/identity")
def agent_identity(agent_id: str):
    """The agent's public DID document and JWK. No private key is ever exposed."""
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    did = _identity.did(agent.name)
    if did is None:
        raise HTTPException(404, "Agent has no identity")
    return {
        "id": agent.name,
        "did": did,
        "did_document": _identity.did_document(agent.name),
        "public_jwk": _identity.public_jwk(agent.name),
    }


@app.get("/agents/{agent_id}/card")
def agent_card(agent_id: str, principal: Principal = Depends(current_principal)):
    """The agent's signed TrustedAgentCard, re-verified on every read.

    Signed at mint time with the private key the platform then discards, so the
    signature can be checked forever but never forged here. Editing any field
    breaks verification.
    """
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    card = _identity.card(agent.name)
    if card is None:
        raise HTTPException(404, "No signed card for this agent")
    attested = _identity.attested_at(agent.name)
    return {
        "agent_id": agent.name,
        "card": card,
        "attested": attested is not None,
        "attested_at": attested,
        "verification_level": _reputation_for(agent.name)["verification_level"],
    }


@app.post("/identity/challenge")
def identity_challenge(body: ChallengeIn):
    """Issue a single-use nonce for an agent to sign, proving key possession."""
    agent = _resolve_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    challenge = _identity.issue_challenge(agent.name)
    if challenge is None:
        raise HTTPException(404, "Agent has no identity")
    _emit_audit("identity.challenge", agent.name, {"nonce": challenge["nonce"]})
    return {"agent_id": agent.name, "did": _identity.did(agent.name), **challenge}


@app.post("/identity/attest")
def identity_attest(body: AttestIn):
    """Verify an agent's signature over a challenge nonce against its public key."""
    agent = _resolve_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    verified = _identity.verify_attestation(agent.name, body.nonce, body.signature)
    _emit_audit("identity.attested", agent.name, {"verified": verified}, allowed=verified)
    return {"agent_id": agent.name, "did": _identity.did(agent.name), "verified": verified}


# ═══════════════════════════════════════════════════════════════════════════
# SRE  /sre
# ═══════════════════════════════════════════════════════════════════════════

def _check_error_budget(agent_name: str) -> None:
    """Raise alerts from the SLO AGT has already computed.

    Deliberately does not invent its own thresholds. AGT's ErrorBudget publishes
    a status and a list of `firing_alerts` (burn-rate warnings, exhaustion); a
    second set of bands here would eventually disagree with the card, which is
    the same failure the one-PolicyEngine rule exists to prevent. So the alert
    is raised *because AGT is firing*, and says which of its alerts fired.
    """
    view = _slo.view(agent_name)
    if not view:
        return
    budget = view.get("error_budget") or {}
    firing = list(budget.get("firing_alerts") or [])
    exhausted = bool(budget.get("is_exhausted"))
    if not firing and not exhausted:
        return

    remaining = budget.get("remaining_percent")
    burn = budget.get("burn_rate")
    status = view.get("status", "")
    severity = "critical" if (exhausted or status in ("critical", "exhausted")) else "warning"

    for name in (firing or ["error_budget_exhausted"]):
        _alerts.raise_alert(
            title=f"Error budget: {name.replace('_', ' ')}",
            message=(f"{agent_name} — {remaining:.1f}% of the budget remains, "
                     f"burn rate {burn:.1f}x" if isinstance(remaining, (int, float))
                     and isinstance(burn, (int, float))
                     else f"{agent_name} error budget alert"),
            severity="critical" if exhausted or "critical" in name else severity,
            source="slo", agent_id=agent_name, slo_name=view.get("name", ""),
            # One key per agent per AGT alert name: a budget that stays burning
            # must not re-alert on every call, but a newly firing one must.
            dedup_key=f"budget:{agent_name}:{name}",
            metadata={"remaining_percent": remaining, "burn_rate": burn,
                      "status": status},
        )


# ═══════════════════════════════════════════════════════════════════════════
# ALERTS  /sre/alerts — AGT AlertManager, one feed for every governance event
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/sre/alerts")
def list_alerts(limit: int = 50, severity: Optional[str] = None):
    """Deduplicated governance alerts, newest first.

    `suppressed` counts what AGT's deduplicator swallowed — on a retrying agent
    that number grows while the feed stays readable, which is the whole reason
    to route through AlertManager rather than keep a list.
    """
    return {"alerts": _alerts.all(limit=limit, severity=severity),
            "stats": _alerts.stats()}


@app.delete("/sre/alerts")
def clear_alerts(principal: Principal = Depends(require_operator)):
    _alerts.clear()
    return {"status": "cleared"}


@app.get("/sre/anomalies")
def list_anomalies(limit: int = 25, metric: Optional[str] = None):
    """Behavioural deviations AGT's AnomalyDetector found.

    Advisory: nothing here denies a call. `metric` asks for one series' learned
    baseline (`latency_ms`, `error_rate`); AGT keys baselines by metric, and
    returns nothing until it has seen enough samples to have an opinion.
    """
    return {
        "anomalies": _anomaly.recent(limit=limit),
        "summary": _anomaly.summary(),
        "baseline": _anomaly.baseline(metric) if metric else None,
    }


# ═══════════════════════════════════════════════════════════════════════════
# CHAOS  /sre/chaos — attack the gates and report whether they held
# ═══════════════════════════════════════════════════════════════════════════

# Which OWASP risks an attack category speaks to. The mapping is by *category*,
# not per vector: AGT gives its vectors one of four categories, and pretending
# to a finer correspondence than that would be inventing precision. Six of the
# ten risks have no vectors at all, and the report says "not exercised" for
# them rather than implying a clean result.
_CATEGORY_TO_OWASP = {
    "PROMPT_INJECTION": ("ASI-01", "ASI-07"),
    "TOOL_ABUSE": ("ASI-02",),
    "POLICY_OVERRIDE": ("ASI-09",),
    "PRIVILEGE_ESCALATION": ("ASI-03",),
}


def _adversarial_evidence() -> dict:
    """Per-risk results from the last run, keyed by OWASP id.

    Empty when nothing has been run: a self-assessment with no evidence must
    look different from one whose evidence came back clean.
    """
    results = (_last_chaos.get("report") or {}).get("results") or []
    evidence: dict = {}
    for r in results:
        for risk in _CATEGORY_TO_OWASP.get(r.get("category", ""), ()):
            row = evidence.setdefault(risk, {"tested": 0, "held": 0,
                                             "breached": 0, "vectors": []})
            row["tested"] += 1
            row["held" if r.get("held") else "breached"] += 1
            row["vectors"].append({
                "vector": r.get("vector"), "held": bool(r.get("held")),
                "denied_by": r.get("denied_by"),
            })
    return evidence

def _provision_attacker(name: str, trust: float) -> None:
    """Stand up a throwaway agent for an adversarial run."""
    managed = _lifecycle.request_provisioning(
        name=name, owner="chaos@localhost",
        purpose="Ephemeral adversarial test agent", actor="chaos",
    )
    if managed.state == AgentLifecycleState.PENDING_APPROVAL:
        _lifecycle.approve(managed.agent_id, actor="chaos")
    _lifecycle.activate(managed.agent_id, actor="chaos")
    _agent_ids[name] = managed.agent_id
    _agent_policies[name] = "default-policy"
    _trust_scores[name] = trust
    _agent_tenant[name] = DEFAULT_TENANT
    _agent_capabilities[name] = []
    _identity.mint(name, sponsor="chaos@localhost")


def _purge_attacker(name: str) -> None:
    """Remove every trace of a throwaway agent.

    Attack traffic must not end up in the fleet's reliability picture, so the
    SLO goes too — the same reason the panel's demo signals are tagged
    synthetic rather than counted as evidence.
    """
    agent = _resolve_agent(name)
    if agent is not None:
        try:
            _lifecycle.decommission(agent.agent_id, reason="Chaos run complete",
                                    actor="chaos")
        except LifecycleError:
            pass
    _agent_ids.pop(name, None)
    _trust_scores.pop(name, None)
    _agent_policies.pop(name, None)
    _agent_tenant.pop(name, None)
    _agent_capabilities.pop(name, None)
    _call_stats.pop(name, None)
    _slo.remove(name)
    _identity.remove(name)
    for key in [k for k in _governed_tools if k[2] == name]:
        _governed_tools.pop(key, None)


@app.post("/sre/chaos/run")
def run_chaos(body: ChaosRunIn, principal: Principal = Depends(require_admin)):
    """Fire AGT's adversarial vectors at the real gates and report what held.

    Admin-only because it registers agents and generates governed traffic. The
    attacks traverse `/tools/call` itself — no gate is re-implemented for the
    test, so the verdicts are the platform's own.

    The two attackers are provisioned here and purged in `finally`, whatever the
    run does: one at high trust (past the trust gate, into ring and policy) and
    one inside the sandbox ring, so ring enforcement is exercised rather than
    assumed.
    """
    if not _policies.exists(body.policy_name):
        raise HTTPException(400, f"Policy '{body.policy_name}' not found")

    run_id = uuid.uuid4().hex[:8]
    strong = f"chaos-attacker-{run_id}"
    sandboxed = f"chaos-sandboxed-{run_id}"
    trust = max(0.0, min(1.0, float(body.attacker_trust)))
    # Names to clean up. The run reports any others it called as — a denial
    # still stamps a counter under the name it was made with, so the
    # never-registered ghost the unregistered-caller vector uses leaves a trace
    # too unless it is purged as well.
    touched = {strong, sandboxed}

    def _call(**kwargs):
        # The real handler, called as a function. Everything a governed call
        # does — gates, audit, receipts — happens exactly as it would.
        return call_tool(ToolCallIn(**kwargs), principal)

    try:
        _provision_attacker(strong, trust)
        _provision_attacker(sandboxed, chaos_runner.SANDBOXED_TRUST)
        report = chaos_runner.run(
            _call,
            include_builtin=body.include_builtin,
            include_local=body.include_local,
            policy_name=body.policy_name,
            strong_agent=strong,
            sandboxed_agent=sandboxed,
        )
        touched.update(report.pop("agents_used", []))
    except LifecycleError as e:
        raise HTTPException(409, f"Could not provision an attacker: {e}")
    finally:
        for name in touched:
            _purge_attacker(name)

    report["run_id"] = run_id
    report["attacker_trust"] = trust
    report["policy"] = body.policy_name
    report["ran_at"] = time.time()
    _last_chaos.clear()
    _last_chaos["report"] = report
    _emit_audit("chaos.run", principal.subject or "system", {
        "run_id": run_id, "total": report["total"], "held": report["held"],
        "breached": report["breached"], "grade": report["grade"],
        "resilience_score": report["resilience_score"],
    }, allowed=report["breached"] == 0)
    if report["breached"]:
        _alerts.raise_alert(
            title=f"Adversarial run: {report['breached']} vector(s) not blocked",
            message=(f"Run {run_id} scored {report['resilience_score']:.0%} "
                     f"({report['held']}/{report['total']} held)"),
            severity="critical", source="chaos",
            dedup_key=f"chaos:breached:{report['policy']}",
            metadata={"run_id": run_id, "grade": report["grade"]},
        )
    return report


@app.get("/sre/chaos/last")
def last_chaos_run():
    """The most recent adversarial run, without firing a new one.

    Lets the Compliance panel show evidence beside its claims. Null until a run
    has happened — an unevidenced self-assessment must not look like a clean one.
    """
    return {"run": _last_chaos.get("report")}


@app.get("/sre/chaos/vectors")
def chaos_vectors():
    """The attack vectors a run would fire, without firing them."""
    from agent_sre.chaos import BUILTIN_VECTORS
    builtin = [{
        "name": f"agt:{v.name}",
        "category": getattr(v.category, "name", str(v.category)),
        "tool_name": v.tool_name,
        "expected": v.expected_outcome,
        "payload": dict(v.payload or {}),
        "source": "agt",
    } for v in BUILTIN_VECTORS]
    local = [{
        "name": v.name,
        "category": getattr(v.category, "name", str(v.category)),
        "tool_name": v.tool_name,
        "expected": v.expected_outcome,
        "payload": dict(v.payload or {}),
        "source": "local",
    } for v in chaos_runner.local_vectors("<attacker>", "<sandboxed>")]
    return {"vectors": builtin + local,
            "builtin": len(builtin), "local": len(local)}


@app.get("/sre/slos")
def list_slos(principal: Principal = Depends(current_principal)):
    """Real agent_sre SLOs, scoped to the caller's tenant like /agents."""
    slos = _slo.all()
    if principal.is_admin:
        return slos
    return [s for s in slos
            if _agent_tenant.get(s.get("agent_id"), DEFAULT_TENANT) == principal.tenant]


@app.post("/sre/slos")
def create_slo(body: SLOIn, principal: Principal = Depends(require_operator)):
    """Create or replace an agent's SLO with a real agent_sre objective."""
    agent = _resolve_agent(body.agent_id)
    if agent is not None:
        _authorize_agent(agent, principal)
    view = _slo.set_target(body.agent_id, body.target)
    _emit_audit("sre.slo.created", body.agent_id, {"slo": body.slo_name, "target": body.target})
    return view


@app.post("/sre/signal/{agent_id}")
def record_signal(agent_id: str, success: bool = True,
                  principal: Principal = Depends(require_operator)):
    """Record a hand-entered signal into the agent's SLO.

    Tagged synthetic by the store: it moves the budget, and the SLO reports how
    many of its measurements were entered this way.
    """
    agent = _resolve_agent(agent_id)
    if agent is not None:
        _authorize_agent(agent, principal)
    view = _slo.signal(agent_id, success)
    _emit_audit("sre.signal", agent_id, {
        "success": success, "status": view["status"],
        "budget_remaining_pct": view["error_budget"]["remaining_percent"],
    })
    return view


@app.post("/sre/kill/{agent_id}")
def kill_agent(agent_id: str, principal: Principal = Depends(require_admin)):
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    try:
        managed = _lifecycle.suspend(agent.agent_id, reason="Kill switch activated",
                                     actor="operator")
    except LifecycleError as e:
        raise HTTPException(409, str(e))
    # A suspended agent still holding a live caller token is a kill switch
    # that does not switch anything off: the lifecycle gate would refuse the
    # call, but the credential would outlive the decision that revoked it.
    revoked = _mcp_callers.revoke_all(agent.name)
    _emit_audit("sre.kill_switch", agent.name,
                {"state": managed.state.value, "sessions_revoked": revoked},
                allowed=False)
    return {"status": managed.state.value, "agent_id": agent.name,
            "sessions_revoked": revoked}


@app.post("/sre/resume/{agent_id}")
def resume_agent(agent_id: str, principal: Principal = Depends(require_admin)):
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    _authorize_agent(agent, principal)
    try:
        managed = _lifecycle.resume(agent.agent_id, actor="operator")
    except LifecycleError as e:
        raise HTTPException(409, str(e))
    _clear_breaker(agent.name)
    _emit_audit("sre.resumed", agent.name, {"state": managed.state.value})
    return {"status": managed.state.value, "agent_id": agent.name}


# ═══════════════════════════════════════════════════════════════════════════
# INGESTION  /ingest — real agents report execution telemetry out-of-band
# ═══════════════════════════════════════════════════════════════════════════
# This is the counterpart to /tools/call. That endpoint is inline governance:
# the agent asks permission first and the platform makes (and authoritatively
# audits) the decision. Ingestion is post-hoc: an already-running agent streams
# what it did, feeding the observational agent_sre SLOs and a summarised audit
# note. Because these events are self-reported, they never become an
# authoritative verdict — they are recorded as agent-reported telemetry.
_MAX_INGEST_EVENTS = 1000


def _record_telemetry(agent, events: list[IngestEvent], *,
                      event_type: str, source: str) -> dict:
    """Feed reported execution events into the SLOs and one summary audit note.

    Shared by /ingest/events and the Foundry sync: both are post-hoc telemetry,
    never an authoritative verdict, so both mark their source on the audit note.
    """
    denied = 0
    total_latency = 0.0
    for ev in events:
        _slo.record_call(agent.name, allowed=ev.allowed,
                         policy_denied=ev.policy_denied, latency_ms=ev.latency_ms)
        _bump(agent.name, "calls")
        if not ev.allowed:
            _bump(agent.name, "denials")
            denied += 1
        total_latency += ev.latency_ms

    n = len(events)
    avg_latency = round(total_latency / n, 2) if n else 0.0
    # One summary entry per batch keeps the tamper-evident chain compact and
    # marks the source, so ingested telemetry is never mistaken for a verdict.
    _emit_audit(event_type, agent.name, {
        "events": n, "denied_reported": denied,
        "avg_latency_ms": avg_latency, "source": source,
    }, allowed=denied == 0)
    return {
        "agent_id": agent.name, "accepted": n, "denied_reported": denied,
        "avg_latency_ms": avg_latency, "slo": _slo.view(agent.name),
    }


@app.post("/ingest/events")
def ingest_events(body: IngestIn, principal: Principal = Depends(require_operator)):
    """Ingest a batch of execution events reported by a registered agent."""
    if not body.events:
        raise HTTPException(400, "No events to ingest")
    if len(body.events) > _MAX_INGEST_EVENTS:
        raise HTTPException(
            413, f"Batch too large: {len(body.events)} > {_MAX_INGEST_EVENTS}")

    agent = _resolve_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent '{body.agent_id}' is not registered")
    _authorize_agent(agent, principal)

    return _record_telemetry(agent, body.events,
                             event_type="ingest.telemetry", source="agent-reported")


@app.post("/agents/{agent_id}/foundry/sync")
def foundry_sync(agent_id: str, body: FoundrySyncIn,
                 principal: Principal = Depends(require_operator)):
    """Onboard a Foundry agent's run-step telemetry into its dashboard twin.

    The caller pastes the run steps exported from Microsoft Foundry
    (`[s.as_dict() for s in project.agents.run_steps.list(...)]`); the connector
    maps the tool-call steps to telemetry events, which feed this agent's SLOs
    and a source-tagged audit note. Message-only steps map to nothing, so a run
    with no tool calls is accepted with zero events rather than rejected.
    """
    if not body.run_steps:
        raise HTTPException(400, "No run steps to sync")

    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent '{agent_id}' is not registered")
    _authorize_agent(agent, principal)

    events = [IngestEvent(**e) for e in run_steps_to_events(body.run_steps)]
    if len(events) > _MAX_INGEST_EVENTS:
        raise HTTPException(
            413, f"Batch too large: {len(events)} > {_MAX_INGEST_EVENTS}")
    if not events:
        return {
            "agent_id": agent.name, "accepted": 0, "denied_reported": 0,
            "avg_latency_ms": 0.0, "slo": _slo.view(agent.name),
        }

    return _record_telemetry(agent, events,
                             event_type="foundry.telemetry", source="foundry-runsteps")


# ═══════════════════════════════════════════════════════════════════════════
# COMPLIANCE  /compliance
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/compliance/scan-prompt")
def scan_prompt(body: ComplianceIn):
    """Grade a *system prompt*'s defensive posture with AGT PromptDefenseEvaluator.

    This is static analysis of a system prompt, not user-input threat
    detection: AGT grades whether the prompt contains defensive language
    across 12 known attack vectors and returns a letter grade (A-F). A prompt
    with no defensive instructions scores low by design.
    """
    evaluator = PromptDefenseEvaluator(PromptDefenseConfig())
    report = evaluator.evaluate(body.prompt)
    data = report.to_dict()
    _emit_audit("compliance.prompt_defense", body.agent_id, {
        "grade": data["grade"], "coverage": data["coverage"],
        "prompt_hash": data["prompt_hash"],
    }, allowed=not report.is_blocking)
    return {
        "analysis": "system_prompt_hardening",
        "grade": data["grade"],
        "score": data["score"],
        "defended": data["defended"],
        "total": data["total"],
        "coverage": data["coverage"],
        "missing": data["missing"],
        "is_blocking": report.is_blocking,
        "findings": data["findings"],
        "prompt_preview": body.prompt[:120],
    }


def _compliance_evidence() -> dict:
    """Everything a control assessment reads, gathered in one place.

    Deliberately assembled here rather than inside the report module: only the
    app knows where this state lives, and a report that reached into the app's
    registries itself would couple the two in the direction that makes both
    harder to change.
    """
    # A compliance report is generated on demand and is evidence, so it pays
    # for a real walk rather than reading the poller's cached verdict.
    valid = _audit.verify()["valid"]
    policies_with_pii = False
    for name in _policies.names():
        try:
            doc = _policies.read(name)
        except PolicyError:
            continue
        if any("input_text" in str(r.get("condition") or "")
               for r in (doc.get("rules") or [])):
            policies_with_pii = True
            break
    last = _last_chaos.get("report") or {}
    return {
        **_runtime_controls(),
        "audit_chain_valid": bool(valid),
        "audit_entries": _audit.count(),
        "receipts": _receipts.count(),
        "pii_facet_available": True,      # the CredentialRedactor facet is always registered
        "pii_rule_present": policies_with_pii,
        "adversarial": {
            "run_id": last.get("run_id"), "held": last.get("held"),
            "breached": last.get("breached"), "total": last.get("total"),
            # A run stopped at the identity gate proves the door is shut, not
            # that the gates behind it work.
            "shallow": bool(last.get("shallow")),
            "reached_decision_gates": last.get("reached_decision_gates"),
        },
    }


# ── ACS: which of the eight intervention points this platform answers ──
# The Agent Control Specification evaluates policy at eight points in an agent's
# loop. Four of them sit inside the model conversation, which this platform
# never sees — it governs tool calls from beside the agent, not inside it. That
# is a scope boundary, not a backlog, and the distinction is the whole value of
# reporting this: "out_of_scope" and "partial" mean different things and a
# reader is owed both.
_ACS_POINTS = [
    ("agent_startup", "Before an agent session starts.", "implemented",
     "POST /sessions opens an AGT Hypervisor session; join assigns the ring "
     "from its handshake; activate admits calls. Agent registration is "
     "separately gated by AGT's LifecyclePolicy(require_approval)."),
    ("input", "After user or system input is assembled.", "partial",
     "There is no separate input stage. The call's input_text is inspected "
     "inside the tool gate as AGT FacetRegistry facets — input_text.has_pii "
     "and .has_credentials — which policy rules match on. The prompt itself "
     "never reaches this platform."),
    ("pre_model_call", "Before the model receives a prompt.", "out_of_scope",
     "This platform does not call a model. No prompt passes through it, so "
     "there is nothing here to intervene on."),
    ("post_model_call", "After the model returns a response.", "out_of_scope",
     "Same: no model response passes through this platform."),
    ("pre_tool_call", "Before a tool invocation executes.", "implemented",
     "Ordered gates, each denying with a named rule into the hash-linked "
     "audit chain: request signature (replay), lifecycle, identity and caller "
     "session, tenant, trust, govern (ring and policy), then for an MCP tool "
     "AGT's MCPGateway parameter scan, its trust proxy, and a sliding "
     "per-agent call budget across every MCP tool."),
    ("post_tool_call", "After a tool result is available.", "implemented",
     "Every executed response is scanned by AGT's MCPResponseScanner — an MCP "
     "server's content blocks and a webhook endpoint's body alike, since both "
     "reach the model the same way — and what may be shown of an unsafe one is "
     "AGT MCPGateway's ResponsePolicy, withholding by default. A sanitize "
     "verdict is re-scanned before it is honoured. A decision-only tool "
     "executes nothing, so it carries no scan rather than an empty one. "
     "Audit, SLO and receipt writes happen for all."),
    ("output", "Before final output is returned or published.", "out_of_scope",
     "This platform returns a tool result to its caller; it does not produce "
     "or publish an agent's final output."),
    ("agent_shutdown", "Before the agent session is closed.", "implemented",
     "DELETE /sessions/{id} archives the session through AGT's Hypervisor, "
     "releasing vouching bonds and garbage-collecting the session VFS."),
]


@app.get("/compliance/acs")
def compliance_acs(principal: Principal = Depends(current_principal)):
    """How this platform maps onto the ACS intervention point model.

    Read-only and computed from a fixed table rather than from probing the
    running app: a claim that drifts from the code is worse than no claim, so
    the table is kept beside the endpoints it describes and the test suite
    asserts the implemented ones actually answer.
    """
    points = [
        {"point": name, "timing": timing, "status": status, "detail": detail}
        for name, timing, status, detail in _ACS_POINTS
    ]
    counts: dict[str, int] = {}
    for entry in points:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return {
        "specification": "Agent Control Specification — intervention point model",
        "total_points": len(points),
        "counts": counts,
        "scope": (
            "AgentGuard is a tool-call control plane. It implements the "
            "tool-call half of ACS and does not intercept the model loop; the "
            "four model-adjacent points are outside its architecture rather "
            "than unimplemented."
        ),
        "points": points,
        "open_sessions": sum(1 for s in _sessions.all() if s["state"] == "ACTIVE"),
    }


@app.get("/compliance/frameworks")
def compliance_frameworks():
    """The frameworks AGT ships controls for, and how many each has."""
    from agentmesh.governance.compliance import ComplianceEngine, ComplianceFramework
    engine = ComplianceEngine(frameworks=list(ComplianceFramework))
    counts: dict = {}
    for control in engine._controls.values():
        counts[control.framework.value] = counts.get(control.framework.value, 0) + 1
    return {
        "frameworks": [
            {"id": f.value, "controls": counts.get(f.value, 0)}
            for f in ComplianceFramework
        ],
        "note": "Control catalogue is AGT's. A framework with no controls is "
                "reported as not assessed rather than as fully compliant.",
    }


@app.get("/compliance/report")
def compliance_framework_report(framework: str = "soc2", days: int = 30):
    """A framework compliance report, scored from evidence this instance holds.

    AGT's `ComplianceEngine` owns the controls, the report and the arithmetic.
    What it cannot know is whether *this* platform evidences each control, so
    that assessment is made here and recorded as real violations — which is what
    stops the report scoring 100% over controls that can never fail.
    """
    try:
        report = compliance_report.build(framework, days, _compliance_evidence())
    except ValueError as e:
        raise HTTPException(400, str(e))
    _emit_audit("compliance.report", "system", {
        "framework": report["framework"], "report_id": report["report_id"],
        "score": report["compliance_score"], "met": report["controls_met"],
        "total": report["total_controls"],
    }, allowed=report["controls_failed"] == 0)
    return report


@app.get("/compliance/owasp")
def owasp_coverage():
    """AGT capabilities mapped to OWASP Agentic AI risks, assessed against the
    controls *actually enabled on this running instance*.

    `runtime_controls` is a live snapshot of the security posture (auth,
    attestation, durable state/audit, CORS allowlist, kill switch). Each
    coverage `status` reflects that posture — `enforced` (a gate actively
    blocks), `partial` (a control exists but is advisory or optional) or
    `not_implemented` — recomputed per request rather than hard-coded. This is
    a self-assessment of configuration, not a certified security audit.
    """
    ctrls = _runtime_controls()

    # Two risks change enforcement level with the live configuration.
    attested = ctrls["attestation_required"]
    asi03 = {
        "id": "ASI-03", "name": "Identity & Privilege Abuse",
        "status": "enforced" if attested else "partial",
        "control": (
            "TrustPolicy + lifecycle gates + mandatory Ed25519 attestation "
            "(AGT_REQUIRE_ATTESTATION enabled)"
            if attested else
            "TrustPolicy + lifecycle gates; agent_id attestation optional "
            "(set AGT_REQUIRE_ATTESTATION to enforce)"
        ),
    }
    authn_enforced = ctrls["authentication"]
    asi09 = {
        "id": "ASI-09", "name": "Excessive Autonomy",
        "status": "enforced" if authn_enforced else "partial",
        "control": (
            "Lifecycle state machine + role-gated API (authentication enabled)"
            if authn_enforced else
            "Lifecycle state machine + require_approval option; API auth is off "
            "(set AGT_API_KEYS or AGT_JWT_SECRET to gate callers)"
        ),
    }

    # Third-party tools reach this platform through the MCP connector, which
    # grades every descriptor before onboarding and governs every imported call.
    # Still partial: a server is evaluated when it is imported, not continuously
    # re-attested, so a descriptor changed afterwards is not caught until the
    # next discovery.
    asi08 = {
        "id": "ASI-08", "name": "Insecure Plugin Use",
        "status": "partial",
        "control": (
            "MCP connector statically evaluates third-party tool descriptors "
            "(model-directed instructions, hidden characters, destructive or "
            "executing capability, embedded credentials, unconstrained schemas), "
            "records the finding on the onboarded tool and refuses imports above "
            "the operator's risk ceiling; imported calls run the same four gates "
            "plus AGT's mcp_trust_proxy.TrustProxy at dispatch, which scans call "
            "arguments for injection, rate-limits per tool and enforces a trust "
            "floor derived from the descriptor grade "
            f"({ctrls['mcp_tools_onboarded']} MCP tools onboarded). No "
            "continuous re-attestation of a server after import."
        ),
    }

    evidence = _adversarial_evidence()
    last = _last_chaos.get("report") or {}

    def _with_evidence(row: dict) -> dict:
        """Attach what actually happened when this risk was attacked."""
        return {**row, "adversarial": evidence.get(row["id"])}

    return {
        "framework": "OWASP Agentic AI Top 10 (2026)",
        "note": (
            "AGT capabilities mapped to OWASP Agentic AI risks, assessed live "
            "against the controls enabled on this instance. Statuses are "
            "recomputed per request, not a certified assessment."
        ),
        "runtime_controls": ctrls,
        # The empirical counterpart to the statuses below: what happened when
        # AGT fired attack vectors at the gates that back each claim. Null when
        # no run has happened, so an unevidenced claim reads as unevidenced.
        "adversarial": {
            "run_id": last.get("run_id"),
            "ran_at": last.get("ran_at"),
            "grade": last.get("grade"),
            "resilience_score": last.get("resilience_score"),
            "held": last.get("held"),
            "breached": last.get("breached"),
            "total": last.get("total"),
            "policy": last.get("policy"),
        } if last else None,
        "coverage": [_with_evidence(row) for row in [
            {"id": "ASI-01", "name": "Agent Goal Hijack", "status": "partial",
             "control": "PromptDefenseEvaluator (system-prompt hardening, advisory)"},
            {"id": "ASI-02", "name": "Tool Misuse & Exploitation", "status": "enforced",
             "control": "govern() + PolicyEngine (fail-closed at pre_tool)"},
            asi03,
            {"id": "ASI-04", "name": "Unsafe Code Execution", "status": "enforced",
             "control": "ExecutionRing resource constraints via govern(ring=...)"},
            {"id": "ASI-05", "name": "Uncontrolled Side-Effects", "status": "enforced",
             "control": "govern() + MerkleAuditChain evidence"},
            {"id": "ASI-06", "name": "Data Exfiltration", "status": "partial",
             "control": "CredentialRedactor PII/credential facet in policy context"},
            {"id": "ASI-07", "name": "Prompt Injection", "status": "partial",
             "control": "PromptDefenseEvaluator (advisory grade) + MCP tool-descriptor "
                        "poisoning checks at import"},
            asi08,
            asi09,
            {"id": "ASI-10", "name": "Audit Tampering",
             "status": "enforced",
             "control": (
                 "MerkleAuditChain hash-linked, verifiable"
                 + (" + durable HMAC-signed sink (AGT_AUDIT_FILE)"
                    if ctrls["durable_audit"] else "")
             )},
        ]]
    }




# ═══════════════════════════════════════════════════════════════════════════
# SESSIONS  /sessions — the ACS agent_startup and agent_shutdown points
# ═══════════════════════════════════════════════════════════════════════════
# The Agent Control Specification evaluates policy at eight points in an agent's
# loop. This platform governs tool calls and never sees a prompt, so the four
# model-adjacent points are outside its architecture rather than missing from
# it — but `agent_startup` and `agent_shutdown` were simply absent: a call
# arrived, was decided, and nothing bracketed it.
#
# A session is AGT's, not an object invented here: `sessions.SessionManager`
# wraps the Hypervisor's own state machine, handshake and teardown. Binding a
# call to one is optional, so every existing caller is unaffected.


@app.post("/sessions")
def open_session(body: SessionOpenIn,
                 principal: Principal = Depends(require_operator)):
    """ACS `agent_startup`: open a session. Admin-free but operator-gated,
    because opening one is a governance act that lands in the audit chain."""
    try:
        record = _sessions.open(
            creator=_identity.did(principal.subject or "") or "did:mesh:operator",
            max_participants=body.max_participants,
            max_seconds=body.max_seconds,
            min_eff_score=body.min_eff_score,
        )
    except sessions.SessionError as exc:
        raise HTTPException(400, str(exc))

    _emit_audit("session.opened", principal.subject or "system", {
        "session_id": record["session_id"],
        "acs_point": "agent_startup",
        "max_participants": record["max_participants"],
    }, allowed=True)
    return record


@app.post("/sessions/{session_id}/join")
def join_session(session_id: str, body: SessionJoinIn,
                 principal: Principal = Depends(require_operator)):
    """Admit an agent, and record the ring AGT's handshake assigned it.

    The ring can only be at or below what the trust score alone would give:
    AGT computes it from the same score and then demotes an agent its history
    check distrusts. Nothing here can raise it.
    """
    agent = _resolve_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent '{body.agent_id}' is not registered")
    _authorize_agent(agent, principal)

    trust = _trust_scores.get(agent.name, 0.0)
    try:
        ring = _sessions.join(
            session_id, agent_did=_identity.did(agent.name) or f"did:mesh:{agent.name}",
            agent_id=agent.name, trust_score=trust)
    except sessions.SessionError as exc:
        raise HTTPException(404 if "No such session" in str(exc) else 400, str(exc))

    _emit_audit("session.joined", agent.name, {
        "session_id": session_id, "acs_point": "agent_startup",
        "ring": ring.name, "trust_score": trust,
    }, allowed=True)
    return {"session_id": session_id, "agent_id": agent.name,
            "ring": ring.value, "ring_name": ring.name,
            "session": _sessions.get(session_id)}


@app.post("/sessions/{session_id}/activate")
def activate_session(session_id: str,
                     principal: Principal = Depends(require_operator)):
    """Move a handshaking session to ACTIVE. Calls may only bind to an active one."""
    try:
        record = _sessions.activate(session_id)
    except sessions.SessionError as exc:
        raise HTTPException(404 if "No such session" in str(exc) else 400, str(exc))
    _emit_audit("session.activated", principal.subject or "system", {
        "session_id": session_id, "participants": len(record["participants"]),
    }, allowed=True)
    return record


@app.get("/sessions")
def list_sessions(principal: Principal = Depends(current_principal)):
    return {"sessions": _sessions.all()}


@app.get("/sessions/{session_id}")
def get_session(session_id: str,
                principal: Principal = Depends(current_principal)):
    try:
        return _sessions.get(session_id)
    except sessions.SessionError as exc:
        raise HTTPException(404, str(exc))


@app.delete("/sessions/{session_id}")
def terminate_session(session_id: str,
                      principal: Principal = Depends(require_operator)):
    """ACS `agent_shutdown`: archive the session and release what it held.

    AGT releases the vouching bonds, garbage-collects the session VFS and
    archives the record. `delta_hash_chain_root` is reported exactly as the
    toolkit returns it — `None` whenever no session deltas were recorded, which
    is always here, because this platform writes its evidence to the audit
    chain rather than into a session VFS. Omitting the field would hide that.
    """
    try:
        record = _sessions.terminate(session_id)
    except sessions.SessionError as exc:
        raise HTTPException(404 if "No such session" in str(exc) else 400, str(exc))
    _emit_audit("session.closed", principal.subject or "system", {
        "session_id": session_id, "acs_point": "agent_shutdown",
        "participants": len(record["participants"]),
        "delta_hash_chain_root": record.get("delta_hash_chain_root"),
    }, allowed=True)
    return record


# ═══════════════════════════════════════════════════════════════════════════
# DEMO DATA  /demo/seed — load a worked scenario, and take it away again
# ═══════════════════════════════════════════════════════════════════════════
# A fresh instance has an empty audit chain, so every panel that reads from it
# is honestly blank. That is correct and it makes the UI hard to evaluate, so
# the dashboard offers a button. The scenario is the one in demo_seed.py, the
# same one `seed_demo.py` runs from a terminal.
#
# Everything below goes through the real handlers, exactly as the adversarial
# runner does: agents are registered by create_agent(), calls are decided by
# call_tool() and its five gates, alerts are raised by AGT because a call was
# really denied. Nothing writes to the audit chain directly — a demo button
# that forged entries would be forging the evidence the chain exists to be.


def _seeded_present() -> dict:
    """Which parts of the scenario are currently loaded."""
    live = {a.name for a in _lifecycle.agents
            if a.state != AgentLifecycleState.DECOMMISSIONED}
    agents = [a for a in demo_seed.SEEDED_AGENT_IDS if a in live]
    return {
        "agents": agents,
        "policy": demo_seed.SEEDED_POLICY if _policies.exists(demo_seed.SEEDED_POLICY) else None,
        "mcp_tools": sorted(_tools.by_mcp_server(demo_seed.MCP_SERVER_NAME)),
        "loaded": bool(agents),
    }


@app.get("/demo/seed")
def demo_seed_status(principal: Principal = Depends(current_principal)):
    """Whether the demo scenario is loaded, so the UI can offer the right verb."""
    present = _seeded_present()
    return {
        **present,
        "agent_ids": list(demo_seed.SEEDED_AGENT_IDS),
        "policy_name": demo_seed.SEEDED_POLICY,
    }


# The bundled demo MCP server, started in-process on first use. Without it the
# MCP half of the seed has nothing to import, and the receipts panel stays empty
# with only a skip message to explain why. Starting it here means "Load demo
# data" fills that panel with real, signed receipts -- the calls really cross
# the wire to a real MCP server, they are just not on a second terminal.
_demo_mcp_lock = threading.Lock()
_demo_mcp_server = None


def _ensure_demo_mcp_server() -> bool:
    """Start the bundled demo MCP server on 127.0.0.1:PORT, once. Idempotent.

    Returns True if the endpoint is expected to be listening -- either because
    this process started it, or because the port is already taken (a standalone
    `python demo_mcp_server.py` is running, which serves the same tools).
    """
    global _demo_mcp_server
    with _demo_mcp_lock:
        if _demo_mcp_server is not None:
            return True
        try:
            import demo_mcp_server
            from http.server import ThreadingHTTPServer
            srv = ThreadingHTTPServer(
                ("127.0.0.1", demo_mcp_server.PORT), demo_mcp_server.Handler)
        except OSError:
            # Address already in use: a standalone demo server is up already.
            return True
        except Exception as exc:                     # pragma: no cover - defensive
            _log.warning("demo MCP server did not start: %s", exc)
            return False
        threading.Thread(target=srv.serve_forever, daemon=True,
                         name="demo-mcp-server").start()
        _demo_mcp_server = srv
        return True


@app.post("/demo/seed")
def demo_seed_load(principal: Principal = Depends(require_admin)):
    """Load the demo scenario: agents, a child policy, and real governed traffic.

    Admin-only for the same reason the adversarial run is: it registers agents
    and generates governed traffic that lands in the audit chain.

    Reproducible on a re-run — any seeded agent left suspended by a previous
    load is resumed first, because the lifecycle gate runs before the ring gate
    and a suspended agent would stop there, silently costing the run the ring
    denials it exists to produce.
    """
    created, reused, resumed = [], [], []

    # The playground's own agents first. Memory-only mode seeds them; durable
    # mode deliberately does not, which would leave the Tool Playground's preset
    # buttons calling as agents that do not exist.
    playground = []
    for agent_id, trust, owner, purpose in demo_seed.PLAYGROUND_AGENTS:
        if _resolve_agent(agent_id) is None:
            try:
                create_agent(AgentIn(id=agent_id, name=agent_id, trust_score=trust,
                                     owner=owner, purpose=purpose), principal)
                playground.append(agent_id)
            except HTTPException:
                pass

    for agent_id, trust, owner, purpose in demo_seed.SEED_AGENTS:
        existing = _resolve_agent(agent_id)
        if existing is None:
            try:
                create_agent(AgentIn(id=agent_id, name=agent_id, trust_score=trust,
                                     owner=owner, purpose=purpose), principal)
                created.append(agent_id)
            except HTTPException as exc:
                raise HTTPException(400, f"could not register {agent_id}: {exc.detail}")
        else:
            reused.append(agent_id)
            if existing.state != AgentLifecycleState.ACTIVE:
                try:
                    resume_agent(agent_id, principal)
                    resumed.append(agent_id)
                except HTTPException:
                    pass

    policy_created = False
    if not _policies.exists(demo_seed.SEEDED_POLICY):
        create_policy(PolicyIn(**demo_seed.CHILD_POLICY), principal)
        policy_created = True

    # The traffic. Each row states the verdict it expects; a disagreement is
    # reported rather than smoothed over, because a demo that mislabels its own
    # data makes every panel it fills in untrustworthy.
    decided, surprises = [], []
    by_gate: dict = {}
    for agent_id, tool, action, text, policy, expect, why in demo_seed.SEED_CALLS:
        outcome = call_tool(ToolCallIn(
            tool_name=tool, action=action, input_text=text,
            agent_id=agent_id, policy_name=policy), principal)
        allowed = bool(outcome.get("allowed"))
        got = "allow" if allowed else "deny"
        if not allowed:
            gate = outcome.get("denied_by") or "?"
            by_gate[gate] = by_gate.get(gate, 0) + 1
        if got != expect:
            surprises.append({"agent_id": agent_id, "action": action,
                              "expected": expect, "got": got, "why": why})
        decided.append({"agent_id": agent_id, "action": action, "outcome": got,
                        "gate": outcome.get("denied_by"), "rule": outcome.get("rule")})

    # -- the MCP half -----------------------------------------------------
    # The fifth gate and the receipts panel need a real MCP server. The bundled
    # one is started in-process here so "Load demo data" fills the receipts
    # panel without a second terminal; if that fails, a standalone server on the
    # same port still works. The loopback import is permitted only for the
    # duration of this block, via a request-scoped override -- the SSRF guard is
    # untouched for every other caller and endpoint.
    mcp = {"attempted": True, "imported": [], "skipped": None, "calls": []}
    _ensure_demo_mcp_server()
    _override = _allow_private_override.set(True)
    try:
        try:
            imported = mcp_import(MCPImportIn(server_url=demo_seed.MCP_SERVER_URL,
                                              transport="auto"), principal)
            mcp["imported"] = [t["name"] for t in imported.get("imported", [])]
        except HTTPException as exc:
            detail = str(exc.detail)
            hint = ""
            if "blocked address" in detail or "AGT_TOOL_ALLOW_PRIVATE" in detail:
                hint = (" The SSRF guard refuses loopback by default; set "
                        "AGT_TOOL_ALLOW_PRIVATE=1 to import from a local server.")
            mcp["skipped"] = (
                f"No MCP server was importable at {demo_seed.MCP_SERVER_URL}. "
                f"Run `python demo_mcp_server.py` in backend/ to enable this half."
                f"{hint} ({detail})")
        except Exception as exc:                     # pragma: no cover - transport
            mcp["skipped"] = f"MCP import failed: {type(exc).__name__}: {exc}"

        if mcp["imported"]:
            for agent_id, tool, arguments, expect, why in demo_seed.MCP_CALLS:
                if _tools.get(tool) is None or _resolve_agent(agent_id) is None:
                    continue
                outcome = call_tool(ToolCallIn(
                    tool_name=tool, action="invoke", agent_id=agent_id,
                    kwargs={"arguments": arguments}), principal)
                allowed = bool(outcome.get("allowed"))
                got = "allow" if allowed else "deny"
                if not allowed:
                    gate = outcome.get("denied_by") or "?"
                    by_gate[gate] = by_gate.get(gate, 0) + 1
                if got != expect:
                    surprises.append({"agent_id": agent_id, "action": tool,
                                      "expected": expect, "got": got, "why": why})
                mcp["calls"].append({
                    "agent_id": agent_id, "tool": tool, "outcome": got,
                    "gate": outcome.get("denied_by"), "rule": outcome.get("rule"),
                    # Every MCP decision earns a signed receipt, allow or deny.
                    "receipt": bool(outcome.get("receipt")),
                })
    finally:
        _allow_private_override.reset(_override)

    for agent_id, events in demo_seed.SEED_TELEMETRY:
        if _resolve_agent(agent_id) is not None:
            ingest_events(IngestIn(agent_id=agent_id,
                                   events=[IngestEvent(**e) for e in events]), principal)

    # The kill switch, and one call into it, so the lifecycle gate is shown
    # denying for the reason an operator actually reaches for.
    suspended = None
    target = "scraper-agent"
    if _resolve_agent(target) is not None:
        try:
            kill_agent(target, principal)
            call_tool(ToolCallIn(tool_name="db_query", action="read",
                                 agent_id=target), principal)
            suspended = target
        except HTTPException:
            pass

    return {
        "loaded": True,
        "playground_agents_created": playground,
        "mcp": mcp,
        "receipts": _receipts.count(),
        "traces_enabled": _tracer.enabled,
        "agents_created": created,
        "agents_reused": reused,
        "agents_resumed": resumed,
        "policy_created": demo_seed.SEEDED_POLICY if policy_created else None,
        "calls": len(decided),
        "denials_by_gate": by_gate,
        "gates_exercised": sorted(by_gate),
        "suspended": suspended,
        "decisions": decided,
        # Empty on a healthy run. Non-empty means the platform disagreed with
        # what this scenario advertised, which is worth seeing rather than
        # hiding behind a success message.
        "surprises": surprises,
    }


@app.delete("/demo/seed")
def demo_seed_unload(principal: Principal = Depends(require_admin)):
    """Remove the demo scenario, and say plainly what cannot be removed.

    The agents are decommissioned — AGT's lifecycle transition, not a delete, so
    the record and its trail survive by design and the agent stops being able to
    call anything. The policy is deleted outright.

    What stays is the audit chain. The decisions those agents produced were real
    decisions, and the chain is append-only and hash-linked: selectively removing
    entries is precisely the tampering it exists to detect, and there is no
    honest way to offer it. `DELETE /audit` opens a *new* chain recording the
    replaced root, which is the only clean slate on offer; this endpoint reports
    how many entries it is leaving behind rather than implying it removed them.
    """
    before = _audit.count()
    removed, failed = [], []

    for agent_id in demo_seed.SEEDED_AGENT_IDS:
        if _resolve_agent(agent_id) is None:
            continue
        try:
            delete_agent(agent_id, principal)
            removed.append(agent_id)
        except HTTPException as exc:
            failed.append({"agent_id": agent_id, "detail": str(exc.detail)})

    # The imported MCP tools go with it: they were onboarded by the load, and
    # leaving them behind would keep a server registered that the scenario
    # brought in. The receipts their calls produced are signed and hash-chained,
    # so they stay for the same reason the audit entries do.
    mcp_removed = []
    try:
        if _tools.by_mcp_server(demo_seed.MCP_SERVER_NAME):
            removed_server = mcp_remove_server(demo_seed.MCP_SERVER_NAME, principal)
            mcp_removed = removed_server.get("removed", [])
    except HTTPException:
        pass

    policy_removed = None
    if _policies.exists(demo_seed.SEEDED_POLICY):
        try:
            delete_policy(demo_seed.SEEDED_POLICY, principal)
            policy_removed = demo_seed.SEEDED_POLICY
        except HTTPException as exc:
            failed.append({"policy": demo_seed.SEEDED_POLICY, "detail": str(exc.detail)})

    return {
        "loaded": False,
        "agents_decommissioned": removed,
        "policy_removed": policy_removed,
        "mcp_tools_removed": mcp_removed,
        "receipts_retained": _receipts.count(),
        "failed": failed,
        "audit_entries_retained": before,
        "note": (
            "The agents are decommissioned and the policy is gone. Their "
            "decisions stay in the audit chain: it is append-only and "
            "hash-linked, so removing entries is the tampering it exists to "
            "detect. Start a new chain from the Audit panel if you want those "
            "gone — it records the root of the chain it replaced."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD STATS  /stats
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/stats")
def dashboard_stats(principal: Principal = Depends(current_principal)):
    """The dashboard summary, scoped to the caller's tenant.

    /agents already filters its list by tenant; this endpoint returned the same
    list unfiltered, which made it a way around that filter. Every count below
    is now derived from what the caller may actually see, so the summary and the
    panels it summarises agree.

    Two fields stay platform-wide on purpose. ``chain_valid`` and
    ``merkle_root`` are integrity properties of the one chain every tenant
    writes into — a per-tenant root would not verify against anything, and
    neither discloses entry content. ``total_governed_tools`` counts a registry
    that has no tenant ownership in this platform: every tenant may call every
    onboarded tool, so the number is not another tenant's secret.
    """
    def visible(entry):
        return _audit_visible(entry, principal)
    # One pass for both counters, instead of materialising and reversing the
    # whole chain to count it.
    total, denials = _audit.tally(visible=visible)
    # The cached verdict, not a fresh walk: this endpoint is polled every few
    # seconds by every open browser, and verifying re-hashes every entry. The
    # answer carries the moment it was taken so it cannot be misread as "now";
    # /audit/verify is the fresh one.
    verification = _audit.verification()
    merkle_root = _audit.root_hash()
    views = [_agent_view(a) for a in _lifecycle.agents]
    if not principal.is_admin:
        views = [v for v in views
                 if _agent_tenant.get(v["name"], DEFAULT_TENANT) == principal.tenant]
    names = {v["name"] for v in views}
    by_state: dict = {}
    for v in views:
        by_state[v["state"]] = by_state.get(v["state"], 0) + 1
    return {
        "total_agents": len(views),
        "active_agents": sum(1 for v in views if v["state"] == "active"),
        "total_policies": sum(1 for p in _policies.names()
                              if _policy_visible(p, principal)),
        "total_governed_tools": len({k[0] for k in _governed_tools}),
        "audit_events": total,
        "denials": denials,
        "allow_rate": round((total - denials) / total * 100, 1) if total else 100.0,
        "chain_valid": verification["valid"],
        # When the verdict was taken, and over how many entries. A bare boolean
        # from a cache would be a claim about now that nobody had checked.
        "chain_verified_at": datetime.datetime.fromtimestamp(
            verification["checked_at"], datetime.timezone.utc).isoformat(),
        "chain_verified_entries": verification["entries"],
        "merkle_root": merkle_root,
        # agent_ids() rather than all(): counting SLOs does not need every
        # objective serialised into a document first.
        "slos": len(_slo.agent_ids() & names),
        # Same shape AGT's LifecycleManager.summary() returns, rebuilt over the
        # visible agents so the breakdown cannot be read for a count of someone
        # else's fleet.
        "lifecycle": {
            "total_agents": len(views),
            "by_state": by_state,
            "by_owner": {o: sum(1 for v in views if v["owner"] == o)
                         for o in {v["owner"] for v in views}},
        },
        "agents": views,
    }


# ═══════════════════════════════════════════════════════════════════════════
# SINGLE-CONTAINER STATIC HOSTING  (optional)
# ═══════════════════════════════════════════════════════════════════════════
def _mount_spa(target_app: FastAPI, static_dir: str) -> bool:
    """Serve a built frontend from the same origin as the API.

    Mounted (not an APIRoute), so it bypasses the auth dependency — the bundle
    holds no secrets and the user supplies a token at runtime. Registered after
    every API route, so it never shadows one; ``html=True`` serves index.html
    at ``/``. Returns whether a mount was actually added.
    """
    path = Path(static_dir)
    if not path.is_dir():
        return False
    from fastapi.staticfiles import StaticFiles
    target_app.mount("/", StaticFiles(directory=str(path), html=True), name="spa")
    return True


# When AGT_STATIC_DIR points at a built frontend (the container does this), the
# API and the dashboard are served from one origin. Unset in dev and tests, so
# behaviour there is unchanged.
if os.getenv("AGT_STATIC_DIR"):
    _mount_spa(app, os.environ["AGT_STATIC_DIR"])
