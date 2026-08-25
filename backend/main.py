"""
AGT Dashboard Backend — FastAPI + real agent-governance-toolkit
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

import os, re, time, yaml, datetime
from pathlib import Path
import threading
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
from foundry_connector import run_steps_to_events
from auth import AuthProvider, Principal, ANONYMOUS, DEFAULT_TENANT


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


def _lint_condition(condition: str) -> list[str]:
    """Return the atoms of *condition* that AGT's grammar cannot parse."""
    atoms, unparsable = [condition], []
    for sep in (" or ", " and "):
        atoms = [piece for atom in atoms for piece in atom.split(sep)]
    for atom in atoms:
        atom = atom.strip()
        if atom and not any(p.match(atom) for p in _ATOM_PATTERNS):
            unparsable.append(atom)
    return unparsable


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
    verify_integrity(), get_proof(), export(). The single exception is
    root_hash(): AuditLog exposes no public accessor for the Merkle root
    short of export(), which serialises every entry. That one reach into
    AGT internals is isolated here, so an AGT upgrade touches one method
    rather than eight call sites.

    The lock matters because handlers are sync defs, so FastAPI runs them
    in a thread pool, and add_entry() links hashes and rebuilds the tree.
    """

    _UNBOUNDED = 10 ** 9

    def __init__(self) -> None:
        self._log = _build_audit_log()
        self._lock = threading.Lock()

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
                limit: int = 50) -> "list[AuditEntry]":
        """Newest-first entries. The AGT query() returns oldest-first."""
        with self._lock:
            found = self._log.query(agent_did=agent_id, event_type=event_type,
                                    limit=self._UNBOUNDED)
        return list(reversed(found))[:limit]

    def count(self) -> int:
        with self._lock:
            return len(self._log.query(limit=self._UNBOUNDED))

    def root_hash(self) -> Optional[str]:
        # AGT API gap: no public Merkle-root accessor on AuditLog.
        with self._lock:
            return self._log._chain.get_root_hash()

    def verify(self):
        with self._lock:
            return self._log.verify_integrity()

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
            previous_count = len(self._log.query(limit=self._UNBOUNDED))
            self._log = _build_audit_log()
        return previous_root, previous_count


_audit = AuditStore()


def _emit_audit(event_type: str, agent_id: str, details: dict, allowed: bool = True):
    _audit.log(event_type, agent_id, details, allowed)


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


_lifecycle = LifecycleManager(
    policy=LifecyclePolicy(require_approval=False, require_owner=True),
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
_trust_scores: dict[str, float] = {}         # agent name -> score
_slo = SLOStore()                            # real agent_sre SLOs, per agent


# ── Durable state ─────────────────────────────────────────────────────────────
# Set AGT_STATE_DIR to persist agents across restarts: AGT's LifecycleManager
# owns the agent records (agents.json), a MetaStore holds the non-secret
# trust/tenant/policy sidecar (agent_meta.json), and IdentityStore persists the
# public DIDs (identities.json). Unset — the shipped default — keeps everything
# in memory, exactly as before. Private keys are never written; a persisted
# agent keeps a stable DID but the caller retains its once-issued private key.
_identity = IdentityStore(storage_path=_state_file("identities.json"))
_meta = MetaStore(_state_file("agent_meta.json"))
_governed_tools: dict[tuple, Any] = {}       # (tool, policy, agent, ring) -> GovernedCallable
_agent_tenant: dict[str, str] = {}           # agent name -> owning tenant
_agent_foundry: dict[str, dict] = {}         # agent name -> Foundry onboarding metadata


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
    """
    return ExecutionRing.from_eff_score(trust_score)


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
        return {"tool": tool_name, "action": action, "result": f"Executed {action} on {tool_name}"}

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
        _lifecycle.activate(managed.agent_id, actor="system")
        _agent_ids[name] = managed.agent_id
        _agent_policies[name] = "default-policy"
        _trust_scores[name] = trust
        _agent_tenant[name] = DEFAULT_TENANT
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

    persisted = list(_lifecycle.agents)
    if persisted:
        _rehydrate_state(persisted)
    elif not _meta.durable:
        # Demo agents are a playground convenience for the ephemeral in-memory
        # mode. A durable deployment (AGT_STATE_DIR set) starts empty and is
        # populated by real registrations, not fixtures.
        _seed_demo_agents()

    for agent_id in list(_agent_ids.keys())[:2]:
        _slo.ensure(agent_id)

    for tool in DEMO_TOOLS:
        try:
            _register_tool(tool, "default-policy")
        except Exception:
            pass


def teardown_state(clear_policies: bool = False) -> None:
    """Drop in-memory state and rebuild the stores from the environment.

    Policies are deliberately left on disk: they persist across restarts,
    which is the point of the file-backed store. Only the test suite asks
    for them to be cleared, so each test starts from the default policy.

    The durable stores are reconstructed from AGT_STATE_DIR here, so this
    doubles as a restart: any persisted agents/identities are reloaded.
    """
    global _lifecycle, _audit, _identity, _meta
    if clear_policies:
        for name in _policies.names():
            _policies.path(name).unlink(missing_ok=True)
    for store in (_agent_policies, _trust_scores,
                  _slo, _identity, _governed_tools, _agent_ids, _call_stats,
                  _agent_tenant, _agent_foundry):
        store.clear()
    # AGT keeps breach detectors in its own module globals, so clearing our
    # stores is not enough to give a test a clean process.
    _reset_shared_breach_detectors()
    _lifecycle = LifecycleManager(
        policy=LifecyclePolicy(require_approval=False, require_owner=True),
        storage_path=_state_file("agents.json"),
    )
    _identity = IdentityStore(storage_path=_state_file("identities.json"))
    _meta = MetaStore(_state_file("agent_meta.json"))
    _audit = AuditStore()


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


app = FastAPI(title="AGT Playground API", lifespan=lifespan,
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

class EvaluateIn(BaseModel):
    policy_name: str = "default-policy"
    agent_id: str = "*"
    # Supply call arguments and the context is built exactly as /tools/call
    # builds it. Supply a raw context instead to debug rules directly.
    action: Optional[str] = None
    input_text: str = ""
    kwargs: dict[str, Any] = {}
    context: Optional[dict[str, Any]] = None

class AttestationIn(BaseModel):
    nonce: str
    signature: str

class ToolCallIn(BaseModel):
    tool_name: str
    policy_name: str = "default-policy"
    action: str = "read"
    input_text: str = ""
    agent_id: str = "research-agent"
    kwargs: dict[str, Any] = {}
    # When present, the caller proves possession of the agent's private key.
    # When absent, the agent_id is self-asserted (legacy) and flagged as such.
    attestation: Optional[AttestationIn] = None

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
        "warnings": _policy_warnings(doc),
        "dependents": _policies.dependents(name),
    }


def _policy_warnings(doc: dict) -> list[dict]:
    """Every way a rule in this document can silently fail to fire.

    Three classes, all of which AGT accepts without complaint:
      1. a condition its grammar cannot parse;
      2. a stage other than pre_tool, which govern() never evaluates;
      3. a rule disabled outright.
    Inheritance drops are reported separately by /policies/{name}/resolved,
    because detecting them needs the merged policy.
    """
    out = list(_lint_rules(doc.get("rules", [])))
    for rule in doc.get("rules", []):
        if rule.get("stage", "pre_tool") != "pre_tool":
            out.append({
                "rule": rule.get("name", "?"),
                "condition": rule.get("condition", ""),
                "unparsable": [],
                "effect": (
                    f"Stage is {rule.get('stage')!r}, but govern() evaluates at "
                    "'pre_tool' — this rule never fires in this dashboard."
                ),
            })
        if rule.get("enabled", True) is False:
            out.append({
                "rule": rule.get("name", "?"),
                "condition": rule.get("condition", ""),
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


def _save_policy(name: str, body, *, creating: bool):
    """Validate, then persist. Nothing is written unless AGT can parse it."""
    doc = _policy_doc(body, name)

    dead = _lint_rules(doc["rules"])
    if dead:
        _reject("Policy contains conditions AGT cannot evaluate", dead)

    try:
        _policies.validate(name, doc)
    except PolicyError as e:
        _reject(e)

    _policies.write(name, doc)
    # Cached callables carry the old rules and strategy.
    for key in [k for k in _governed_tools if k[1] == name]:
        _governed_tools.pop(key, None)
    _emit_audit("policy.created" if creating else "policy.updated", "system", {
        "policy": name, "rules": len(doc["rules"]), "extends": doc["extends"],
    })
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
        "fields": [
            {"path": "action.type", "type": "string",
             "help": "The action passed to the governed tool."},
            {"path": "agent.id", "type": "string", "help": "Readable agent name."},
            {"path": "agent.agent_id", "type": "string", "help": "AGT lifecycle id."},
            {"path": "agent.state", "type": "string",
             "help": "AGT lifecycle state, e.g. active."},
            {"path": "agent.ring", "type": "number",
             "help": "Execution ring, derived from trust."},
            {"path": "agent.trust_score", "type": "number", "help": "0.0 to 1.0."},
            {"path": "input_text.has_pii", "type": "boolean",
             "help": "Set by AGT CredentialRedactor via FacetRegistry."},
            {"path": "input_text.has_credentials", "type": "boolean",
             "help": "Set by AGT CredentialRedactor via FacetRegistry."},
            {"path": "sql.verb", "type": "string",
             "help": "AGT protocol facet, when the context carries sql."},
            {"path": "sql.target", "type": "string", "help": "AGT protocol facet."},
        ],
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
def list_policies():
    return [_policy_view(n) for n in _policies.names()]


@app.post("/policies")
def create_policy(body: PolicyIn, principal: Principal = Depends(require_operator)):
    try:
        if _policies.exists(body.name):
            raise HTTPException(400, f"Policy '{body.name}' already exists")
        return _save_policy(body.name, body, creating=True)
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
def get_policy(name: str):
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
        return _save_policy(name, body, creating=False)
    except PolicyError as e:
        _reject(e)


@app.get("/policies/{name}/yaml")
def get_policy_yaml(name: str):
    """The policy exactly as it sits on disk, for the read-only YAML pane."""
    if not _safe_exists(name):
        raise HTTPException(404, "Policy not found")
    return {"name": name, "yaml": _policies.yaml_text(name)}


def _safe_exists(name: str) -> bool:
    """exists() that treats an invalid name as simply absent."""
    try:
        return _policies.exists(name)
    except PolicyError:
        return False


@app.get("/policies/{name}/resolved")
def get_policy_resolved(name: str):
    """The merged policy AGT enforces, with each rule's origin.

    Differs from the authored document whenever `extends` is used: inherited
    rules appear here, and child rules AGT dropped are listed separately.
    """
    if not _safe_exists(name):
        raise HTTPException(404, "Policy not found")
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
    try:
        _policies.delete(name)
    except PolicyError as e:
        raise HTTPException(409, str(e))
    for key in [k for k in _governed_tools if k[1] == name]:
        _governed_tools.pop(key, None)
    _emit_audit("policy.deleted", "system", {"policy": name})
    return {"status": "deleted"}


@app.post("/policies/evaluate")
def evaluate_policy(body: EvaluateIn):
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
    return {
        "tools": sorted({k[0] for k in _governed_tools}),
        "available": ["db_query", "send_email", "web_search", "write_file",
                      "delete_file", "shell_exec", "drop_table"],
    }


def _deny(agent_name: str, tool: str, action: str, policy: str,
          event: str, reason: str, gate: str, start: float, rule: str = "",
          slo_agent: "str | None" = None):
    """Record a denial and shape the response."""
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    _emit_audit(event, agent_name, {
        "tool": tool, "action": action, "policy": policy,
        "reason": reason, "rule": rule,
    }, allowed=False)
    _bump(agent_name, "denials")
    # Feed the real SLO when the agent exists (skip unregistered callers).
    if slo_agent is not None:
        _slo.record_call(slo_agent, allowed=False,
                         policy_denied=gate in ("policy", "ring"),
                         latency_ms=latency_ms)
    return {
        "allowed": False, "reason": reason, "denied_by": gate,
        "rule": rule or None,
        "latency_ms": latency_ms, "policy": policy,
    }


@app.post("/tools/call")
def call_tool(body: ToolCallIn, principal: Principal = Depends(require_operator)):
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

    # ── Gate 1: lifecycle state (AGT LifecycleManager) ─────────────────
    agent = _resolve_agent(body.agent_id)
    if agent is None:
        return _deny(body.agent_id, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.unregistered",
                     f"Agent '{body.agent_id}' is not registered — unknown agents are untrusted",
                     "lifecycle", start, rule="lifecycle:unregistered")

    if agent.state != AgentLifecycleState.ACTIVE:
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.lifecycle",
                     f"Agent '{agent.name}' is {agent.state.value}, not active",
                     "lifecycle", start, rule=f"lifecycle:{agent.state.value}",
                     slo_agent=agent.name)

    _authorize_agent(agent, principal)

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
                         slo_agent=agent.name)

    # ── Gate 2: trust (AGT TrustPolicy / PolicyEvaluator) ──────────────
    trust_score = _trust_scores.get(agent.name, 0.0)
    trust_decision, _ = _evaluate_trust(agent.name, trust_score)
    if not trust_decision.allowed:
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     "tool.call.denied.trust",
                     f"Trust {trust_score} below minimum {MIN_TRUST}",
                     "trust", start, rule=trust_decision.rule_name or "deny-low-trust",
                     slo_agent=agent.name)

    # ── Gates 3 and 4: ring enforcement then policy, both inside govern() ──
    ring = _ring_for(trust_score)
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
            **body.kwargs,
        )
    except Exception as e:
        raise HTTPException(500, str(e))

    latency_ms = round((time.perf_counter() - start) * 1000, 2)

    if isinstance(outcome, Denied):
        d = outcome.decision
        # AGT labels ring denials with these rule names; everything else is policy.
        gate = "ring" if d.matched_rule in ("ring_enforcement", "ring_breaker") else "policy"
        return _deny(agent.name, body.tool_name, body.action, body.policy_name,
                     f"tool.call.denied.{gate}", d.reason or "Denied",
                     gate, start, rule=d.matched_rule or "", slo_agent=agent.name)

    _emit_audit("tool.call.allowed", agent.name, {
        "tool": body.tool_name, "action": body.action,
        "policy": body.policy_name, "ring": ring.name, "latency_ms": latency_ms,
        "did": _identity.did(agent.name), "identity_verified": identity_verified,
    }, allowed=True)
    _bump(agent.name, "calls")
    _slo.record_call(agent.name, allowed=True, policy_denied=False,
                     latency_ms=latency_ms)
    return {
        "allowed": True, "result": outcome,
        "passed_gates": ["lifecycle", "trust", "ring", "policy"],
        "trust_score": trust_score, "ring": ring.name,
        "did": _identity.did(agent.name), "identity_verified": identity_verified,
        "latency_ms": latency_ms, "policy": body.policy_name,
    }


# ═══════════════════════════════════════════════════════════════════════════
# TRUST ENGINE  /trust
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/trust")
def trust_overview():
    return {
        "agents": [
            {"agent_id": k, "trust_score": v,
             "level": "high" if v >= 0.8 else "medium" if v >= 0.5 else "low"}
            for k, v in _trust_scores.items()
        ]
    }


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
def get_audit(limit: int = 50, agent_id: Optional[str] = None, event_type: Optional[str] = None):
    entries = _audit.entries(agent_id=agent_id, event_type=event_type, limit=limit)
    return {
        "events": [_serialise_entry(e) for e in entries],
        "total": _audit.count(),
        "merkle_root": _audit.root_hash(),
    }


@app.get("/audit/verify")
def verify_audit():
    """Recompute every entry hash and re-walk the chain links."""
    valid, error = _audit.verify()
    root, count = _audit.root_hash(), _audit.count()
    return {
        "valid": valid,
        "error": error,
        "merkle_root": root,
        "entry_count": count,
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


@app.get("/audit/proof/{entry_id}")
def audit_proof(entry_id: str):
    """Merkle inclusion proof for a single entry."""
    proof = _audit.proof(entry_id)
    if proof is None:
        raise HTTPException(404, "Entry not found")
    return proof


@app.get("/audit/export")
def export_audit():
    """Full chain export with its Merkle root, for offline verification."""
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


@app.get("/agents/{agent_id}/lifecycle")
def agent_lifecycle(agent_id: str):
    """The AGT lifecycle audit trail for one agent.

    LifecycleManager records every state change with its actor and reason.
    This is separate from the governance audit chain: it tracks who changed
    the agent, not what the agent did.
    """
    agent = _resolve_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
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
        _lifecycle.activate(managed.agent_id, actor="dashboard")
    except LifecycleError as e:
        raise HTTPException(400, str(e))

    _agent_ids[body.id] = managed.agent_id
    _agent_policies[body.id] = body.policy
    _trust_scores[body.id] = body.trust_score
    _agent_tenant[body.id] = principal.tenant
    if body.project_endpoint or body.foundry_agent_id:
        _agent_foundry[body.id] = {
            "project_endpoint": body.project_endpoint,
            "foundry_agent_id": body.foundry_agent_id,
        }
    issued = _identity.mint(body.id, sponsor=body.owner,
                            capabilities=[body.purpose] if body.purpose else None)
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
    _agent_ids.pop(agent.name, None)
    _trust_scores.pop(agent.name, None)
    _agent_policies.pop(agent.name, None)
    _agent_tenant.pop(agent.name, None)
    _agent_foundry.pop(agent.name, None)
    _identity.remove(agent.name)
    _persist_meta()
    _emit_audit("agent.decommissioned", agent.name, {"agent_id": agent.agent_id})
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

@app.get("/sre/slos")
def list_slos():
    """Real agent_sre SLOs. Empty of measurements until calls are made."""
    return _slo.all()


@app.post("/sre/slos")
def create_slo(body: SLOIn, principal: Principal = Depends(require_operator)):
    """Create or replace an agent's SLO with a real agent_sre objective."""
    view = _slo.set_target(body.agent_id, body.target)
    _emit_audit("sre.slo.created", body.agent_id, {"slo": body.slo_name, "target": body.target})
    return view


@app.post("/sre/signal/{agent_id}")
def record_signal(agent_id: str, success: bool = True,
                  principal: Principal = Depends(require_operator)):
    """Record a real success/failure signal into the agent's SLO."""
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
    _emit_audit("sre.kill_switch", agent.name, {"state": managed.state.value}, allowed=False)
    return {"status": managed.state.value, "agent_id": agent.name}


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


@app.get("/compliance/owasp")
def owasp_coverage():
    """Reference map of AGT capabilities to OWASP Agentic AI risks.

    `status` is the honest enforcement state of each control *in this
    platform*: `enforced` (a gate actively blocks), `partial` (a control
    exists but is advisory or incomplete), or `not_implemented`. This is a
    reference mapping, not a certified security assessment.
    """
    return {
        "framework": "OWASP Agentic AI Top 10 (2026)",
        "note": (
            "Reference mapping of AGT capabilities to OWASP Agentic AI risks, "
            "annotated with the enforcement status of each control in this "
            "platform. Not a certified assessment."
        ),
        "coverage": [
            {"id": "ASI-01", "name": "Agent Goal Hijack", "status": "partial",
             "control": "PromptDefenseEvaluator (system-prompt hardening, advisory)"},
            {"id": "ASI-02", "name": "Tool Misuse & Exploitation", "status": "enforced",
             "control": "govern() + PolicyEngine (fail-closed at pre_tool)"},
            {"id": "ASI-03", "name": "Identity & Privilege Abuse", "status": "partial",
             "control": "TrustPolicy + lifecycle gates; agent_id not yet attested"},
            {"id": "ASI-04", "name": "Unsafe Code Execution", "status": "enforced",
             "control": "ExecutionRing resource constraints via govern(ring=...)"},
            {"id": "ASI-05", "name": "Uncontrolled Side-Effects", "status": "enforced",
             "control": "govern() + MerkleAuditChain evidence"},
            {"id": "ASI-06", "name": "Data Exfiltration", "status": "partial",
             "control": "CredentialRedactor PII/credential facet in policy context"},
            {"id": "ASI-07", "name": "Prompt Injection", "status": "partial",
             "control": "PromptDefenseEvaluator (advisory grade, not blocking)"},
            {"id": "ASI-08", "name": "Insecure Plugin Use", "status": "not_implemented",
             "control": "No marketplace/plugin trust scoring in this platform"},
            {"id": "ASI-09", "name": "Excessive Autonomy", "status": "partial",
             "control": "Lifecycle state machine + require_approval option"},
            {"id": "ASI-10", "name": "Audit Tampering", "status": "enforced",
             "control": "MerkleAuditChain hash-linked, verifiable"},
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD STATS  /stats
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/stats")
def dashboard_stats():
    entries = _audit.entries(limit=AuditStore._UNBOUNDED)
    chain_valid, _ = _audit.verify()
    merkle_root = _audit.root_hash()
    total = len(entries)
    denials = sum(1 for e in entries if e.outcome == "denied")
    views = [_agent_view(a) for a in _lifecycle.agents]
    return {
        "total_agents": len(views),
        "active_agents": sum(1 for v in views if v["state"] == "active"),
        "total_policies": len(_policies.names()),
        "total_governed_tools": len({k[0] for k in _governed_tools}),
        "audit_events": total,
        "denials": denials,
        "allow_rate": round((total - denials) / total * 100, 1) if total else 100.0,
        "chain_valid": chain_valid,
        "merkle_root": merkle_root,
        "slos": len(_slo.all()),
        "lifecycle": _lifecycle.summary(),
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
