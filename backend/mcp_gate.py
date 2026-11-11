"""AGT-native trust gating for MCP tool dispatch.

This is the toolkit's own ``mcp_trust_proxy.TrustProxy``, wired in as the last
gate before a governed MCP call leaves the process.

It earns its place because of what the existing gates do *not* cover. The four
gates decide whether this agent may call this tool; the descriptor evaluation in
``mcp_connector`` decides whether the tool was safe to onboard. Neither looks at
the arguments actually being sent, and the descriptor grade is a point-in-time
snapshot that nothing enforces afterwards. TrustProxy closes exactly that gap:

  * ``tool_args`` is scanned for prompt-injection patterns on **every** call, so
    a tool that graded clean at import cannot be used to carry a poisoned
    payload later;
  * a per-tool rate limit bounds how fast one agent can drive one remote tool;
  * a per-tool trust floor is derived from the tool's *own* descriptor grade, so
    the static evaluation stops being a report and becomes the runtime policy;
  * a tool may require capabilities the calling agent has to hold;
  * an agent with no minted DID cannot dispatch at all.

Why not ``agentmesh.trust.bridge.ProtocolBridge`` / ``MCPAdapter``, the
protocol-bridge primitives from AGT's tutorial 16: their transport is a stub.
``ProtocolBridge._send()`` returns ``{"status": "sent"}`` without contacting
anything, and ``MCPAdapter.call_tool()`` returns a hardcoded
``{"result": "success", "governed": True}`` once its trust check passes — there
is no transport call in its body. Routing MCP calls through them would report
success for calls that never happened, which is the one thing this project
promises never to do. So the real transport stays in ``mcp_connector`` and the
real gating comes from ``TrustProxy``, which is complete, tested upstream, and
explicitly documented as middleware "in front of any MCP server".

TrustProxy is documented as not thread-safe. FastAPI runs the sync handlers in a
thread pool, so every call into it is taken under a lock here.
"""

from __future__ import annotations

import threading

from mcp_trust_proxy import ToolPolicy, TrustProxy

# The dashboard scores trust as a float in [0.0, 1.0]; every AGT bridge
# primitive scores it as an int in [0, 1000]. The conversion happens at this
# boundary only — the float stays canonical everywhere else in the app.
TRUST_SCALE = 1000

# The floor for an MCP tool whose own grade sets no higher bar. 300 mirrors
# MIN_TRUST (0.3), so this gate can never be laxer than the trust gate that
# already ran.
DEFAULT_MIN_TRUST = 300

# A tool's descriptor grade *is* its runtime policy. `critical` is refused
# outright rather than given a threshold: the findings that reach that tier are
# model-directed instructions, embedded credentials and hidden characters, none
# of which become acceptable at a higher trust score. A `min_trust` of 0 is
# TrustProxy's "no per-tool floor" — it falls back to DEFAULT_MIN_TRUST.
RISK_POLICY = {
    "critical": {"blocked": True,  "min_trust": 0,   "max_calls_per_minute": 0},
    "high":     {"blocked": False, "min_trust": 800, "max_calls_per_minute": 10},
    "medium":   {"blocked": False, "min_trust": 500, "max_calls_per_minute": 30},
    "low":      {"blocked": False, "min_trust": 0,   "max_calls_per_minute": 60},
}

# AuthResult carries a human-readable reason but no machine-readable code, so
# the rule id is recovered from the message. A wording change upstream degrades
# the id to `mcp_proxy:denied` rather than breaking the denial itself. Order
# matters: "is blocked by policy" has to be tried before "is blocked".
_RULE_FROM_REASON = (
    ("Injection pattern detected", "mcp_proxy:argument_injection"),
    ("Rate limit exceeded", "mcp_proxy:rate_limit"),
    ("Missing capabilities", "mcp_proxy:capability"),
    ("Trust score", "mcp_proxy:min_trust"),
    ("is blocked by policy", "mcp_proxy:tool_blocked"),
    ("Argument scanning failed", "mcp_proxy:scan_failed"),
    ("DID is required", "mcp_proxy:no_did"),
    ("is blocked", "mcp_proxy:agent_blocked"),
)


def rule_for(reason: str) -> str:
    """Map a TrustProxy denial reason onto a stable rule id."""
    for needle, rule in _RULE_FROM_REASON:
        if needle in reason:
            return rule
    return "mcp_proxy:denied"


class MCPGateDenied(Exception):
    """Raised inside the governed callable when the proxy refuses dispatch.

    Raised rather than returned because it has to abort from *inside* the
    function ``govern()`` is wrapping. AGT invokes the wrapped callable
    unwrapped, so the exception reaches ``/tools/call``, which turns it into the
    same denial shape every other gate produces.
    """

    def __init__(self, reason: str, rule: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.rule = rule


class MCPGate:
    """Thread-safe adapter over AGT's ``TrustProxy``, one per process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proxy = self._build()
        self._synced: dict[str, tuple] = {}

    @staticmethod
    def _build() -> TrustProxy:
        return TrustProxy(
            default_min_trust=DEFAULT_MIN_TRUST,
            require_did=True,
            scan_arguments=True,
        )

    @staticmethod
    def policy_for(spec: dict) -> ToolPolicy:
        """Derive one tool's runtime policy from its stored descriptor grade."""
        evaluation = spec.get("evaluation") or {}
        risk = evaluation.get("risk") or spec.get("risk") or "medium"
        shape = RISK_POLICY.get(risk, RISK_POLICY["medium"])
        return ToolPolicy(
            min_trust=shape["min_trust"],
            required_capabilities=list(spec.get("required_capabilities") or []),
            blocked=shape["blocked"],
            max_calls_per_minute=shape["max_calls_per_minute"],
            description=f"Derived from descriptor risk '{risk}'",
        )

    def _sync(self, tool_name: str, spec: dict) -> None:
        """Ensure the proxy holds the policy this tool's grade implies.

        Derived lazily from the registry rather than written once at import, so
        a restart, a re-import or an edited definition cannot leave the runtime
        policy pointing at a stale grade. TrustProxy keys its rate tracker
        separately from its policies, so re-setting one does not hand an agent a
        fresh budget.
        """
        policy = self.policy_for(spec)
        signature = (policy.min_trust, tuple(policy.required_capabilities),
                     policy.blocked, policy.max_calls_per_minute)
        if self._synced.get(tool_name) == signature:
            return
        self._proxy.set_tool_policy(tool_name, policy)
        self._synced[tool_name] = signature

    def enforce(self, *, tool_name: str, spec: dict, did: "str | None",
                trust_score: float, capabilities: "list[str] | None",
                arguments: "dict | None") -> None:
        """Authorize one MCP dispatch, or raise :class:`MCPGateDenied`."""
        score = int(round(max(0.0, min(1.0, float(trust_score))) * TRUST_SCALE))
        with self._lock:
            self._sync(tool_name, spec)
            result = self._proxy.authorize(
                agent_did=did or "",
                agent_trust_score=score,
                tool_name=tool_name,
                agent_capabilities=list(capabilities or []),
                # Falsy tool_args skips the scan inside TrustProxy; an empty
                # argument map has nothing to scan, so that is the right thing.
                tool_args=arguments or None,
            )
        if not result.allowed:
            raise MCPGateDenied(result.reason, rule_for(result.reason))

    def describe(self, tool_name: str, spec: dict) -> dict:
        """The runtime policy a tool would be dispatched under, for reporting."""
        policy = self.policy_for(spec)
        return {
            "tool": tool_name,
            "blocked": policy.blocked,
            "min_trust": (policy.min_trust or DEFAULT_MIN_TRUST) / TRUST_SCALE,
            "required_capabilities": list(policy.required_capabilities),
            "max_calls_per_minute": policy.max_calls_per_minute,
            "derived_from": policy.description,
        }

    def forget(self, tool_name: str) -> None:
        """Drop a removed tool's cached policy so a re-import re-derives it."""
        with self._lock:
            self._synced.pop(tool_name, None)

    def stats(self) -> dict:
        with self._lock:
            return self._proxy.get_stats()

    def clear(self) -> None:
        """Rebuild the proxy.

        Called by ``reset_state``: rate-limit budgets and the proxy's own audit
        log are process state, so without this one test's throttled agent would
        arrive throttled in the next.
        """
        with self._lock:
            self._proxy = self._build()
            self._synced.clear()
