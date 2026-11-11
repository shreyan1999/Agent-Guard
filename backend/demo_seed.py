"""The demo scenario: which agents, which policy, which calls.

Data only, no transport. Two things drive it and they must not drift apart:
`seed_demo.py` runs it over HTTP from a terminal, and `POST /demo/seed` runs it
in-process so the dashboard can offer a button. Keeping the scenario here means
both produce the same fleet, the same policy and the same gate coverage.

Nothing in this file decides anything. Every row below is an *input* to the real
API; the verdicts come from the gates.
"""

from __future__ import annotations

#: Agents this scenario owns. Removing the demo data removes exactly these.
SEEDED_AGENT_IDS = ("billing-agent", "support-agent", "etl-agent",
                    "scraper-agent", "intern-agent")

#: The policy this scenario creates. `default-policy` is the platform's and is
#: never touched.
SEEDED_POLICY = "finance-policy"

# -- the fleet ----------------------------------------------------------------
# Trust scores are chosen to straddle the two thresholds that actually decide
# something: MIN_TRUST (0.3) below which the trust gate refuses, and the ring
# boundary (0.6) below which AGT drops the agent into RING_3_SANDBOX and takes
# away network, filesystem and subprocess.
SEED_AGENTS = [
    # (id, trust, owner, purpose)
    ("billing-agent",   0.88, "finance@acme.test",  "Reconciles invoices"),
    ("support-agent",   0.72, "support@acme.test",  "Answers customer tickets"),
    ("etl-agent",       0.64, "data@acme.test",     "Moves records between stores"),
    ("scraper-agent",   0.45, "research@acme.test", "Collects public pages"),
    ("intern-agent",    0.22, "labs@acme.test",     "Unproven, sandboxed"),
]

# A child policy, so the Policy panel has an `extends` chain to render and the
# resolved view has something to resolve.
CHILD_POLICY = {
    "name": "finance-policy",
    "description": "Adds a finance-specific rule on top of the baseline.",
    "default_action": "allow",
    "extends": ["default-policy"],
    "rules": [
        {"name": "no-bulk-export", "condition": "action.type == 'export'",
         "action": "deny", "priority": 15,
         "description": "Bulk export of finance records is refused."},
    ],
}

# -- the traffic --------------------------------------------------------------
# `expect` is what this script believes each call should do. It is checked
# against what the platform actually decided, and any disagreement is reported
# rather than swallowed -- a seeder that quietly mislabels its own data would
# make the dashboard it fills in untrustworthy.
#
# (agent, tool, action, input_text, policy, expect, why)
SEED_CALLS = [
    # Allowed work -- the ordinary case, and the majority, so the allow rate is
    # not an artificially grim number.
    ("billing-agent", "db_query",   "read", "SELECT * FROM invoices WHERE paid = 0",
     "finance-policy", "allow", "ordinary read by a trusted agent"),
    ("billing-agent", "db_query",   "read", "SELECT total FROM invoices",
     "finance-policy", "allow", "ordinary read"),
    ("support-agent", "db_query",   "read", "SELECT * FROM tickets",
     "default-policy", "allow", "ordinary read"),
    ("support-agent", "send_email", "read", "Draft reply to ticket 4821",
     "default-policy", "allow", "reading, not sending"),
    ("etl-agent",     "db_query",   "read", "SELECT id FROM staging",
     "default-policy", "allow", "ordinary read"),
    ("billing-agent", "web_search", "read", "invoice reconciliation guidance",
     "finance-policy", "allow", "search by a ring-2 agent"),

    # Policy gate -- the baseline's own rules.
    ("etl-agent",     "db_query",   "drop", "DROP TABLE staging",
     "default-policy", "deny", "block-destructive"),
    ("support-agent", "db_query",   "delete", "DELETE FROM tickets",
     "default-policy", "deny", "block-destructive"),
    ("billing-agent", "db_query",   "export", "export every invoice",
     "finance-policy", "deny", "the child policy's own rule"),
    ("support-agent", "db_query",   "read", "customer SSN 123-45-6789 on file",
     "default-policy", "deny", "block-pii, via the CredentialRedactor facet"),

    # Ring gate -- a sandboxed agent reaching for a capability its ring forbids.
    ("scraper-agent", "web_search", "web_search", "",
     "default-policy", "deny", "ring 3 has no network"),
    ("scraper-agent", "db_query",   "shell_exec", "",
     "default-policy", "deny", "ring 3 has no subprocess"),

    # Trust gate -- below MIN_TRUST, refused before policy even runs.
    ("intern-agent",  "db_query",   "read", "SELECT 1",
     "default-policy", "deny", "trust 0.22 is under the 0.3 floor"),

    # Lifecycle gate -- an agent nobody registered.
    ("ghost-agent",   "db_query",   "read", "SELECT 1",
     "default-policy", "deny", "unregistered callers are untrusted"),
]

# Out-of-band telemetry, the counterpart to inline governance: an agent that
# already ran something and is reporting it. The backend tags these
# `agent-reported` in the audit note, so they cannot be mistaken for verdicts.
SEED_TELEMETRY = [
    ("billing-agent", [
        {"tool": "db_query", "action": "read", "allowed": True, "latency_ms": 38.0},
        {"tool": "db_query", "action": "read", "allowed": True, "latency_ms": 41.5},
        {"tool": "db_query", "action": "read", "allowed": True, "latency_ms": 55.2},
    ]),
    ("support-agent", [
        {"tool": "send_email", "action": "send_email", "allowed": True, "latency_ms": 120.0},
        {"tool": "send_email", "action": "send_email", "allowed": False,
         "latency_ms": 95.0, "policy_denied": True, "error": "recipient not allowed"},
    ]),
]

# -- the Tool Playground's own agents ------------------------------------------
# In memory-only mode the platform seeds these at startup. Under AGT_STATE_DIR
# it deliberately does not -- "a durable deployment starts empty and is
# populated by real registrations" -- which leaves the Tool Playground's preset
# buttons pointing at agents that do not exist. The seed registers them when
# they are missing so those presets keep producing the verdicts their labels
# advertise, and skips them when the platform already did.
PLAYGROUND_AGENTS = [
    ("research-agent", 0.92, "demo@localhost", "Seeded demo agent"),
    ("data-agent", 0.75, "demo@localhost", "Seeded demo agent"),
    ("email-agent", 0.55, "demo@localhost", "Seeded demo agent"),
    ("untrusted-agent", 0.18, "demo@localhost", "Seeded demo agent"),
]

# -- the MCP half --------------------------------------------------------------
# `demo_mcp_server.py` ships in this directory and advertises four tools graded
# one per risk tier, which is what makes the fifth gate demonstrable: AGT's
# trust proxy refuses a `critical` descriptor outright and holds the others to a
# trust floor derived from their grade.
#
# Optional by design. A button cannot conjure a server on another port, so if
# nothing is listening the seed skips this half and says why rather than
# failing. Importing from loopback also needs AGT_TOOL_ALLOW_PRIVATE, because
# the SSRF guard refuses private addresses by default -- that refusal is a
# feature, and the skip message names it.
MCP_SERVER_URL = "http://127.0.0.1:8931/mcp"
MCP_SERVER_NAME = "demo-notes"

#: (agent, tool, arguments, expect, why)
MCP_CALLS = [
    ("billing-agent", "mcp.demo-notes.echo", {"text": "hello from the demo seed"},
     "allow", "low-grade descriptor, trust well above its floor"),
    ("support-agent", "mcp.demo-notes.lookup_order", {"order_id": "A-1042"},
     "allow", "medium grade, trust 0.72 clears the 0.5 floor"),
    ("support-agent", "mcp.demo-notes.purge_bucket", {"bucket": "tmp"},
     "deny", "high grade lifts the floor to 0.8; this agent is 0.72"),
    ("billing-agent", "mcp.demo-notes.search_notes", {"query": "quarterly"},
     "deny", "critical descriptor -- refused at dispatch whatever the trust"),
]
