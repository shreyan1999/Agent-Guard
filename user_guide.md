# AgentGuard — User Guide (SOP)

A standard operating procedure for using AgentGuard. It
describes only what the platform actually does. Where a feature is a
demonstration, a reference, or observational rather than enforcing, this guide
says so plainly.

> **Read this first.** This is a **learning playground for the Microsoft Agent
> Governance Toolkit (AGT)**, not a production governance product. Several
> panels run real AGT enforcement; others are reference material or
> demonstrations. Do not use this tool, or its output, to make compliance or
> security claims about your own systems. The [README](README.md) "What's real,
> and what isn't" table is the authoritative source of truth for each feature.

---

## 1. Scope — what this platform is and is not

| It **is** | It **is not** |
|---|---|
| A UI + API for writing AGT policies and firing governed tool calls at them | A hosted, production-ready governance control plane |
| A real integration of AGT's `PolicyEngine`, `TrustPolicy`, `LifecycleManager`, `agent_sre` SLOs and Merkle audit chain | An automated assessment of *your* codebase's security posture |
| A way to **monitor** an external agent (including Microsoft Foundry) via reported telemetry | An inline enforcement proxy that sits in front of an external agent |
| A single-container app you run locally or on Azure Container Apps | A multi-tenant SaaS with managed secrets and SSO |

**Feature honesty at a glance:**

- **Real AGT enforcement:** Tool Playground, Policy Engine, Trust & Identity, Agents (lifecycle), Agent SRE (SLOs), Audit Log, Prompt scan.
- **Live self-assessment (not a certified audit):** the Compliance panel's OWASP Agentic AI mapping now reports the controls actually enabled on the running instance.
- **Observational (monitoring, not enforcement):** telemetry ingestion and Microsoft Foundry onboarding.

---

## 2. Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.11+ | Backend (`agent-governance-toolkit[full]`) |
| Node.js | 18+ | Frontend build / dev server |
| npm | 9+ | Frontend dependencies |
| Docker | any recent | Optional — single-container run |
| Azure Developer CLI (`azd`) | latest | Optional — deploy to Azure Container Apps |

---

## 3. Starting the platform

### 3.1 One command

- **Windows:** run `start.bat`
- **macOS / Linux:** `chmod +x start.sh && ./start.sh`

Both set up the Python virtual environment, install dependencies, start the API
on `127.0.0.1:8000`, and start the React UI on `localhost:3000`.

### 3.2 Manual (two terminals)

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows;  source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install
npm start
```

### 3.3 Verify it is running

| Check | Expected |
|---|---|
| Open `http://localhost:3000` | Dashboard loads; sidebar shows a green "API online" dot |
| `curl http://localhost:8000/health` | `{"status":"ok","version":"1.0.0","agents":4,"policies":1}` |
| Open `http://localhost:8000/docs` | Swagger UI listing every endpoint |

The four agents and one policy shown by default are **in-memory demo data**.
They disappear on restart unless you enable persistence (Section 4.2).

---

## 4. Configuration (optional)

All configuration is via environment variables set **before** starting the
backend. With none set, the platform runs open and in-memory — convenient for a
local playground, not appropriate for shared use.

### 4.1 Access control (off by default)

Without configuration, every caller is treated as an anonymous local **admin**
and no token is required. To require authentication:

```bash
# token:subject:tenant:roles  (comma- or newline-separated)
set AGT_API_KEYS=s3cret:ana:acme:admin,readonly:bob:acme:viewer
```

- Roles form a hierarchy: `viewer` < `operator` < `admin`.
- Mutating endpoints require `operator`; destructive ones require `admin`.
- Agents are scoped to the tenant that registered them; an admin sees all.
- **Policies are scoped to the tenant that created them.** A policy authored by
  one tenant is invisible to another and cannot govern its agents; the seeded
  `default-policy` has no owner and stays shared. Admins see every tenant's
  policies. (In the single-tenant default, everything lives in one tenant, so
  this is transparent.)
- In the UI, store the token in the browser: `localStorage.setItem('agt_api_token', '<token>')`.

Alternative: point `AGT_API_KEYS_FILE` at a JSON file instead of an inline list.

**Static JWT bearer tokens (optional).** Set `AGT_JWT_SECRET` and the platform
also accepts HS256 JSON Web Tokens signed with that shared secret; the principal
is read from the token's `sub`, `tenant` and `roles` claims, with `exp`/`nbf`
and optional `AGT_JWT_ISSUER` / `AGT_JWT_AUDIENCE` enforced. This is a
deliberately **static** verifier — one symmetric secret, algorithm pinned to
HS256. It does **not** do OIDC discovery, JWKS, asymmetric keys or key
rotation; those need an external identity provider.

### 4.2 Persistence (off by default)

```bash
set AGT_STATE_DIR=C:\path\to\state
```

When set, **agents, trust scores, tenant assignments, public DIDs, Foundry
links, policy ownership and agent_sre SLO measurements survive a restart**. Two
honest caveats:

- **Private keys are never written.** The private key of an agent's identity is
  issued once at registration; store it yourself.
- **SLO measurements persist** to a durable per-agent SQLite database (agent_sre's
  own `SQLiteMeasurementStore`) under `AGT_STATE_DIR/slo/`. The recorded SLIs,
  their computed compliance and the error-budget burn are reloaded on restart.
  With `AGT_STATE_DIR` unset the SLO stores are in-memory and reset with the
  process.
- **Decision traces are captured only when this is set** (under
  `AGT_STATE_DIR/traces/`). With it unset the Audit Log panel says tracing is
  off rather than showing an empty list, because AGT's default trace directory
  would write into whatever directory the server was started from.
- With `AGT_STATE_DIR` set, the app **starts empty** — no demo agents are
  seeded. Real registrations populate it.

### 4.3 Durable audit (off by default)

```bash
set AGT_AUDIT_FILE=C:\path\to\audit.log
set AGT_AUDIT_KEY=<hmac-key>
```

Persists the tamper-evident audit chain across restarts.

### 4.4 Other

| Variable | Purpose | Default |
|---|---|---|
| `AGT_REQUIRE_ATTESTATION` | When set (`1`/`true`), every `/tools/call` must carry a signed attestation that verifies against the agent's key, or it is denied | unset (optional) |
| `AGT_JWT_SECRET` | Accept static HS256 JWT bearer tokens signed with this secret | unset |
| `AGT_JWT_ISSUER` / `AGT_JWT_AUDIENCE` | Optional `iss` / `aud` claims enforced on JWTs | unset |
| `AGT_TOOL_ALLOW_PRIVATE` | Allow onboarded tool endpoints that resolve to private/loopback hosts (for local webhook testing). Off = SSRF-safe: private, loopback and cloud-metadata targets are refused | unset (blocked) |
| `AGT_HOST` | Bind address passed to uvicorn by `start.bat` / `start.sh` | `127.0.0.1` |
| `AGT_CORS_ORIGINS` | Comma-separated allowlist | `http://localhost:3000,http://127.0.0.1:3000` |

---

## 5. The panels

| Panel | What it does | Backing |
|---|---|---|
| **Overview** | Live counts (agents, policies, calls) and health | Real |
| **Policy Engine** | Author, edit, lint, validate, inherit, evaluate and dry-run policies; inspect authored, resolved and YAML views | Real AGT `PolicyEngine` + `ShadowMode` |
| **Tool Playground** | Fire a governed tool call through the four gates | Real AGT `govern()` |
| **Trust & Identity** | Set/inspect trust, see the execution ring it buys, view AGT's computed reputation, and inspect each agent's signed identity card | Real AGT `TrustPolicy` + `AgentIdentity` + `TrustedAgentCard` + `nexus.ReputationEngine` |
| **Agents** | Register (with optional admin approval), inspect, suspend/resume, decommission, read each agent's lifecycle trail; onboard Foundry agents | Real AGT `LifecycleManager` |
| **Agent SRE** | Per-agent SLOs and error budgets, deduplicated alerts, behavioural anomaly detection, adversarial evaluation of the gates, kill switch | Real AGT `agent_sre` (`slo` + `alerts` + `anomaly` + `chaos`) |
| **Compliance** | Prompt-defense grade (real), OWASP live self-assessment with the last adversarial run attached to each risk, and SOC 2 / GDPR / HIPAA / EU AI Act reports scored from live evidence | Mixed — see below |
| **Audit Log** | Merkle-chained event stream, per-entry inclusion proofs, durable signed-file verification, accountability/EEOAP export, and per-call decision traces you can open and diff | Real AGT `MerkleAuditChain` + `HashChainVerifier` + `audit_accountability_export` + `agent_sre.replay` |

---

## 6. Standard procedures

### SOP 6.1 — Register an agent

1. Go to **Agents** → **Register Agent**.
2. Enter an **Agent ID** and **Display Name**, choose a **Policy**, set the
   **Trust Score** slider.
3. (Optional) Fill the **Azure AI Foundry** fields to link an external agent —
   see SOP 6.4.
4. Click **Register Agent**.

What actually happens: the agent is provisioned and activated through AGT's
`LifecycleManager`, and an Ed25519 identity with a `did:mesh` DID is minted. The
**private key is returned once**, in the success message / API response — store
it if you intend to attest later. The platform keeps only the public key.

### SOP 6.2 — Write and test a policy

1. Go to **Policy Engine** → create or edit a policy.
2. Rules are linted as you save; an unparsable rule is rejected (HTTP 400) with
   the reason.
3. Use the **evaluator** to test a context against the policy. This runs the
   **same `PolicyEngine` instance** the Tool Playground enforces with — the
   verdict shown is the verdict the runtime applies.

Notes that are true of the grammar:

- Conditions may reference the agent: `agent.trust_score`, `agent.state`, `agent.ring`, etc.
- PII/credential detection is exposed as facets (`input_text.has_pii`,
  `has_credentials`) computed by AGT's `CredentialRedactor`. Its coverage is
  finite (common email/SSN/card/key patterns); anything outside those patterns
  is **not** detected. Do not treat it as complete DLP.

### SOP 6.3 — Fire a governed tool call

1. Go to **Tool Playground**.
2. Pick a tool and action, provide input, choose the agent and policy.
3. Submit. The call runs four gates in order — **Lifecycle → Trust → Ring →
   Policy** — and the response names the gate that stopped it in `denied_by`.

This is the reference integration: it wraps the tool in AGT's `govern()` and the
decision is real. A denial here is an actual enforcement outcome, and it is
written to the audit log.

**Onboarding your own tools.** The tool list is a durable registry, not a
hardcoded set. Use *Onboard a Tool for Evaluation* to add a tool (name, actions,
risk, optional webhook). Give it an HTTP(S) `endpoint_url` and an allowed call
is **really invoked** — the actual HTTP status and latency are recorded and feed
the SLO; a failing endpoint is reported as a failed execution, never a faked
success. Leave the endpoint blank and the tool is governance-decision-only
(honestly reported as "nothing was executed"). Endpoints are SSRF-validated:
non-HTTP schemes and private/loopback/cloud-metadata targets are refused unless
`AGT_TOOL_ALLOW_PRIVATE` is set for local testing. Built-in demo tools cannot be
deleted; your own can.

### SOP 6.4 — Onboard a Microsoft Foundry agent (observational)

**Important:** this brings a Foundry agent under **monitoring**, not inline
enforcement. It replays telemetry Foundry already recorded; it does not
intercept the agent's tool calls. The backend never calls the Foundry SDK or
holds Azure credentials — you supply the exported run steps.

1. **Agents → Register Agent.** Fill the standard fields, then the **Azure AI
   Foundry** section: the **Project Endpoint** and the **Foundry Agent ID**
   (`asst_…`). Register.
2. The agent card now shows a Foundry badge and a **Sync from Foundry** button.
3. In the Foundry portal or SDK, export a thread run's steps:
   ```python
   run_steps = [s.as_dict() for s in
                project.agents.run_steps.list(thread_id=..., run_id=...)]
   ```
4. Click **Sync from Foundry**, paste the JSON array, and **Sync telemetry**.

What is recorded: only `tool_calls` steps become events (a run with none is
accepted with zero events); each feeds this agent's `agent_sre` SLOs and a
single audit note tagged `source: foundry-runsteps`. Message-only steps are
ignored. Because this is self-reported telemetry, it is **never** an
authoritative allow/deny verdict.

For automation, the same operation is `POST /agents/{id}/foundry/sync`.

### SOP 6.5 — Connect your own agent programmatically

Use the dependency-free SDK in `backend/agt_client.py`. Two integration modes:

- **Inline (enforcing):** call `authorize(...)` **before** acting; it runs the
  four gates and can attach a cryptographic attestation so the `agent_id` is
  proven, not merely asserted.
- **Out-of-band (observational):** call `report_call(...)` / `report(...)` after
  acting to stream telemetry into the SLOs.

```python
from agt_client import GovernanceClient

agent = GovernanceClient("http://localhost:8000", token="s3cret")  # token if auth on
agent.register("billing-agent", owner="team@corp", trust_score=0.9)
# store the once-issued private key to attest after a restart

verdict = agent.authorize("web_search", action="read")
if verdict["allowed"]:
    agent.report_call("web_search", allowed=True, latency_ms=42)
```

Attestation is **optional by default**: an unattested call is honoured on its
self-asserted `agent_id` but flagged `identity_verified: false`. Set
`AGT_REQUIRE_ATTESTATION` (Section 4.4) to make it mandatory — then an
unattested or wrongly-signed call is denied at the identity gate.

### SOP 6.6 — Monitor SLOs and use the kill switch

1. Go to **Agent SRE** to see each agent's SLO, compliance and latency
   indicators over a real error budget.
2. **Kill** suspends an agent through AGT's `SUSPENDED` lifecycle state. This is
   enforced **before** policy — a kill switch that policy could override is not a
   kill switch — so a suspended agent is denied every call.
3. **Resume** returns it to active and clears its ring-violation budget.

Remember SLO measurements are in-memory unless `AGT_STATE_DIR` is set, in which
case they persist across restarts (Section 4.2).

### SOP 6.7 — Verify audit integrity

1. Go to **Audit Log** to view the event stream, newest first, each entry
   SHA-256 hashed over its own fields plus the previous entry's hash.
2. **Verify** re-walks the chain and reports whether it is intact. Editing,
   deleting, reordering — or even recomputing an edited entry's own hash —
   breaks verification, because the next entry's chain link no longer matches.
3. **Export** returns the full chain and Merkle root for offline verification;
   per-entry Merkle inclusion proofs are available via `GET /audit/proof/{id}`.

Note: clearing the audit log starts a **new** chain and records the old root; it
does not silently erase history.

### SOP 6.8 — Trace how a decision was made

The audit chain answers *whether* a call was allowed and proves the record has
not been edited. When you need to know *why* it went the way it did — or why one
call took 400 ms and an identical one took 40 — open its trace.

**Requires `AGT_STATE_DIR`** (see §4.2). Without it the panel says tracing is
off; it does not show an empty list, which would read as "no calls were made".

1. Go to **Audit Log** and scroll to **Decision traces**. Each row is one
   governed call: when, what was called, by whom, the outcome, how many spans
   and the total duration.
2. Click the call to open its timeline. Each bar is one span:

   | Span | What it covers |
   |---|---|
   | `gate:lifecycle` `gate:identity` `gate:tenant` `gate:trust` | The gates that run in this handler, each timed individually |
   | `gate:govern` | Ring, policy **and** the MCP proxy together — AGT decides all three inside `govern()` and returns one outcome, so this platform cannot time them apart. Three bars here would be three invented numbers |
   | *tool name* | The remote call, using the round trip the connector itself measured. Absent when nothing was dispatched |
   | `record:governance` | The audit chain, SLO, alert and receipt writes that follow the decision. On a fast local deny this is most of the request — charging it to whichever gate decided would make that gate look slow |

   The bars add up to the trace's total duration, so there is no unexplained gap.
3. A denied call's trace **ends on the gate that denied it**, with that span in
   red and the rule named. Nothing downstream of the denial appears, because
   nothing downstream ran.
4. To compare two calls, tick two rows and press **Diff**. AGT's `ReplayEngine`
   returns typed findings — `status change`, `output mismatch`, `extra span` —
   rather than a text diff, so "the same call decided differently" is a fact
   rather than something you have to spot.

Traces survive a restart. Delete one with the bin icon (admin only); the
deletion is itself audited.

---

## 7. Roles and who can do what

| Action | Minimum role (when auth is enabled) |
|---|---|
| View any panel / list agents, policies, SLOs, audit | `viewer` |
| Register agents, write policies, fire tool calls, sync Foundry telemetry, update trust, signal SLOs | `operator` |
| Decommission agents, delete policies, clear audit, delete a trace, kill/resume | `admin` |

With auth disabled, every caller is an anonymous admin.

---

## 8. Known limitations — do not rely on these

- **Compliance → OWASP mapping is a self-assessment**, not a certified audit. It
  reports the controls actually enabled on the running instance (auth,
  attestation, durable state/audit, CORS, kill switch) and the enforcement
  status of each risk — but it does **not** scan your codebase or guarantee
  compliance.
- **Prompt scan grades a *system prompt*'s defensive language** (A–F). It is
  static analysis of the prompt, **not** a detector for malicious user input.
- **Foundry onboarding and `/ingest/events` are observational.** They feed SLOs
  and audit notes from self-reported data; they do not enforce anything. (This
  is inherent: replayed telemetry describes calls that already happened.)
- **PII/credential detection is pattern-limited** to AGT's `CredentialRedactor`.
- **SPIFFE/mTLS and full OIDC + secret rotation are not implemented** — they need
  an external identity provider / PKI. JWT support here is a static HS256
  verifier only (see Section 4.1).

---

## 9. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Sidebar shows "API offline" | Backend not running or wrong port | Confirm `uvicorn` is up on `:8000`; check `curl /health` |
| `401 Missing or invalid API key` | Auth is enabled | Set `localStorage['agt_api_token']` to a valid token |
| `403 Requires 'operator'/'admin' role` | Token lacks the role | Use a token with the required role |
| `403 Agent belongs to another tenant` | Cross-tenant access | Use a token in the agent's tenant, or an admin token |
| Agents vanished after restart | Persistence not enabled | Set `AGT_STATE_DIR` before starting |
| Foundry sync says 0 accepted | Run steps had no `tool_calls` | Expected — only tool-call steps map to events |
| `Run steps must be valid JSON` in sync modal | Malformed paste | Paste a JSON **array** of run-step dicts |
| Frontend calls go to `localhost:8000` in a container | `REACT_APP_API_URL` unset at build | Build with `REACT_APP_API_URL=""` for same-origin |

---

## 10. Deployment (brief)

The app ships as a **single container**: the frontend is built and served by the
FastAPI backend from one origin. See the [README](README.md) "Deploy" section
for the `docker build` / `docker run` commands and the Azure Container Apps
(`azd up`) path, including how to pass `AGT_API_KEYS` as a Container App secret.

---

*For the precise, feature-by-feature statement of what runs real AGT versus what
is reference or demonstration, always defer to the "What's real, and what isn't"
table in the [README](README.md).*
