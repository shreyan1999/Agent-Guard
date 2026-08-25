# AGT Governance Dashboard

A local playground for exploring the [Microsoft Agent Governance Toolkit](https://microsoft.github.io/agent-governance-toolkit/) (AGT). It gives you a browser UI for writing policies, firing governed tool calls at them, and watching the resulting decisions.

> **This is a learning playground, not a governance product.** Some panels are backed by real AGT enforcement; others are local implementations or demo stubs built to illustrate a concept. The table below says exactly which is which. Do not use this to make claims about your own governance posture.

---

## What's real, and what isn't

| Area | Endpoint | Status | What actually runs |
|---|---|---|---|
| **Tool Playground** | `POST /tools/call` | **Real AGT** | `agentmesh.governance.govern()` wraps the tool; AGT's `PolicyEngine` makes the decision and raises `GovernanceDenied`. This is the reference integration. |
| **Telemetry ingestion** | `POST /ingest/events` | **Real AGT** | Out-of-band counterpart to `/tools/call`: a running agent streams the events it already executed, which feed the real `agent_sre` SLOs and a summarised, source-tagged audit note. Self-reported telemetry, never an authoritative verdict. |
| **Foundry connector** | `backend/foundry_connector.py`, `POST /agents/{id}/foundry/sync` | **Real schema** | Maps Microsoft Foundry (Azure AI Agents) `RunStep` telemetry — `tool_calls` steps, status, timestamps, `last_error` — into ingestion events. It never calls the Foundry SDK itself (the caller pastes `run_steps.list(...).as_dict()`), so a Foundry agent's tool use feeds the same SLOs and audit trail. Onboardable from the Agents panel: register a twin with the Foundry link, then paste run steps to sync. |
| **Trust evaluation** | `POST /trust/evaluate` | **Real AGT** | Genuine `TrustPolicy` + `PolicyEvaluator`, and the *same* policy object `/tools/call` enforces with — a verdict shown here is the verdict the runtime applies. |
| **Agent identity** | `/identity/*`, `/agents/{id}/identity` | **Real AGT** | Each agent is minted an Ed25519 `agentmesh.identity.AgentIdentity` with a `did:mesh` DID. The platform keeps only the public key; the private key is issued once at registration. A tool call can be cryptographically attested via a single-use challenge nonce the agent signs. |
| **Policy evaluation** | `POST /policies/evaluate` | **Real AGT** | Runs the *same* `PolicyEngine` instance the Tool Playground enforces with, on a context built by AGT the same way — agent facet included. The two cannot report different verdicts. |
| **Policy storage** | `/policies` | **Real AGT** | One YAML file per policy in a single directory, loaded by `Policy.from_yaml_file()`. Policies persist across restarts and can inherit from each other via `extends`. |
| **Agent registry** | `/agents` | **Real AGT** | AGT's `LifecycleManager` owns agent records and state. Provisioning, activation, suspension and decommissioning are lifecycle transitions with actor attribution and their own audit trail (`GET /agents/{id}/lifecycle`). |
| **Agent SRE** | `/sre/*` | **Real AGT** | Per-agent `agent_sre.SLO` objects with `TaskSuccessRate`, `PolicyCompliance` and `ResponseLatency` indicators over a real `ErrorBudget`. Governed tool calls feed measurements into the SLO, so error-budget burn rate and firing alerts are computed by AGT, not by this app. |
| **Audit log** | `GET /audit` | **Real AGT** | AGT's `AuditLog` over a `MerkleAuditChain`. Every entry is SHA-256 hashed over its own fields plus the previous entry's hash. `GET /audit/verify` re-walks the chain; `GET /audit/proof/{id}` returns a Merkle inclusion proof. |
| **Prompt scan** | `POST /compliance/scan-prompt` | **Real AGT** | AGT's `PromptDefenseEvaluator` grades a **system prompt**'s defensive posture (A–F over 12 vectors). It is static analysis of a prompt's own defensive language — not a detector for malicious user input. |
| **OWASP coverage** | `GET /compliance/owasp` | **Reference** | A hardcoded mapping of AGT controls to the OWASP Agentic AI Top 10, each marked `enforced` / `partial` / `not_implemented`. It is reference material about AGT, **not** an automated assessment of this codebase. |
| **Access control** | all endpoints | **App-layer** | Not an AGT primitive — this is FastAPI guarding who reaches the API. Off by default (anonymous local admin); set `AGT_API_KEYS` to require bearer tokens, a `viewer`/`operator`/`admin` role hierarchy, and per-tenant agent isolation. |

---

## Coverage against the AGT pillars

AGT organises governance under four pillars. Here is where this playground honestly sits:

| Pillar | AGT capability | This project |
|---|---|---|
| **Policy** — fail-closed decisions | `PolicyEngine`, `govern()`, `FacetRegistry`, `Policy.extends` | **Implemented.** One `PolicyEngine` serves both the Policy panel and enforcement. Policies are file-backed, support inheritance and per-policy conflict strategy, and every way a rule can silently fail to fire is reported. |
| **Trust** — DID, SPIFFE, mTLS | `TrustPolicy`, identity primitives | **Enforced and attestable.** A shared `TrustPolicy` gates every call below `MIN_TRUST`, `agent_id` reaches `govern()` so AGT evaluates as that agent, and the score selects the execution ring. Each agent now has a real Ed25519 `AgentIdentity` (`did:mesh` DID); a call can be cryptographically attested by signing a challenge nonce, verified against the agent's public key. Attestation is currently *optional* — an unattested call is honoured on its self-asserted `agent_id` but flagged `identity_verified: false`. Making attestation mandatory, and SPIFFE/mTLS, are the remaining steps. |
| **Runtime** — isolation, kill switches | `hypervisor.rings`, `ExecutionRing`, `LifecycleManager` | **Implemented.** The kill switch is AGT's `SUSPENDED` lifecycle state, enforced before policy and not overridable by policy; invalid transitions are rejected by AGT's state machine. Trust derives an `ExecutionRing` via `ExecutionRing.from_eff_score()`, and `govern(ring=…)` enforces its resource constraints inside AGT, with a per-session circuit breaker. |
| **Evidence** — tamper-evident audit | `MerkleAuditChain` | **Implemented.** Backed by AGT's `AuditLog` / `MerkleAuditChain`. Editing, deleting or reordering an entry breaks verification — including when the attacker recomputes the edited entry's own hash, because the next entry's chain link still fails. Durable storage is opt-in (see below). |

The **Compliance** panel does not map onto any AGT pillar. The prompt-defense grade is a real AGT evaluator, but the OWASP list is reference material, not a control.

---

## How a tool call is decided

`POST /tools/call` runs four gates. Each is backed by an AGT primitive, and the
response names the one that stopped the call in `denied_by`.

| # | Gate | AGT primitive | Denies when |
|---|---|---|---|
| 1 | **Lifecycle** | `LifecycleManager` | The agent is unregistered, or its state is not `ACTIVE` (the kill switch is the `SUSPENDED` state) |
| 2 | **Trust** | `TrustPolicy` + `PolicyEvaluator` | `trust_score < MIN_TRUST` (default `0.3`) |
| 3 | **Ring** | `ExecutionRing` + `govern(ring=…)` | The agent's ring forbids the resource the action needs |
| 4 | **Policy** | `PolicyEngine` via `govern()` | An AGT rule matches with a non-`allow` action |

Gates 1 and 2 run before `govern()` — a kill switch that policy could override
is not a kill switch. Gates 3 and 4 run *inside* `govern()`, and both report
through AGT's `on_deny` callback carrying a `PolicyDecision`.

### Trust selects the execution ring

AGT maps a trust score to a ring with `ExecutionRing.from_eff_score()`, and each
ring permits a different set of resources. Raising or lowering an agent's trust
changes what it can reach, with no policy edit:

| Trust | Ring | Network | Filesystem | Subprocess |
|---|---|---|---|---|
| `> 0.60` | `RING_2_STANDARD` | yes | scoped | yes |
| `≤ 0.60` | `RING_3_SANDBOX` | no | none | no |

`RING_1_PRIVILEGED` needs `> 0.95` **and** consensus, which this playground does
not model, so it is never reached.

**The breaker.** AGT tracks ring violations per agent session and trips a circuit
breaker after repeated attempts, after which *every* call from that agent is
denied with rule `ring_breaker` — including actions its ring would normally
permit. That is the intended defence against an agent probing its sandbox. A
session here lasts as long as the agent, so the trip would otherwise be
permanent; resuming a suspended agent clears the violation budget, making
suspend/resume the operator's remedy. AGT infers the resource type from the action
name — `web_search` is network, `write_file` is filesystem, `shell_exec` is
subprocess, everything else is tool execution.

### Writing rules against the agent

The agent is injected into the policy context as a dict, so your own rules can
reference it:

```yaml
- name: email-needs-high-trust
  condition: agent.trust_score < 0.8 and action.type == "send_email"
  action: deny
```

Available fields: `agent.id`, `agent.agent_id`, `agent.trust_score`, `agent.state`, `agent.ring`.

### Enriching the context instead of the grammar

Because the grammar has no regex, detection happens *before* evaluation and
lands in the context as a flag. This project registers one extractor on AGT's
`FacetRegistry`, backed by AGT's own `CredentialRedactor`:

```yaml
- name: block-pii
  condition: input_text.has_pii
  action: deny
```

`PolicyEngine.evaluate()` runs the registry on every evaluation, so the facet is
present in the Policy panel and at the enforcement point alike — there is no
path where one sees it and the other does not. Available facets on `input_text`:
`has_pii`, `pii_types`, `has_credentials`.

Detection coverage is AGT's, not this project's: `CredentialRedactor` ships
patterns for email, US phone, US SSN, credit card, IPv4, and for OpenAI/GitHub/
AWS/Azure keys, bearer tokens, JWTs, PEM keys and connection strings. Anything
outside those patterns is not detected — for example `sk_live_…` is not matched.

---

## Writing policies

Each policy is one YAML file in `backend/policies/` (override with
`AGT_POLICY_DIR`). They persist across restarts, and AGT loads them with
`Policy.from_yaml_file()`, which is what makes inheritance possible — parents
are resolved relative to that directory, and AGT refuses any parent outside it.

### Inheritance

```yaml
name: team-policy
extends: [org-baseline]
scope: tenant
conflict_strategy: deny_overrides
```

Parent rules are merged first, deduplicated by name, and inheritance is
**additive-only**: a child cannot weaken a parent `deny`. AGT drops such a rule
with only a log line, so `GET /policies/{name}/resolved` reports it explicitly,
along with the origin policy of every merged rule. A parent cannot be deleted
while a child still extends it.

### Conflict strategy and scope

`conflict_strategy` is per policy and reaches `govern()`:
`deny_overrides` (default), `allow_overrides`, `priority_first_match`,
`most_specific_wins`. **`scope` is only consulted by `most_specific_wins`** —
under any other strategy it has no effect, which is why the two are configured
together rather than separately.

### Three ways a rule can silently do nothing

AGT accepts all three without complaint, so the dashboard reports them:

| | Reported by |
|---|---|
| A condition AGT's grammar cannot parse | rejected at write time, 400 |
| `stage` other than `pre_tool` — `govern()` never evaluates it | warning on the policy |
| A child rule weakening an inherited `deny` — dropped by AGT | `dropped_rules` in `/resolved` |

### Building conditions in the UI

The Policy panel composes conditions from pickers rather than free text: choose
a field, then an operator (filtered to that field's type), then a value. The
generated clause is shown as you build it.

Because AGT's grammar is small and closed, the builder covers **all** of it —
which is what makes it worth having. A rule AGT cannot evaluate stops being
something the linter reports after the fact and becomes something you cannot
express in the first place.

It also blocks values AGT cannot carry. There is no escaping in the grammar, so
a value containing a quote, or the separators `" and "` / `" or "`, silently
turns the rule into one that never matches:

> Value cannot contain "and" — AGT splits on it before reading the clause, so
> the rule would never match.

`]` is blocked only for the `in` list, whose regex stops at the first one; a
quoted `==` value carries it fine.

Conditions the builder cannot represent — an older policy using an operator AGT
never supported — are shown as stored, read-only, rather than silently rewritten.

Since `or` binds looser than `and` and the grammar has no parentheses, a mixed
condition is spelled back out: *Reads as: (A and B) or C*.

### Schema

`GET /policies/schema` returns the operators, context fields, actions, stages,
scopes and strategies the backend accepts, generated from the same constants the
linter and store use. Each operator carries both a `template` (render a clause)
and a `pattern` (read one back), so the editor has one source for both
directions. It exists so the editor cannot offer something the backend would
then reject; tests assert every operator lints clean, parses its own output,
and is unambiguous against the others.

---

## Known limitations

Read these before drawing conclusions from anything the UI shows you.

**The expression grammar is deliberately small.** AGT supports `==`, `!=`,
`in [...]`, numeric comparison (`>`, `<`, `>=`, `<=`) and bare truthiness,
combined with `and` / `or`. There is no regex or substring operator. Anything
richer belongs in the *context*, not the condition — see below. Conditions are
linted when a policy is created: a rule AGT cannot parse is rejected with a 400
naming the offending atom, and existing policies show a warning in the panel.

**`warn` blocks.** AGT computes `allowed = (action == "allow")`, so a rule with action `warn` denies the call. The rule builder offers `warn` as if it were non-blocking. It is not.

**Rule priority is descending.** Higher priority numbers evaluate first. The bundled default policy numbers its rules the other way round; the default `deny_overrides` conflict strategy currently hides this.

**Agent identity is real but attestation is optional.** Every agent is minted an Ed25519 `AgentIdentity` with a `did:mesh` DID; the platform retains only the public key and issues the private key once, at registration. A tool call *can* be cryptographically attested: `POST /identity/challenge` issues a single-use nonce, the agent signs it, and `/tools/call` verifies the signature against the agent's public key (`identity_verified: true`). The residual gap is that an **unattested** call is still honoured on its self-asserted `agent_id` — only flagged `identity_verified: false` — for backward compatibility and the browser UI. Making attestation mandatory, plus SPIFFE/mTLS binding, is the next step for the Trust pillar.

**Agent persistence is opt-in.** By default the registry is in-memory: demo agents are re-seeded on every restart, and there is no durable record. Set `AGT_STATE_DIR` and the registry becomes durable — AGT's `LifecycleManager` persists agent records (`agents.json`, so a suspended kill-switch survives a restart), a sidecar `agent_meta.json` keeps trust/tenant/policy, and `identities.json` keeps the public DIDs so an agent's DID is **stable** across restarts. Private keys are never written: the once-issued private key stays with the caller, and the reloaded public key still verifies its attestations. A durable deployment starts **empty** (no demo agents) and is populated by real registrations.

**The prompt scanner grades system prompts, not user input.** `POST /compliance/scan-prompt` runs AGT's `PromptDefenseEvaluator`, which performs *static analysis of a system prompt*, grading whether defensive language is present (A–F over 12 vectors). It is **not** a detector for malicious user input, and it does no PII detection. A benign question like "What is the weather today?" grades **F, 0/12**, because it contains no defensive language — that is correct behaviour, not a bug. Feed it an agent's system prompt, not an end-user message.

**Authentication is off by default.** The playground ships open: with no keys configured every request runs as an anonymous local admin, exactly as before. Set `AGT_API_KEYS` (`token:subject:tenant:roles`, e.g. `s3cret:ana:acme:operator`) or `AGT_API_KEYS_FILE` and the same endpoints require a bearer token, enforce a three-tier role hierarchy (`viewer` ⊂ `operator` ⊂ `admin`), and scope agents by tenant — a caller sees and mutates only its own tenant's agents, while an `admin` spans tenants. Reads need `viewer`; creating agents/policies, invoking tools and updating trust need `operator`; deleting agents/policies, the kill switch and resetting the audit chain need `admin`. `/health` and the OpenAPI docs stay public so the browser can reach `/docs` to authenticate. CORS is now an allowlist (`AGT_CORS_ORIGINS`, default the local React origin) rather than `*`, and the launch scripts bind `127.0.0.1` by default (`AGT_HOST` to expose). The frontend attaches a bearer token from `localStorage['agt_api_token']` or `REACT_APP_API_TOKEN` when present. **Still missing:** token rotation, an OIDC/JWT path, and per-tenant policy isolation (policies remain a shared global library).

**Audit durability is opt-in.** The chain is held in memory and starts empty on restart. Set `AGT_AUDIT_FILE` and `AGT_AUDIT_KEY` to also stream entries to an append-only, HMAC-signed JSON-lines file via AGT's `FileAuditSink`. This is not the default because re-verifying on-disk entries requires the same key across restarts, and key management is out of scope for a playground.

**SLO measurements are in-memory.** With `AGT_STATE_DIR` set, agents, trust, tenant and public DIDs persist (above), and policies are file-backed by default; SLO measurements are the remaining volatile state and are rebuilt empty on restart. The SLO registry is guarded by a lock, as is the audit chain; the remaining handlers mutate shared dictionaries without locking.

---

## Prerequisites

| Tool | Version |
|---|---|
| Python | **3.11+** — `agent-governance-toolkit[full]` pulls `-core` and `-cli`, which both require 3.11 |
| Node.js | 18+ |
| npm | 9+ |
| pytest | installed via `backend/requirements-dev.txt`, for the test suite |

---

## Quick Start

### macOS / Linux
```bash
chmod +x start.sh
./start.sh
```

### Windows
```bat
start.bat
```

### Manual Setup

**Backend**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

On Windows, activate with `.venv\Scripts\activate` instead.

**Frontend** (new terminal)
```bash
cd frontend
npm install
npm start
```

Open **http://localhost:3000**

API docs (Swagger): **http://localhost:8000/docs**

### Verify it's running

When both servers are up you'll see:

| Service | URL | What you get |
|---|---|---|
| Dashboard | http://localhost:3000 | The React UI (CRA prints `Compiled successfully!`) |
| API | http://localhost:8000 | The FastAPI backend (uvicorn prints `Application startup complete`) |
| API docs | http://localhost:8000/docs | Swagger UI for every endpoint |

A quick backend health check:

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"1.0.0","agents":4,"policies":1}
```

The four seeded agents and one default policy are the in-memory demo data; set
`AGT_STATE_DIR` to start empty and persist real registrations instead.

---

## Deploy

The whole app ships as **one container**: a multi-stage [Dockerfile](Dockerfile)
builds the React dashboard, then the FastAPI backend serves both the API and the
built bundle from a single origin (`AGT_STATIC_DIR`, wired by
[`main._mount_spa`](backend/main.py)). Because the bundle is served by a *mount*,
it bypasses the auth dependency — the user supplies a token at runtime — while
every API route stays protected.

```bash
docker build -t agt-dashboard .
docker run -p 8000:8000 agt-dashboard          # open http://localhost:8000
# Opt into auth, persistence and durable audit at runtime:
docker run -p 8000:8000 \
  -e AGT_API_KEYS="s3cret:ana:acme:admin" \
  -e AGT_STATE_DIR=/data -v agt-state:/data \
  agt-dashboard
```

**Azure Container Apps**, via the Azure Developer CLI. The Bicep under
[infra/](infra/) provisions a Container Apps environment, a private registry
(anonymous pull disabled) and a user-assigned managed identity that pulls the
image with an `AcrPull` role — no registry credentials in code. `AGT_API_KEYS`
is passed as a Container App secret, and the ingress `targetPort` matches the
container's `8000`.

```bash
azd auth login
azd up            # builds the image, provisions infra, deploys
```

The container listens on `8000`; set `AGT_API_KEYS` (and optionally
`AGT_CORS_ORIGINS`) as azd environment values to enable auth before deploying.

---

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

244 tests covering the four gates, cryptographic identity attestation, API-key
auth with role and tenant enforcement, opt-in durable state, out-of-band
telemetry ingestion, the client SDK, the Foundry connector and UI onboarding,
single-container static hosting, policy agreement, tamper detection, the real
agent_sre SLOs and the lifecycle API. They run against the FastAPI app
in-process; each test rebuilds every module-level store via `reset_state()`,
including AGT's own breach-detector registry, so the suite is order-independent.

| File | What it pins down |
|---|---|
| `test_gates.py` | Each gate denies for its own reason, and the ring circuit breaker trips and clears |
| `test_policy.py` | The Policy panel and the enforcement path agree on verdict *and* rule, across a sweep of inputs |
| `test_audit.py` | Editing, deleting, reordering or re-hashing an entry all break chain verification |
| `test_demo_claims.py` | Every demo button in `ToolPanel.js` produces the verdict its label advertises |
| `test_lifecycle_and_api.py` | Lifecycle transitions, trust threshold agreement, endpoint contract |
| `test_identity.py` | DID issuance, the private key is issued once, and challenge-response attestation verifies real signatures and rejects forgeries and replays |
| `test_auth.py` | Bearer-token auth, the `viewer`/`operator`/`admin` role hierarchy, tenant isolation on listing and cross-tenant mutation, and malformed-key rejection |
| `test_persistence.py` | With `AGT_STATE_DIR` set, agents, trust, tenant and public DIDs survive a simulated restart, the kill switch persists, and the in-memory default writes nothing |
| `test_ingest.py` | A batch of reported events feeds the real SLOs, updates counters, writes one source-tagged audit note, and rejects unregistered agents and oversized batches |
| `test_sdk.py` | The client SDK, driven against the live app: registration captures the issued key, authorization signs a real challenge nonce, and reporting streams telemetry |
| `test_foundry_connector.py` | Foundry `RunStep` telemetry maps to ingestion events — only `tool_calls` steps, function names, failure/error, timestamp latency — and streams into the SLOs |
| `test_foundry_sync.py` | The onboarding endpoint: registration records the Foundry link and it survives a restart, pasted run steps feed the SLOs and one `foundry.telemetry` note, and empty/unknown/oversized inputs are handled |
| `test_packaging.py` | The single-container static mount serves index.html at the root without shadowing an API route, and stays off when `AGT_STATIC_DIR` is unset |
| `test_policy_store.py` | Persistence, name safety, inheritance, conflict strategy, and the schema-vs-linter drift guard |
| `test_condition_builder.py` | The schema contract: every operator renders, parses and lints; the frontend fixture matches the live endpoint |
| `test_known_broken.py` | Defects listed under Known limitations, so they cannot be quietly forgotten |

`test_demo_claims.py` parses `DEMO_CALLS` out of the frontend source rather than
restating it, so relabelling a button in the UI without changing behaviour fails
the build. Two shipped demos once lied — "SSN DETECTED (deny)" allowed the call,
and "SEND EMAIL (warn)" denied it — which is what this file exists to prevent.

The suite contains several `known_broken` tests that pin the *current*
self-asserted identity model. Wiring AGT's identity primitives makes those tests
fail, which is the prompt to update the README claim in the same change.

The frontend has its own suite for the condition model — pure
serialize/parse/validate logic, run with Node's built-in test runner:

```bash
cd frontend
npm test
```

Its schema fixture is compared against the live endpoint by
`test_condition_builder.py`, so the two cannot drift onto different grammars.

CI runs the backend suite, the frontend suite and a production build on every
push and pull request (`.github/workflows/ci.yml`).

---

## Project Structure

```
agt-dashboard/
├── .github/workflows/ci.yml ← Backend tests + frontend build
├── backend/
│   ├── main.py              ← FastAPI app — endpoints and gates
│   ├── policy_store.py      ← File-backed policy store + inheritance
│   ├── sre_monitor.py       ← Real agent_sre SLOs, per agent
│   ├── identity_store.py    ← Ed25519 agent identities (DID) + attestation
│   ├── auth.py              ← API-key auth, role hierarchy, tenant scoping
│   ├── state_store.py       ← Durable non-secret agent metadata (opt-in)
│   ├── agt_client.py        ← Dependency-free client SDK for real agents
│   ├── foundry_connector.py ← Maps Microsoft Foundry run-step telemetry to ingestion
│   ├── policies/            ← One YAML per policy (gitignored)
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── pytest.ini
│   └── tests/               ← 244 tests; see Tests above
├── frontend/
│   ├── src/
│   │   ├── App.js           ← Main layout + overview dashboard
│   │   ├── api.js           ← Fetch helpers for all endpoints
│   │   ├── index.css        ← Design system (CSS vars)
│   │   └── panels/
│   │       ├── policy/
│   │       │   ├── ConditionBuilder.js  ← Graphical condition editor
│   │       │   └── conditionModel.js    ← Pure serialize/parse/validate
│   │       ├── PolicyPanel.js     ← Policy editor + evaluator
│   │       ├── ToolPanel.js       ← govern() playground (real AGT)
│   │       ├── TrustPanel.js      ← Trust evaluation (enforced; same policy as /tools/call)
│   │       ├── AgentsPanel.js     ← Agent registry (AGT LifecycleManager, in-memory)
│   │       ├── SREPanel.js        ← Real agent_sre SLOs; kill switch via lifecycle (enforced)
│   │       ├── CompliancePanel.js ← System-prompt hardening grade + OWASP reference
│   │       └── AuditPanel.js      ← In-memory event log
│   └── package.json
├── Dockerfile               ← Multi-stage: build the SPA, serve it + the API
├── .dockerignore
├── azure.yaml               ← Azure Developer CLI service map (azd up)
├── infra/                   ← Bicep for Azure Container Apps (managed identity)
│   ├── main.bicep
│   ├── resources.bicep
│   └── main.parameters.json
├── start.sh                 ← One-command launcher (Mac/Linux)
├── start.bat                ← One-command launcher (Windows)
└── README.md
```

---

## Connecting a real agent

Two ways to bring your own agent under governance, both against real AGT:

- **Inline** — ask permission before acting. `POST /tools/call` runs the four
  gates and returns an allow/deny verdict; a call can be cryptographically
  attested so the `agent_id` is proven, not self-asserted.
- **Out-of-band** — report what already ran. `POST /ingest/events` streams a
  batch of execution events into the `agent_sre` SLOs and a summarised audit
  note. These are self-reported telemetry, never an authoritative verdict.

`backend/agt_client.py` is a dependency-free client SDK for both. Its default
transport uses only the standard library; inject an `httpx.Client`,
`requests.Session` or Starlette `TestClient` to reuse an existing one.

```python
from agt_client import GovernanceClient

agent = GovernanceClient("http://localhost:8000", token="s3cret")  # token optional
agent.register("billing-agent", owner="team@corp", trust_score=0.9)
# The private key is issued once, here; store it to attest after a restart.

verdict = agent.authorize("web_search", action="read")  # signs a real challenge
if verdict["allowed"]:
    agent.report_call("web_search", allowed=True, latency_ms=42)
```

### Onboarding a Microsoft Foundry agent

A Foundry-hosted agent is brought under governance as a **twin**: you register a
dashboard agent linked to its Foundry identity, then feed it the run-step
telemetry Foundry already recorded. This is observational — it lights up the
twin's SLOs and audit trail, not inline enforcement.

From the **Agents** panel (no code):

1. **Register Agent** → fill the ID/name/policy, then the optional **Azure AI
   Foundry** fields: the project endpoint and the Foundry agent id (`asst_…`).
2. The agent card shows a Foundry badge and a **Sync from Foundry** button.
3. In the Foundry portal or SDK, export the run steps of a thread run
   (`[s.as_dict() for s in project.agents.run_steps.list(thread_id=..., run_id=...)]`),
   paste the JSON array into the modal, and **Sync telemetry**.

The backend maps only the `tool_calls` steps to events (a run with none is
accepted with zero events), feeds this agent's `agent_sre` SLOs, and writes one
`foundry.telemetry` audit note tagged `source: foundry-runsteps`. Pasting the
exported JSON keeps Azure credentials and the Foundry SDK out of the dashboard
entirely. Equivalent to `POST /agents/{id}/foundry/sync` for automation.

---

## API Endpoints

```
GET  /health                     Health check
GET  /stats                      Dashboard overview stats

GET  /policies                   List all policies, with lint warnings
GET  /policies/schema            Operators, fields and options the editor may use
POST /policies                   Create (linted; 400 on unparsable rules)
GET  /policies/{name}            One authored policy
PUT  /policies/{name}            Replace a policy
DELETE /policies/{name}          Delete (409 if another policy extends it)
POST /policies/validate          Check a draft without saving it
GET  /policies/{name}/yaml       The file verbatim, for the read-only YAML pane
GET  /policies/{name}/resolved   Merged policy: rule origins and dropped rules
POST /policies/evaluate          Evaluate via the same PolicyEngine that enforces

POST /tools/call                 Execute a governed tool call through four gates
GET  /tools                      List available tools
POST /ingest/events              Ingest a batch of self-reported execution telemetry

GET  /trust                      Trust scores for all agents
POST /trust/evaluate             TrustPolicy evaluation (same policy /tools/call enforces with)
POST /trust/update               Update an agent's trust score

POST /compliance/scan-prompt     Grade a system prompt's defensive posture (A–F)
GET  /compliance/owasp           OWASP Agentic AI mapping (enforced/partial/not_implemented)

GET  /sre/slos                   List per-agent agent_sre SLOs
POST /sre/slos                   Create/reset an agent's SLO target
POST /sre/signal/{agent_id}      Record a success/failure event on the SLO
POST /sre/kill/{agent_id}        Suspend via LifecycleManager (enforced)
POST /sre/resume/{agent_id}      Resume via LifecycleManager

GET  /agents                     List all agents
POST /agents                     Register and activate an agent via LifecycleManager
DELETE /agents/{agent_id}         Decommission an agent (lifecycle transition, not a delete)
GET  /agents/{agent_id}/lifecycle   AGT lifecycle audit trail for one agent
GET  /agents/{agent_id}/identity    Public DID document + JWK (no private key)
POST /agents/{agent_id}/foundry/sync  Ingest pasted Foundry run steps into the agent's twin

POST /identity/challenge         Issue a single-use nonce for an agent to sign
POST /identity/attest            Verify a signature over a nonce against the agent's public key
GET  /audit                      Event stream, newest first, with per-entry hashes
GET  /audit/verify               Re-walk the chain and report integrity
GET  /audit/proof/{entry_id}     Merkle inclusion proof for one entry
GET  /audit/export               Full chain + Merkle root, for offline verification
DELETE /audit                    Start a new chain (records the old root, does not erase)
```

---

## AGT modules actually used

```
agent-governance-toolkit[full] 4.1.0
  agentmesh.governance
    ├── govern(agent_id=, ring=, on_deny=, session_id=)  — tool enforcement
    ├── PolicyEngine (via govern)                        — rule evaluation, both paths
    ├── protocol_facets.FacetRegistry                    — context enrichment
    ├── Policy.from_yaml_file + extends                  — policy inheritance
    ├── conflict_resolution strategies                   — per-policy resolution
    ├── PolicyEvaluator + TrustPolicy/TrustRule          — trust gate
    ├── AuditLog → MerkleAuditChain                      — evidence
    └── audit_backends.FileAuditSink                     — optional durable sink
  agentmesh.lifecycle
    ├── LifecycleManager + LifecyclePolicy               — agent registry
    └── AgentLifecycleState                              — kill switch
  hypervisor
    └── ExecutionRing.from_eff_score()                   — trust → ring
  agent_os
    └── CredentialRedactor                               — PII / credential facets
  agent_compliance
    └── PromptDefenseEvaluator                           — system-prompt hardening grade
  agentmesh.identity
    ├── AgentIdentity.create / sign / verify_signature   — Ed25519 did:mesh identity
    └── to_jwk / from_jwk                                — public-key issuance & attestation
  agent_sre
    ├── SLO + ErrorBudget                                — per-agent objectives
    └── SLIRegistry (TaskSuccessRate, PolicyCompliance…) — real indicators
```

Every symbol imported by `main.py` is now called. The one place this codebase
reaches past AGT's public API is `AuditStore.root_hash()`: `AuditLog` exposes no
public Merkle-root accessor short of `export()`, which serialises every entry.
That access is isolated in one method so an AGT upgrade touches one place.

The installed distribution contains 40+ AGT packages; this project meaningfully
exercises seven: governance, lifecycle, hypervisor, credential redaction,
prompt defense, identity and SRE.

### Package consolidation and deprecation warnings

AGT 4.x consolidated its many old distributions (`agentmesh-platform`,
`agent-os-kernel`, `agent-hypervisor`, `agent-sre`, …) into a handful of
`agent-governance-toolkit-*` packages. This project already installs the
consolidated distribution (`agent-governance-toolkit[full]`). The old top-level
import paths (`agentmesh.*`, `agent_os.*`, `hypervisor.*`, `agent_compliance`)
are **deliberately preserved** as the canonical API in 4.1.0 — verified against
the installed package, no complete non-deprecated namespace exists yet (only
`agent_control_plane` re-exports `PolicyEngine`/`PolicyRule`). Each such import
emits a one-time package-consolidation `DeprecationWarning`. Rather than hiding
*all* deprecation warnings, the app suppresses only that known upstream notice
by message, so genuine deprecations elsewhere still surface.

---

## A note on AGT versions

This project pins AGT **4.1.0** and builds on `govern()`. The current toolkit documentation describes **AGT 5**, with the Agent Control Specification (ACS) as the canonical policy decision runtime, and notes that `govern()` remains a convenience API while new integrations should target ACS. Porting this playground to ACS is an open item.

---

## Contributing

The limitations above are the roadmap. The highest-value fixes, roughly in order:

1. Extend access control: token rotation, an OIDC/JWT path, and per-tenant policy isolation (agents are tenant-scoped today; policies are still a shared global library).
2. Make identity attestation *mandatory* (it is real but optional today), and add SPIFFE/mTLS binding.
3. Replace the static `_trust_scores` map with AGT's `TrustTracker`, so trust moves with observed behaviour instead of manual edits.
4. Evaluate migrating from `govern()` to the Agent Control Specification (ACS), the canonical AGT 5 policy runtime.
