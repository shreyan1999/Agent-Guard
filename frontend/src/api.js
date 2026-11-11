// An empty REACT_APP_API_URL means "same origin" (the single-container build);
// only an unset var falls back to the local dev backend. Hence ?? not ||.
const BASE = process.env.REACT_APP_API_URL ?? 'http://localhost:8000';

// Optional bearer token, used only when the backend has auth enabled
// (AGT_API_KEYS set). Read from build-time env or, at runtime, localStorage
// so the token never has to be baked into the bundle.
function authToken() {
  if (typeof localStorage !== 'undefined') {
    const stored = localStorage.getItem('agt_api_token');
    if (stored) return stored;
  }
  return process.env.REACT_APP_API_TOKEN || '';
}

async function req(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  const token = authToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    // Some endpoints (policy linting) return a structured detail object.
    const e = new Error(typeof err.detail === 'string' ? err.detail : 'Request failed');
    if (err.detail && typeof err.detail === 'object') e.message = err.detail;
    throw e;
  }
  return res.json();
}

export const api = {
  get: (p) => req('GET', p),
  post: (p, b) => req('POST', p, b),
  del: (p) => req('DELETE', p),

  stats: () => req('GET', '/stats'),
  health: () => req('GET', '/health'),

  policies: {
    list: () => req('GET', '/policies'),
    get: (name) => req('GET', `/policies/${encodeURIComponent(name)}`),
    create: (b) => req('POST', '/policies', b),
    delete: (name) => req('DELETE', `/policies/${encodeURIComponent(name)}`),
    evaluate: (b) => req('POST', '/policies/evaluate', b),
    schema: () => req('GET', '/policies/schema'),
    update: (name, b) => req('PUT', `/policies/${encodeURIComponent(name)}`, b),
    validate: (b) => req('POST', '/policies/validate', b),
    yaml: (name) => req('GET', `/policies/${encodeURIComponent(name)}/yaml`),
    resolved: (name) => req('GET', `/policies/${encodeURIComponent(name)}/resolved`),
    // Dry-run a candidate against the policy in force, over contexts
    // replayed from the audit chain. Evaluates; never enforces.
    shadow: (b) => req('POST', '/policies/shadow', b),
  },
  tools: {
    list: () => req('GET', '/tools'),
    call: (b) => req('POST', '/tools/call', b),
    register: (b) => req('POST', '/tools/register', b),
    remove: (name) => req('DELETE', `/tools/${encodeURIComponent(name)}`),
  },
  mcp: {
    discover: (b) => req('POST', '/mcp/discover', b),
    import: (b) => req('POST', '/mcp/import', b),
    servers: () => req('GET', '/mcp/servers'),
    removeServer: (name) => req('DELETE', `/mcp/servers/${name}`),
    // Re-fetch what the server advertises now and compare it against the
    // descriptor each tool was imported with (rug-pull check).
    verifyServer: (name) => req('POST', `/mcp/servers/${encodeURIComponent(name)}/verify`),
    // Every AGT MCP control this platform runs, read from the live objects
    // rather than a fixed table, so a control that was reconfigured or
    // switched off reports what it actually is.
    controls: (agentId) =>
      req('GET', `/mcp/controls${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''}`),
    // The detection rule set in force: which file, how many rules, and how
    // many the toolkit ships that this file does not carry.
    securityRules: () => req('GET', '/mcp/security-rules'),
    validateRules: (content, kind = 'mcp') =>
      req('POST', '/mcp/security-rules/validate', { content, kind }),
    reloadRules: () => req('POST', '/mcp/security-rules/reload'),
    // Known vulnerabilities in the server's own package, as opposed to its
    // tool text. Offline unless AGT_MCP_CVE_ONLINE is set.
    vulnerabilities: (server) =>
      req('POST', `/mcp/servers/${encodeURIComponent(server)}/vulnerabilities`),
  },
  receipts: {
    list: (limit = 50) => req('GET', `/mcp/receipts?limit=${limit}`),
    verify: () => req('GET', '/mcp/receipts/verify'),
    export: () => req('GET', '/mcp/receipts/export'),
  },
  trust: {
    overview: () => req('GET', '/trust'),
    evaluate: (b) => req('POST', '/trust/evaluate', b),
    update: (agent_id, score) => req('POST', `/trust/update?agent_id=${encodeURIComponent(agent_id)}&score=${score}`),
    // Adopt AGT's computed reputation as the enforced trust score.
    promote: (agent_id) => req('POST', `/trust/promote/${encodeURIComponent(agent_id)}`),
  },
  identity: {
    // Signed TrustedAgentCard, re-verified server-side on every read.
    card: (agent_id) => req('GET', `/agents/${encodeURIComponent(agent_id)}/card`),
    document: (agent_id) => req('GET', `/agents/${encodeURIComponent(agent_id)}/identity`),
    challenge: (agent_id) => req('POST', '/identity/challenge', { agent_id }),
  },
  audit: {
    get: (limit = 50, agent_id, event_type) => {
      let q = `?limit=${limit}`;
      if (agent_id) q += `&agent_id=${agent_id}`;
      if (event_type) q += `&event_type=${event_type}`;
      return req('GET', `/audit${q}`);
    },
    clear: () => req('DELETE', '/audit'),
    verify: () => req('GET', '/audit/verify'),
    proof: (id) => req('GET', `/audit/proof/${encodeURIComponent(id)}`),
    export: () => req('GET', '/audit/export'),
    // The other half of durable audit: re-read what FileAuditSink wrote and
    // check every entry against the key it was written with.
    verifyFile: () => req('GET', '/audit/verify-file'),
    // The chain as external accountability records rather than a JSON dump.
    accountability: (limit = 200) =>
      req('GET', `/audit/export/accountability?limit=${limit}`),
  },
  // AGT agent_sre.replay: how a decision was made, span by span. The audit
  // chain proves a decision happened; a trace shows the path it took there.
  traces: {
    list: (limit = 50, agentId) =>
      req('GET', `/traces?limit=${limit}` +
        (agentId ? `&agent_id=${encodeURIComponent(agentId)}` : '')),
    get: (id) => req('GET', `/traces/${encodeURIComponent(id)}`),
    // AGT's ReplayEngine, which returns typed findings rather than a text diff.
    diff: (a, b) =>
      req('GET', `/traces/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`),
    remove: (id) => req('DELETE', `/traces/${encodeURIComponent(id)}`),
  },
  agents: {
    list: () => req('GET', '/agents'),
    create: (b) => req('POST', '/agents', b),
    delete: (id) => req('DELETE', `/agents/${encodeURIComponent(id)}`),
    // AGT's own LifecycleManager audit trail: who moved this agent, and why.
    lifecycle: (id) => req('GET', `/agents/${encodeURIComponent(id)}/lifecycle`),
    approve: (id) => req('POST', `/agents/${encodeURIComponent(id)}/approve`),
    reject: (id, reason) =>
      req('POST', `/agents/${encodeURIComponent(id)}/reject?reason=${encodeURIComponent(reason || 'Not approved')}`),
    // Suspend/resume are the same AGT SUSPENDED transition the SRE kill switch
    // uses — one state, one code path, reachable from either tab.
    suspend: (id) => req('POST', `/sre/kill/${encodeURIComponent(id)}`),
    resume: (id) => req('POST', `/sre/resume/${encodeURIComponent(id)}`),
    foundrySync: (id, runSteps) => req('POST', `/agents/${encodeURIComponent(id)}/foundry/sync`, { run_steps: runSteps }),
  },
  sre: {
    slos: () => req('GET', '/sre/slos'),
    createSlo: (b) => req('POST', '/sre/slos', b),
    signal: (id, success) => req('POST', `/sre/signal/${encodeURIComponent(id)}?success=${success}`),
    kill: (id) => req('POST', `/sre/kill/${encodeURIComponent(id)}`),
    resume: (id) => req('POST', `/sre/resume/${encodeURIComponent(id)}`),
    // AGT AlertManager — deduplicated, one feed for every governance event.
    alerts: (limit = 50) => req('GET', `/sre/alerts?limit=${limit}`),
    clearAlerts: () => req('DELETE', '/sre/alerts'),
    // AGT AnomalyDetector — behavioural deviation, advisory only.
    anomalies: (metric) =>
      req('GET', `/sre/anomalies${metric ? `?metric=${encodeURIComponent(metric)}` : ''}`),
    // AGT AdversarialEvaluator — fires attack vectors at the real gates.
    chaosVectors: () => req('GET', '/sre/chaos/vectors'),
    lastChaos: () => req('GET', '/sre/chaos/last'),
    runChaos: (b) => req('POST', '/sre/chaos/run', b || {}),
  },
  // The worked demo scenario the Overview can load and unload. Loading it
  // fires real governed calls, so it is an admin action, and unloading cannot
  // remove the audit entries those calls produced -- the response says so.
  demo: {
    status: () => req('GET', '/demo/seed'),
    load: () => req('POST', '/demo/seed'),
    unload: () => req('DELETE', '/demo/seed'),
  },
  compliance: {
    scanPrompt: (b) => req('POST', '/compliance/scan-prompt', b),
    owasp: () => req('GET', '/compliance/owasp'),
    // AGT ComplianceEngine: a framework report scored from evidence this
    // instance actually holds.
    frameworks: () => req('GET', '/compliance/frameworks'),
    report: (framework, days = 30) =>
      req('GET', `/compliance/report?framework=${encodeURIComponent(framework)}&days=${days}`),
  },
};
