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
    get: (name) => req('GET', `/policies/${name}`),
    create: (b) => req('POST', '/policies', b),
    delete: (name) => req('DELETE', `/policies/${name}`),
    evaluate: (b) => req('POST', '/policies/evaluate', b),
    schema: () => req('GET', '/policies/schema'),
    update: (name, b) => req('PUT', `/policies/${name}`, b),
    validate: (b) => req('POST', '/policies/validate', b),
    yaml: (name) => req('GET', `/policies/${name}/yaml`),
    resolved: (name) => req('GET', `/policies/${name}/resolved`),
  },
  tools: {
    list: () => req('GET', '/tools'),
    call: (b) => req('POST', '/tools/call', b),
    register: (b) => req('POST', '/tools/register', b),
    remove: (name) => req('DELETE', `/tools/${name}`),
  },
  trust: {
    overview: () => req('GET', '/trust'),
    evaluate: (b) => req('POST', '/trust/evaluate', b),
    update: (agent_id, score) => req('POST', `/trust/update?agent_id=${agent_id}&score=${score}`),
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
    proof: (id) => req('GET', `/audit/proof/${id}`),
    export: () => req('GET', '/audit/export'),
  },
  agents: {
    list: () => req('GET', '/agents'),
    create: (b) => req('POST', '/agents', b),
    delete: (id) => req('DELETE', `/agents/${id}`),
    lifecycle: (id) => req('GET', `/agents/${id}/lifecycle`),
    foundrySync: (id, runSteps) => req('POST', `/agents/${id}/foundry/sync`, { run_steps: runSteps }),
  },
  sre: {
    slos: () => req('GET', '/sre/slos'),
    createSlo: (b) => req('POST', '/sre/slos', b),
    signal: (id, success) => req('POST', `/sre/signal/${id}?success=${success}`),
    kill: (id) => req('POST', `/sre/kill/${id}`),
    resume: (id) => req('POST', `/sre/resume/${id}`),
  },
  compliance: {
    scanPrompt: (b) => req('POST', '/compliance/scan-prompt', b),
    owasp: () => req('GET', '/compliance/owasp'),
  },
};
