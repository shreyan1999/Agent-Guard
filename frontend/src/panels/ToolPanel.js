import { useState, useEffect } from 'react';
import { Terminal, Play, CheckCircle, XCircle, Clock, Plus, Trash2, Globe, ShieldOff } from 'lucide-react';
import { api } from '../api';

const DEMO_CALLS = [
  { label: 'READ (allowed)', tool: 'db_query', action: 'read', input_text: 'SELECT * FROM users', agent_id: 'research-agent' },
  { label: 'DROP (denied)', tool: 'db_query', action: 'drop', input_text: 'DROP TABLE users', agent_id: 'data-agent' },
  { label: 'SEND EMAIL (warn = deny)', tool: 'send_email', action: 'send_email', input_text: 'Hello team', agent_id: 'email-agent' },
  { label: 'WEB SEARCH (allowed)', tool: 'web_search', action: 'read', input_text: 'AI governance news', agent_id: 'research-agent' },
  { label: 'LOW TRUST (deny)', tool: 'db_query', action: 'read', input_text: '', agent_id: 'untrusted-agent' },
  { label: 'UNREGISTERED (deny)', tool: 'db_query', action: 'read', input_text: '', agent_id: 'ghost-agent' },
  { label: 'RING 3 / NETWORK (deny)', tool: 'web_search', action: 'web_search', input_text: '', agent_id: 'email-agent' },
  { label: 'RING 3 / SUBPROCESS (deny)', tool: 'db_query', action: 'shell_exec', input_text: '', agent_id: 'email-agent' },
];

const GATE_LABEL = {
  lifecycle: 'Lifecycle',
  trust: 'Trust',
  ring: 'Ring',
  policy: 'Policy',
};
const GATES = ['lifecycle', 'trust', 'ring', 'policy'];

const RISK_TAG = { low: 'allow', medium: 'warn', high: 'deny', critical: 'deny' };

export default function ToolPanel() {
  const [tools, setTools] = useState({ tools: [], available: [] });
  const [registered, setRegistered] = useState([]);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [policies, setPolicies] = useState([]);
  const [form, setForm] = useState({
    tool_name: 'db_query', policy_name: 'default-policy',
    action: 'read', input_text: '', agent_id: 'research-agent', kwargs: {},
  });
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [onb, setOnb] = useState({
    name: '', description: '', actions: '', risk: 'medium',
    endpoint_url: '', timeout_ms: 3000,
  });
  const [onbMsg, setOnbMsg] = useState(null);

  const refreshTools = () => api.tools.list().then(r => {
    setTools(r);
    setRegistered(r.registered || []);
    setAllowPrivate(!!r.allow_private_endpoints);
  }).catch(() => {});

  useEffect(() => {
    refreshTools();
    api.policies.list().then(setPolicies).catch(() => {});
  }, []);

  const onboard = async () => {
    setOnbMsg(null);
    try {
      const spec = await api.tools.register({
        name: onb.name,
        description: onb.description,
        actions: onb.actions.split(',').map(s => s.trim()).filter(Boolean),
        risk: onb.risk,
        endpoint_url: onb.endpoint_url.trim() || null,
        timeout_ms: Number(onb.timeout_ms) || 3000,
      });
      setOnbMsg({ ok: true, text: `Onboarded “${spec.name}”` });
      setOnb({ name: '', description: '', actions: '', risk: 'medium', endpoint_url: '', timeout_ms: 3000 });
      setForm(f => ({ ...f, tool_name: spec.name }));
      refreshTools();
    } catch (e) {
      setOnbMsg({ ok: false, text: typeof e.message === 'string' ? e.message : 'Registration failed' });
    }
  };

  const removeTool = async (name) => {
    try { await api.tools.remove(name); refreshTools(); } catch (e) { /* keep UI responsive */ }
  };

  const run = async () => {
    setLoading(true);
    try {
      const res = await api.tools.call(form);
      const entry = { ...res, ...form, ts: new Date().toISOString() };
      setResult(res);
      setHistory(h => [entry, ...h].slice(0, 20));
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  const runDemo = (d) => {
    setForm(f => ({ ...f, tool_name: d.tool, action: d.action, input_text: d.input_text, agent_id: d.agent_id }));
    setTimeout(run, 50);
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Terminal size={22} color="var(--yellow)" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Tool Playground</h2>
          <p style={{ color: 'var(--text-2)', fontSize: 12 }}>Execute governed tool calls via <code>govern()</code> — see real policy decisions</p>
        </div>
      </div>

      {/* Demo shortcuts */}
      <div style={{ marginBottom: 20 }}>
        <div className="card-title">Quick Demo Calls</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {DEMO_CALLS.map(d => (
            <button key={d.label} className="btn btn-ghost" style={{ fontSize: 12 }}
              onClick={() => {
                setForm(f => ({ ...f, tool_name: d.tool, action: d.action, input_text: d.input_text, agent_id: d.agent_id }));
              }}>
              {d.label}
            </button>
          ))}
        </div>
      </div>

      {/* Onboard a real tool */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        <div className="card">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Plus size={14} /> Onboard a Tool for Evaluation
          </div>
          <p style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 12 }}>
            Register a real tool the platform will govern. Add an HTTP(S) endpoint to have
            allowed calls <strong>actually invoked</strong> (SSRF-guarded) and their real
            latency/success fed into the SLOs — or leave it blank for a governance-decision-only tool.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <label style={lbl}>Name</label>
              <input value={onb.name} onChange={e => setOnb(o => ({ ...o, name: e.target.value }))}
                placeholder="payments_api" style={{ width: '100%', marginBottom: 10 }} />
            </div>
            <div>
              <label style={lbl}>Risk</label>
              <select value={onb.risk} onChange={e => setOnb(o => ({ ...o, risk: e.target.value }))}
                style={{ width: '100%', marginBottom: 10 }}>
                {['low', 'medium', 'high', 'critical'].map(r => <option key={r}>{r}</option>)}
              </select>
            </div>
          </div>

          <label style={lbl}>Description</label>
          <input value={onb.description} onChange={e => setOnb(o => ({ ...o, description: e.target.value }))}
            placeholder="What the tool does" style={{ width: '100%', marginBottom: 10 }} />

          <label style={lbl}>Actions (comma-separated)</label>
          <input value={onb.actions} onChange={e => setOnb(o => ({ ...o, actions: e.target.value }))}
            placeholder="read, write, refund" style={{ width: '100%', marginBottom: 10 }} />

          <label style={lbl}>Endpoint URL (optional — real webhook)</label>
          <input value={onb.endpoint_url} onChange={e => setOnb(o => ({ ...o, endpoint_url: e.target.value }))}
            placeholder="https://example.com/hook" style={{ width: '100%', marginBottom: 10 }} />

          <label style={lbl}>Timeout (ms)</label>
          <input type="number" value={onb.timeout_ms} onChange={e => setOnb(o => ({ ...o, timeout_ms: e.target.value }))}
            style={{ width: '100%', marginBottom: 12 }} />

          {!allowPrivate && (
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 5 }}>
              <ShieldOff size={11} color="var(--yellow)" /> Private/loopback endpoints are blocked. Set <code>AGT_TOOL_ALLOW_PRIVATE=1</code> for local testing.
            </div>
          )}

          <button className="btn btn-primary" onClick={onboard} disabled={!onb.name.trim()}
            style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
            <Plus size={14} /> Onboard Tool
          </button>
          {onbMsg && (
            <div style={{ marginTop: 10, fontSize: 11, color: onbMsg.ok ? 'var(--green)' : 'var(--red)' }}>
              {onbMsg.text}
            </div>
          )}
        </div>

        {/* Registered tools */}
        <div className="card">
          <div className="card-title">Registered Tools</div>
          {registered.length === 0
            ? <div style={{ color: 'var(--text-3)', fontSize: 12 }}>No tools onboarded yet.</div>
            : <div style={{ maxHeight: 360, overflowY: 'auto' }}>
                {registered.map(t => (
                  <div key={t.name} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                    {t.endpoint_url
                      ? <Globe size={14} color="var(--green)" style={{ flexShrink: 0, marginTop: 3 }} />
                      : <Terminal size={14} color="var(--text-3)" style={{ flexShrink: 0, marginTop: 3 }} />}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <code style={{ fontSize: 12, fontWeight: 600 }}>{t.name}</code>
                        <span className={`tag ${RISK_TAG[t.risk] || 'warn'}`} style={{ fontSize: 9 }}>{t.risk}</span>
                        {t.builtin && <span style={{ fontSize: 9, color: 'var(--text-3)' }}>built-in</span>}
                        {t.endpoint_url
                          ? <span style={{ fontSize: 9, color: 'var(--green)' }}>webhook</span>
                          : <span style={{ fontSize: 9, color: 'var(--text-3)' }}>decision-only</span>}
                      </div>
                      {t.description && <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{t.description}</div>}
                      {t.endpoint_url && <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: 'var(--mono)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.endpoint_url}</div>}
                    </div>
                    {!t.builtin && (
                      <button className="btn btn-ghost" onClick={() => removeTool(t.name)}
                        title="Remove tool" style={{ padding: '2px 6px', flexShrink: 0 }}>
                        <Trash2 size={12} color="var(--red)" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
          }
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Form */}
        <div className="card">
          <div className="card-title">Configure Call</div>

          <label style={lbl}>Tool</label>
          <select value={form.tool_name} onChange={e => setForm(f => ({ ...f, tool_name: e.target.value }))}
            style={{ width: '100%', marginBottom: 12 }}>
            {(tools.available || []).map(t => <option key={t}>{t}</option>)}
          </select>

          <label style={lbl}>Action Type</label>
          <input value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}
            placeholder="read / drop / send_email / shell_exec…" style={{ width: '100%', marginBottom: 12 }} />

          <label style={lbl}>Input Text</label>
          <textarea value={form.input_text} onChange={e => setForm(f => ({ ...f, input_text: e.target.value }))}
            placeholder="Optional input content (PII patterns tested here)" style={{ width: '100%', marginBottom: 12, minHeight: 70 }} />

          <label style={lbl}>Agent ID</label>
          <input value={form.agent_id} onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))}
            style={{ width: '100%', marginBottom: 12 }} />

          <label style={lbl}>Policy</label>
          <select value={form.policy_name} onChange={e => setForm(f => ({ ...f, policy_name: e.target.value }))}
            style={{ width: '100%', marginBottom: 16 }}>
            {policies.map(p => <option key={p.name}>{p.name}</option>)}
          </select>

          <button className="btn btn-primary" onClick={run} disabled={loading}
            style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
            <Play size={14} /> {loading ? 'Executing…' : 'Execute Tool Call'}
          </button>
        </div>

        {/* Result */}
        <div>
          {result && (
            <div className="card animate-in" style={{ marginBottom: 16,
              borderColor: result.error ? 'var(--yellow)44' : result.allowed ? 'var(--green)44' : 'var(--red)44',
              background: result.error ? 'var(--yellow-dim)' : result.allowed ? 'var(--green-dim)' : 'var(--red-dim)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                {result.error
                  ? <span className="tag warn">ERROR</span>
                  : result.allowed
                    ? <><CheckCircle size={18} color="var(--green)" /><span className="tag allow">ALLOWED</span></>
                    : <><XCircle size={18} color="var(--red)" /><span className="tag deny">DENIED</span></>
                }
                {result.latency_ms && (
                  <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
                    <Clock size={11} /> {result.latency_ms}ms
                  </span>
                )}
              </div>

              {result.error && <code style={{ fontSize: 12, color: 'var(--yellow)' }}>{result.error}</code>}

              {/* which of the three gates decided */}
              {!result.error && (
                <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
                  {GATES.map(g => {
                    const denied = result.denied_by === g;
                    const passed = result.allowed || (!denied && !reached(result.denied_by, g));
                    return (
                      <span key={g} style={{
                        fontSize: 10, fontFamily: 'var(--mono)', padding: '2px 7px', borderRadius: 3,
                        border: `1px solid ${denied ? 'var(--red)' : passed ? 'var(--green)' : 'var(--border)'}`,
                        color: denied ? 'var(--red)' : passed ? 'var(--green)' : 'var(--text-3)',
                      }}>
                        {denied ? '✗' : passed ? '✓' : '·'} {GATE_LABEL[g]}
                      </span>
                    );
                  })}
                </div>
              )}

              {result.reason && <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 8 }}>{result.reason}</div>}
              {result.allowed && result.executed !== undefined && (
                <div style={{ fontSize: 11, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6,
                  color: result.executed ? (result.execution_ok ? 'var(--green)' : 'var(--red)') : 'var(--text-3)' }}>
                  {result.executed
                    ? (result.execution_ok
                        ? <><Globe size={12} /> Endpoint invoked — HTTP {result.result?.http_status}</>
                        : <><XCircle size={12} /> Endpoint call failed{result.result?.http_status ? ` — HTTP ${result.result.http_status}` : ''}{result.result?.error ? ` (${result.result.error})` : ''}</>)
                    : <>Governance decision only — no endpoint bound to this tool</>}
                </div>
              )}
              {result.result && (
                <pre style={{ fontSize: 11, color: 'var(--text)', background: 'var(--bg-3)', padding: 10, borderRadius: 6, overflow: 'auto' }}>
                  {JSON.stringify(result.result, null, 2)}
                </pre>
              )}
              <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-3)' }}>policy: {result.policy || form.policy_name}</div>
            </div>
          )}

          {/* History */}
          {history.length > 0 && (
            <div className="card">
              <div className="card-title">Call History</div>
              <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                {history.map((h, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
                    {h.allowed ? <CheckCircle size={13} color="var(--green)" /> : <XCircle size={13} color="var(--red)" />}
                    <code style={{ fontSize: 11 }}>{h.tool_name}({h.action})</code>
                    <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{h.agent_id}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Gates run runtime -> trust -> policy; anything after the denying gate never ran.
function reached(deniedBy, gate) {
  const order = GATES;
  if (!deniedBy) return false;
  return order.indexOf(gate) > order.indexOf(deniedBy);
}

const lbl = { display: 'block', fontSize: 11, color: 'var(--text-3)', marginBottom: 4, fontWeight: 600, letterSpacing: '.5px', textTransform: 'uppercase' };
