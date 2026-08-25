import { useState, useEffect } from 'react';
import { Users, Plus, Fingerprint, Cloud } from 'lucide-react';
import { api } from '../api';

const EMPTY_FORM = { id: '', name: '', trust_score: 0.8, policy: 'default-policy', project_endpoint: '', foundry_agent_id: '' };

export default function AgentsPanel() {
  const [agents, setAgents] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [showCreate, setShowCreate] = useState(false);
  const [msg, setMsg] = useState('');
  const [syncFor, setSyncFor] = useState(null);
  const [syncText, setSyncText] = useState('');
  const [syncing, setSyncing] = useState(false);

  const load = async () => {
    const [ag, po] = await Promise.all([api.agents.list(), api.policies.list()]);
    setAgents(ag);
    setPolicies(po);
  };
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!form.id || !form.name) return setMsg('ID and name required');
    try {
      const created = await api.agents.create(form);
      setMsg(created?.did
        ? `Agent registered · identity ${created.did} (private key issued once)`
        : 'Agent registered');
      setForm(EMPTY_FORM);
      setShowCreate(false);
      load();
    } catch (e) { setMsg(e.message); }
  };

  const del = async (id) => {
    if (!window.confirm(`Remove agent ${id}?`)) return;
    await api.agents.delete(id);
    load();
  };

  const openSync = (id) => { setSyncFor(id); setSyncText(''); };

  const doSync = async () => {
    let steps;
    try {
      steps = JSON.parse(syncText);
    } catch (e) {
      return setMsg('Run steps must be valid JSON');
    }
    if (!Array.isArray(steps)) return setMsg('Paste a JSON array of run steps');
    setSyncing(true);
    try {
      const r = await api.agents.foundrySync(syncFor, steps);
      setMsg(`Synced ${syncFor} · ${r.accepted} tool call(s), ${r.denied_reported} failed`);
      setSyncFor(null);
      setSyncText('');
      load();
    } catch (e) {
      setMsg(e.message);
    } finally {
      setSyncing(false);
    }
  };

  const tc = (s) => s >= 0.8 ? 'var(--green)' : s >= 0.5 ? 'var(--yellow)' : 'var(--red)';

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Users size={22} color="var(--accent)" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Agents</h2>
          <p style={{ color: 'var(--text-2)', fontSize: 12 }}>Register, inspect, and manage agents in the governance mesh</p>
        </div>
        <button className="btn btn-primary" style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}
          onClick={() => setShowCreate(v => !v)}>
          <Plus size={14} /> Register Agent
        </button>
      </div>

      {msg && (
        <div style={{ padding: '10px 14px', background: 'var(--accent-dim)', borderRadius: 6, marginBottom: 16, fontSize: 12, color: 'var(--accent)' }}>
          {msg} <button onClick={() => setMsg('')} style={{ float: 'right', background: 'none', color: 'var(--text-3)' }}>✕</button>
        </div>
      )}

      {showCreate && (
        <div className="card animate-in" style={{ marginBottom: 20 }}>
          <div className="card-title">Register New Agent</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <label style={lbl}>Agent ID</label>
              <input value={form.id} onChange={e => setForm(f => ({ ...f, id: e.target.value }))}
                placeholder="my-agent-1" style={{ width: '100%' }} />
            </div>
            <div>
              <label style={lbl}>Display Name</label>
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="My Agent" style={{ width: '100%' }} />
            </div>
            <div>
              <label style={lbl}>Trust Score: {form.trust_score}</label>
              <input type="range" min="0" max="1" step="0.01" value={form.trust_score}
                onChange={e => setForm(f => ({ ...f, trust_score: parseFloat(e.target.value) }))}
                style={{ width: '100%', accentColor: tc(form.trust_score) }} />
            </div>
            <div>
              <label style={lbl}>Policy</label>
              <select value={form.policy} onChange={e => setForm(f => ({ ...f, policy: e.target.value }))} style={{ width: '100%' }}>
                {policies.map(p => <option key={p.name}>{p.name}</option>)}
              </select>
            </div>
          </div>
          <div style={{ borderTop: '1px solid var(--bg-4)', paddingTop: 12, marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '.5px', fontWeight: 600 }}>
              <Cloud size={12} color="var(--accent)" /> Azure AI Foundry (optional)
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={lbl}>Project Endpoint</label>
                <input value={form.project_endpoint} onChange={e => setForm(f => ({ ...f, project_endpoint: e.target.value }))}
                  placeholder="https://<res>.services.ai.azure.com/api/projects/<project>" style={{ width: '100%' }} />
              </div>
              <div>
                <label style={lbl}>Foundry Agent ID</label>
                <input value={form.foundry_agent_id} onChange={e => setForm(f => ({ ...f, foundry_agent_id: e.target.value }))}
                  placeholder="asst_abc123" style={{ width: '100%' }} />
              </div>
            </div>
            <p style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 8 }}>
              Link a Foundry agent to stream its run-step telemetry from the card. Descriptive only — the backend never calls Azure.
            </p>
          </div>
          <button className="btn btn-primary" onClick={create}>Register Agent</button>
        </div>
      )}

      {/* Agent grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(280px,1fr))', gap: 16 }}>
        {agents.map(a => (
          <div key={a.id} className="card" style={{ position: 'relative' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
              <div>
                <div style={{ fontFamily: 'var(--mono)', fontWeight: 600, fontSize: 13 }}>{a.id}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.name}</div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span className={`tag ${a.status === 'active' ? 'allow' : 'deny'}`}>{a.status}</span>
                <button onClick={() => del(a.id)} style={{ background: 'none', color: 'var(--red)', fontSize: 16 }}>×</button>
              </div>
            </div>

            {/* Trust bar */}
            <div style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>
                <span>Trust Score</span>
                <span style={{ fontFamily: 'var(--mono)', color: tc(a.trust_score) }}>{(a.trust_score * 100).toFixed(0)}%</span>
              </div>
              <div style={{ height: 5, background: 'var(--bg-4)', borderRadius: 3 }}>
                <div style={{ width: `${a.trust_score * 100}%`, height: '100%', background: tc(a.trust_score), borderRadius: 3 }} />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
              {[
                { label: 'Policy', value: a.policy },
                { label: 'Calls', value: a.calls },
                { label: 'Denials', value: a.denials },
              ].map(({ label, value }) => (
                <div key={label} style={{ textAlign: 'center', background: 'var(--bg-3)', borderRadius: 6, padding: '6px 8px' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '.5px', marginBottom: 2 }}>{label}</div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 10, fontSize: 10, color: 'var(--text-3)' }}>
              Created: {new Date(a.created_at).toLocaleString()}
            </div>
            {a.did && (
              <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-3)' }}
                title={a.did}>
                <Fingerprint size={11} color="var(--accent)" />
                <code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.did}</code>
              </div>
            )}
            {a.foundry && (
              <div style={{ marginTop: 10, borderTop: '1px solid var(--bg-4)', paddingTop: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-3)', marginBottom: 8 }}
                  title={a.foundry.project_endpoint}>
                  <Cloud size={11} color="var(--accent)" />
                  <code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.foundry.foundry_agent_id || 'Foundry'}
                  </code>
                </div>
                <button className="btn" style={{ width: '100%', fontSize: 11 }} onClick={() => openSync(a.id)}>
                  Sync from Foundry
                </button>
              </div>
            )}
          </div>
        ))}
      </div>

      {syncFor && (
        <div style={overlay} onClick={() => !syncing && setSyncFor(null)}>
          <div className="card" style={{ width: 'min(680px, 92vw)', maxHeight: '86vh', overflow: 'auto' }} onClick={e => e.stopPropagation()}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Cloud size={16} color="var(--accent)" /> Sync run steps — {syncFor}
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 10 }}>
              Paste the run steps exported from Foundry:
              <code style={{ display: 'block', marginTop: 6, fontSize: 11, color: 'var(--text-3)' }}>
                [s.as_dict() for s in project.agents.run_steps.list(thread_id=..., run_id=...)]
              </code>
            </p>
            <textarea value={syncText} onChange={e => setSyncText(e.target.value)}
              placeholder='[ { "type": "tool_calls", "status": "completed", ... } ]'
              style={{ width: '100%', height: 240, fontFamily: 'var(--mono)', fontSize: 12 }} />
            <div style={{ display: 'flex', gap: 8, marginTop: 12, justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setSyncFor(null)} disabled={syncing}>Cancel</button>
              <button className="btn btn-primary" onClick={doSync} disabled={syncing || !syncText.trim()}>
                {syncing ? 'Syncing…' : 'Sync telemetry'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const overlay = { position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50, padding: 20 };

const lbl = { display: 'block', fontSize: 11, color: 'var(--text-3)', marginBottom: 4, fontWeight: 600, letterSpacing: '.5px', textTransform: 'uppercase' };
