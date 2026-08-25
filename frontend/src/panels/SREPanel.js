import { useState, useEffect } from 'react';
import { Zap, Power, Play, TrendingUp, TrendingDown, AlertTriangle } from 'lucide-react';
import { api } from '../api';

export default function SREPanel() {
  const [slos, setSlos] = useState([]);
  const [agents, setAgents] = useState([]);
  const [newSlo, setNewSlo] = useState({ agent_id: '', slo_name: '', target: 0.99 });
  const [msg, setMsg] = useState('');

  const load = async () => {
    const [sl, ag] = await Promise.all([api.sre.slos(), api.agents.list()]);
    setSlos(sl);
    setAgents(ag);
  };
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  const signal = async (id, success) => {
    await api.sre.signal(id, success);
    load();
  };

  const kill = async (id) => {
    await api.sre.kill(id);
    setMsg(`Kill switch activated for ${id}`);
    load();
  };

  const resume = async (id) => {
    await api.sre.resume(id);
    setMsg(`${id} resumed`);
    load();
  };

  const createSlo = async () => {
    if (!newSlo.agent_id || !newSlo.slo_name) return setMsg('Agent ID and SLO name required');
    await api.sre.createSlo(newSlo);
    setMsg('SLO created');
    setNewSlo({ agent_id: '', slo_name: '', target: 0.99 });
    load();
  };

  const budgetColor = (pct) => pct <= 20 ? 'var(--red)' : pct <= 40 ? 'var(--yellow)' : 'var(--green)';
  const statusColor = (s) => s === 'healthy' ? 'var(--green)'
    : s === 'warning' ? 'var(--yellow)'
    : (s === 'critical' || s === 'exhausted') ? 'var(--red)'
    : 'var(--text-3)';
  const statusTag = (s) => s === 'healthy' ? 'allow'
    : s === 'warning' ? 'warn'
    : (s === 'critical' || s === 'exhausted') ? 'deny' : '';

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Zap size={22} color="var(--red)" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Agent SRE</h2>
          <p style={{ color: 'var(--text-2)', fontSize: 12 }}>
            Kill switch · real <code>agent_sre</code> SLOs, error budgets and burn rate
          </p>
        </div>
      </div>

      {msg && (
        <div style={{ padding: '10px 14px', background: 'var(--accent-dim)', borderRadius: 6, marginBottom: 16, fontSize: 12, color: 'var(--accent)' }}>
          {msg} <button onClick={() => setMsg('')} style={{ float: 'right', background: 'none', color: 'var(--text-3)' }}>✕</button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
        {/* Agent kill switch */}
        <div className="card">
          <div className="card-title">Agent Kill Switch</div>
          {agents.map(a => (
            <div key={a.id} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 0', borderBottom: '1px solid var(--border)'
            }}>
              <div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{a.id}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
                  trust: {(a.trust_score * 100).toFixed(0)}% · calls: {a.calls}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span className={`tag ${a.status === 'active' ? 'allow' : 'deny'}`}>{a.status}</span>
                {a.status === 'active'
                  ? <button className="btn btn-danger" style={{ padding: '5px 12px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
                      onClick={() => kill(a.id)}>
                      <Power size={11} /> Kill
                    </button>
                  : <button className="btn btn-ghost" style={{ padding: '5px 12px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
                      onClick={() => resume(a.id)}>
                      <Play size={11} /> Resume
                    </button>
                }
              </div>
            </div>
          ))}
        </div>

        {/* Create SLO */}
        <div className="card">
          <div className="card-title">Create / Reset SLO</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label style={lbl}>Agent ID</label>
              <select value={newSlo.agent_id} onChange={e => setNewSlo(s => ({ ...s, agent_id: e.target.value }))} style={{ width: '100%' }}>
                <option value="">Select agent</option>
                {agents.map(a => <option key={a.id}>{a.id}</option>)}
              </select>
            </div>
            <div>
              <label style={lbl}>SLO Name</label>
              <input value={newSlo.slo_name} onChange={e => setNewSlo(s => ({ ...s, slo_name: e.target.value }))}
                placeholder="e.g. research-agent-reliability" style={{ width: '100%' }} />
            </div>
            <div>
              <label style={lbl}>Task-success target: {(newSlo.target * 100).toFixed(1)}%</label>
              <input type="range" min="0.9" max="0.9999" step="0.0001" value={newSlo.target}
                onChange={e => setNewSlo(s => ({ ...s, target: parseFloat(e.target.value) }))}
                style={{ width: '100%', accentColor: 'var(--green)' }} />
            </div>
            <button className="btn btn-primary" onClick={createSlo}>Create / Reset SLO</button>
          </div>
        </div>
      </div>

      {/* SLO Cards */}
      <div className="card-title" style={{ marginBottom: 12 }}>Active SLOs (agent_sre)</div>
      {slos.length === 0 && (
        <div style={{ color: 'var(--text-3)', fontSize: 12 }}>No SLOs yet. Create one above, or make a governed tool call to start recording measurements.</div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(320px,1fr))', gap: 16 }}>
        {slos.map(s => {
          const eb = s.error_budget || {};
          const remaining = eb.remaining_percent ?? 100;
          const agentId = s.agent_id;
          const alerts = eb.firing_alerts || [];
          return (
            <div key={s.name} className="card" style={{ borderColor: `${statusColor(s.status)}44` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{s.name}</div>
                  {agentId && <code style={{ fontSize: 10, color: 'var(--text-3)' }}>{agentId}</code>}
                </div>
                <span className={`tag ${statusTag(s.status)}`}>{s.status}</span>
              </div>

              {/* Error budget */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>
                  <span>Error Budget Remaining</span>
                  <span style={{ fontFamily: 'var(--mono)', color: budgetColor(remaining) }}>{remaining.toFixed(1)}%</span>
                </div>
                <div style={{ height: 6, background: 'var(--bg-4)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${remaining}%`, height: '100%', background: budgetColor(remaining), borderRadius: 3, transition: 'width .5s' }} />
                </div>
                {typeof eb.burn_rate === 'number' && (
                  <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>
                    burn rate: {eb.burn_rate.toFixed(2)}× {eb.is_exhausted && '· EXHAUSTED'}
                  </div>
                )}
              </div>

              {/* Indicators */}
              <div style={{ marginBottom: 12 }}>
                {(s.indicators || []).map(ind => {
                  const compliant = ind.compliance != null ? ind.compliance >= 1 : null;
                  const pct = ind.compliance != null ? (ind.compliance * 100).toFixed(0) : '—';
                  return (
                    <div key={ind.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, padding: '4px 0' }}>
                      <span style={{ color: 'var(--text-2)' }}>{ind.name}</span>
                      <span style={{ fontFamily: 'var(--mono)', color: compliant === null ? 'var(--text-3)' : compliant ? 'var(--green)' : 'var(--red)' }}>
                        {ind.measurement_count === 0 ? 'no data' : `${pct}% · n=${ind.measurement_count}`}
                      </span>
                    </div>
                  );
                })}
              </div>

              {/* Firing alerts */}
              {alerts.length > 0 && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
                  {alerts.map(a => (
                    <span key={a} className="tag deny" style={{ fontSize: 9, display: 'flex', alignItems: 'center', gap: 3 }}>
                      <AlertTriangle size={9} /> {a}
                    </span>
                  ))}
                </div>
              )}

              {/* Signal buttons */}
              {agentId && (
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-ghost" style={{ flex: 1, fontSize: 11, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                    onClick={() => signal(agentId, true)}>
                    <TrendingUp size={11} color="var(--green)" /> Success
                  </button>
                  <button className="btn btn-ghost" style={{ flex: 1, fontSize: 11, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                    onClick={() => signal(agentId, false)}>
                    <TrendingDown size={11} color="var(--red)" /> Failure
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const lbl = { display: 'block', fontSize: 11, color: 'var(--text-3)', marginBottom: 4, fontWeight: 600, letterSpacing: '.5px', textTransform: 'uppercase' };
