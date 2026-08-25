import { useState, useEffect } from 'react';
import { Lock, Play, Sliders } from 'lucide-react';
import { RadialBarChart, RadialBar, Cell, ResponsiveContainer } from 'recharts';
import { api } from '../api';

export default function TrustPanel() {
  const [overview, setOverview] = useState(null);
  const [form, setForm] = useState({ agent_id: 'research-agent', trust_score: 0.85, delegation_depth: 0, namespace: 'production' });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState({});

  const load = async () => {
    const ov = await api.trust.overview();
    setOverview(ov);
  };
  useEffect(() => { load(); }, []);

  const evaluate = async () => {
    setLoading(true);
    try {
      const res = await api.trust.evaluate(form);
      setResult(res);
    } catch (e) { setResult({ error: e.message }); }
    setLoading(false);
  };

  const updateScore = async (agent_id, score) => {
    setUpdating(u => ({ ...u, [agent_id]: true }));
    try {
      await api.trust.update(agent_id, score);
      load();
    } catch {}
    setUpdating(u => ({ ...u, [agent_id]: false }));
  };

  const color = (s) => s >= 0.8 ? 'var(--green)' : s >= 0.5 ? 'var(--yellow)' : 'var(--red)';

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Lock size={22} color="var(--purple)" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Trust & Identity</h2>
          <p style={{ color: 'var(--text-2)', fontSize: 12 }}>
            TrustPolicy evaluation via <code>PolicyEvaluator</code> with <code>TrustCondition</code> rules
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
        {/* Agent trust scores */}
        <div className="card">
          <div className="card-title">Agent Trust Scores</div>
          {(overview?.agents || []).map(a => (
            <div key={a.agent_id} style={{ marginBottom: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{a.agent_id}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={`tag ${a.level === 'high' ? 'allow' : a.level === 'medium' ? 'warn' : 'deny'}`}>
                    {a.level}
                  </span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: color(a.trust_score) }}>
                    {(a.trust_score * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <input
                  type="range" min="0" max="100" step="1"
                  defaultValue={Math.round(a.trust_score * 100)}
                  style={{ flex: 1, accentColor: color(a.trust_score) }}
                  onMouseUp={e => updateScore(a.agent_id, e.target.value / 100)}
                />
                {updating[a.agent_id] && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>saving…</span>}
              </div>
            </div>
          ))}
        </div>

        {/* Evaluator */}
        <div className="card">
          <div className="card-title">Evaluate Trust Policy</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label style={lbl}>Agent ID</label>
              <input value={form.agent_id} onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))} style={{ width: '100%' }} />
            </div>
            <div>
              <label style={lbl}>Trust Score: {form.trust_score}</label>
              <input type="range" min="0" max="1" step="0.01" value={form.trust_score}
                onChange={e => setForm(f => ({ ...f, trust_score: parseFloat(e.target.value) }))}
                style={{ width: '100%', accentColor: color(form.trust_score) }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-3)' }}>
                <span>0 — untrusted</span><span>0.6 — threshold</span><span>1.0 — full trust</span>
              </div>
            </div>
            <div>
              <label style={lbl}>Delegation Depth</label>
              <input type="number" min="0" max="5" value={form.delegation_depth}
                onChange={e => setForm(f => ({ ...f, delegation_depth: parseInt(e.target.value) }))} style={{ width: '100%' }} />
            </div>
            <div>
              <label style={lbl}>Namespace</label>
              <input value={form.namespace} onChange={e => setForm(f => ({ ...f, namespace: e.target.value }))} style={{ width: '100%' }} />
            </div>
            <button className="btn btn-primary" onClick={evaluate} disabled={loading}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
              <Play size={13} /> {loading ? 'Evaluating…' : 'Run Trust Evaluation'}
            </button>
          </div>

          {result && (
            <div className="animate-in" style={{
              marginTop: 16, padding: 12, borderRadius: 8,
              background: result.error ? 'var(--yellow-dim)' : result.allowed ? 'var(--green-dim)' : 'var(--red-dim)',
              border: `1px solid ${result.error ? 'var(--yellow)' : result.allowed ? 'var(--green)' : 'var(--red)'}44`,
            }}>
              {result.error
                ? <code style={{ color: 'var(--yellow)', fontSize: 12 }}>{result.error}</code>
                : <>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                      <span className={`tag ${result.allowed ? 'allow' : 'deny'}`}>{result.action?.toUpperCase()}</span>
                      {result.rule_name && <code style={{ fontSize: 11, color: 'var(--text-2)' }}>{result.rule_name}</code>}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{result.reason}</div>
                  </>
              }
            </div>
          )}
        </div>
      </div>

      {/* How it works */}
      <div className="card">
        <div className="card-title">How Trust Policy Works</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 16 }}>
          {[
            { title: 'TrustCondition', code: 'field="trust_score"\noperator=ConditionOperator.lt\nvalue=0.6', desc: 'Dot-notated field paths compared via typed operators' },
            { title: 'TrustRule', code: 'name="deny-low-trust"\ncondition=TrustCondition(...)\naction="deny"\npriority=5', desc: 'First-match wins; lower priority number = higher precedence' },
            { title: 'PolicyEvaluator', code: 'evaluator = PolicyEvaluator(\n  policies=[trust_policy]\n)\ndecision = evaluator.evaluate(ctx)', desc: 'Returns TrustPolicyDecision with allowed, rule_name, reason' },
          ].map(({ title, code, desc }) => (
            <div key={title} style={{ background: 'var(--bg-3)', borderRadius: 8, padding: 14 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8, color: 'var(--purple)' }}>{title}</div>
              <pre style={{ fontSize: 10, color: 'var(--text-2)', marginBottom: 8, whiteSpace: 'pre-wrap' }}>{code}</pre>
              <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const lbl = { display: 'block', fontSize: 11, color: 'var(--text-3)', marginBottom: 4, fontWeight: 600, letterSpacing: '.5px', textTransform: 'uppercase' };
