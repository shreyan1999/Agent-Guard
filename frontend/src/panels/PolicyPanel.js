import { useState, useEffect } from 'react';
import { Plus, Trash2, Play, Shield, ChevronDown, ChevronUp } from 'lucide-react';
import { api } from '../api';
import ConditionBuilder from './policy/ConditionBuilder';

export default function PolicyPanel() {
  const [policies, setPolicies] = useState([]);
  const [selected, setSelected] = useState(null);
  const [evalForm, setEvalForm] = useState({ action: 'read', input_text: 'User SSN: 123-45-6789', agent_id: 'data-agent' });
  const [evalResult, setEvalResult] = useState(null);
  const [evalLoading, setEvalLoading] = useState(false);
  const [newPolicy, setNewPolicy] = useState({ name: '', default_action: 'allow', rules: [] });
  const [showCreate, setShowCreate] = useState(false);
  const [newRule, setNewRule] = useState({ name: '', condition: '', action: 'deny', description: '', priority: 50 });
  const [msg, setMsg] = useState('');
  // The grammar the builder is allowed to offer, straight from the backend.
  const [schema, setSchema] = useState(null);

  const load = async () => {
    const list = await api.policies.list();
    setPolicies(list);
    if (!selected && list.length) setSelected(list[0].name);
  };

  useEffect(() => { load(); }, []);
  useEffect(() => { api.policies.schema().then(setSchema).catch(() => {}); }, []);

  const evaluate = async () => {
    setEvalLoading(true);
    setEvalResult(null);
    try {
      const res = await api.policies.evaluate({ policy_name: selected, ...evalForm });
      setEvalResult(res);
    } catch (e) {
      setMsg(e.message);
    }
    setEvalLoading(false);
  };

  const createPolicy = async () => {
    if (!newPolicy.name) return setMsg('Policy name required');
    try {
      await api.policies.create(newPolicy);
      setMsg('Policy created');
      setShowCreate(false);
      setNewPolicy({ name: '', default_action: 'allow', rules: [] });
      load();
    } catch (e) {
      // A rejected policy returns structured lint output, not a plain string.
      const d = e.message;
      if (d && typeof d === 'object' && d.warnings) {
        setMsg(`${d.error}: ` + d.warnings.map(w => `${w.rule} (${w.unparsable.join(', ')})`).join('; ') + ` \u2014 ${d.grammar}`);
      } else {
        setMsg(typeof d === 'string' ? d : JSON.stringify(d));
      }
    }
  };

  const deletePolicy = async (name) => {
    if (!window.confirm(`Delete policy "${name}"?`)) return;
    try {
      await api.policies.delete(name);
      setMsg('Deleted');
      if (selected === name) setSelected(null);
      load();
    } catch (e) { setMsg(e.message); }
  };

  const addRuleToNew = () => {
    if (!newRule.name || !newRule.condition) return setMsg('Rule name and condition required');
    setNewPolicy(p => ({ ...p, rules: [...p.rules, { ...newRule }] }));
    setNewRule({ name: '', condition: '', action: 'deny', description: '', priority: 50 });
  };

  const sel = policies.find(p => p.name === selected);
  const elbl = { display: 'block', fontSize: 11, color: 'var(--text-3)', marginBottom: 4,
    fontWeight: 600, letterSpacing: '.5px', textTransform: 'uppercase' };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Shield size={22} color="var(--accent)" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Policy Engine</h2>
          <p style={{ color: 'var(--text-2)', fontSize: 12 }}>Create YAML governance policies and evaluate them against real contexts</p>
        </div>
        <button className="btn btn-primary" style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}
          onClick={() => setShowCreate(v => !v)}>
          <Plus size={14} /> New Policy
        </button>
      </div>

      {msg && (
        <div style={{ padding: '10px 14px', background: 'var(--accent-dim)', border: '1px solid var(--accent)33', borderRadius: 6, marginBottom: 16, fontSize: 12, color: 'var(--accent)' }}>
          {msg} <button style={{ float: 'right', background: 'none', color: 'var(--text-3)', fontSize: 12 }} onClick={() => setMsg('')}>✕</button>
        </div>
      )}

      {/* Create Form */}
      {showCreate && (
        <div className="card animate-in" style={{ marginBottom: 20 }}>
          <div className="card-title">Create Policy</div>
          <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
            <input placeholder="Policy name" value={newPolicy.name}
              onChange={e => setNewPolicy(p => ({ ...p, name: e.target.value }))} style={{ flex: 1, minWidth: 160 }} />
            <select value={newPolicy.default_action}
              onChange={e => setNewPolicy(p => ({ ...p, default_action: e.target.value }))}>
              <option value="allow">default: allow</option>
              <option value="deny">default: deny</option>
            </select>
          </div>

          {/* Rules builder */}
          <div style={{ marginBottom: 12 }}>
            <div className="card-title" style={{ marginBottom: 8 }}>Rules</div>
            {newPolicy.rules.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                <span className={`tag ${r.action === 'allow' ? 'allow' : r.action === 'deny' ? 'deny' : 'warn'}`}>{r.action}</span>
                <code style={{ color: 'var(--text-2)', fontSize: 11 }}>{r.name}</code>
                <code style={{ color: 'var(--text-3)', fontSize: 11, flex: 1 }}>{r.condition}</code>
                <button onClick={() => setNewPolicy(p => ({ ...p, rules: p.rules.filter((_, j) => j !== i) }))}
                  style={{ background: 'none', color: 'var(--red)', fontSize: 16, lineHeight: 1 }}>×</button>
              </div>
            ))}
            <div style={{ marginTop: 12, padding: 12, borderRadius: 8,
              background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                <input placeholder="rule name" value={newRule.name}
                  onChange={e => setNewRule(r => ({ ...r, name: e.target.value }))}
                  style={{ flex: '1 1 160px', minWidth: 140 }} />
                <select value={newRule.action}
                  onChange={e => setNewRule(r => ({ ...r, action: e.target.value }))}>
                  {(schema?.actions || ['deny', 'allow', 'warn', 'require_approval'])
                    .map(a => <option key={a}>{a}</option>)}
                </select>
                <input type="number" value={newRule.priority} title="Priority"
                  onChange={e => setNewRule(r => ({ ...r, priority: Number(e.target.value) }))}
                  style={{ width: 84 }} />
              </div>

              <ConditionBuilder
                schema={schema}
                value={newRule.condition}
                onChange={condition => setNewRule(r => ({ ...r, condition }))}
              />

              <button className="btn btn-ghost" onClick={addRuleToNew}
                disabled={!newRule.name || !newRule.condition}
                style={{ marginTop: 12 }}>
                + Add Rule
              </button>
            </div>
          </div>

          <button className="btn btn-primary" onClick={createPolicy}>Create Policy</button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 20 }}>
        {/* Policy list */}
        <div>
          <div className="card-title" style={{ marginBottom: 8 }}>Loaded Policies</div>
          {policies.map(p => (
            <div key={p.name}
              onClick={() => setSelected(p.name)}
              style={{
                padding: '10px 14px', borderRadius: 8, marginBottom: 6, cursor: 'pointer',
                background: selected === p.name ? 'var(--accent-dim)' : 'var(--bg-2)',
                border: `1px solid ${selected === p.name ? 'var(--accent)33' : 'var(--border)'}`,
                transition: 'all .15s',
              }}
            >
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{p.name}</div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className={`tag ${p.default_action === 'allow' ? 'allow' : 'deny'}`} style={{ fontSize: 10 }}>
                  {p.default_action}
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{(p.rules || []).length} rules</span>
              </div>
              {p.name !== 'default-policy' && (
                <button
                  onClick={e => { e.stopPropagation(); deletePolicy(p.name); }}
                  style={{ marginTop: 8, background: 'none', color: 'var(--red)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Trash2 size={11} /> Delete
                </button>
              )}
            </div>
          ))}
        </div>

        {/* Policy detail + evaluator */}
        <div>
          {sel && (
            <>
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-title">
                  Rules — {sel.name}
                  <span style={{ marginLeft: 8, fontWeight: 400, color: 'var(--text-3)' }}>
                    evaluated highest priority first
                  </span>
                </div>
                {(sel.warnings || []).length > 0 && (
                  <div style={{ padding: '10px 12px', marginBottom: 12, borderRadius: 6,
                    background: 'var(--yellow-dim)', border: '1px solid var(--yellow)44' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--yellow)', marginBottom: 4 }}>
                      {sel.warnings.length} rule{sel.warnings.length > 1 ? 's' : ''} cannot be evaluated by AGT
                    </div>
                    {sel.warnings.map(w => (
                      <div key={w.rule} style={{ fontSize: 11, color: 'var(--text-2)' }}>
                        <code>{w.rule}</code> — {w.effect}
                      </div>
                    ))}
                  </div>
                )}
                {(sel.rules || []).length === 0
                  ? <div style={{ color: 'var(--text-3)', fontSize: 12 }}>No rules — all actions use default: {sel.default_action}</div>
                  : (sel.rules || []).map((r, i) => (
                    <div key={i} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                      <span className={`tag ${r.action === 'allow' ? 'allow' : r.action === 'deny' ? 'deny' : 'warn'}`} style={{ flexShrink: 0 }}>
                        {r.action}
                      </span>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 2 }}>{r.name}</div>
                        <code style={{ fontSize: 11, color: 'var(--text-2)' }}>{r.condition}</code>
                        {r.description && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{r.description}</div>}
                      </div>
                      <span title="Higher priority is evaluated first"
                        style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-3)', flexShrink: 0 }}>
                        p={r.priority}
                      </span>
                    </div>
                  ))
                }
              </div>

              {/* Evaluator */}
              <div className="card">
                <div className="card-title">Evaluate Policy</div>
                <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--text-2)' }}>
                  Evaluated by the same <code>PolicyEngine</code> instance the Tool Playground
                  enforces with, on a context built the same way — the two cannot disagree.
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
                  <div>
                    <label style={elbl}>Action</label>
                    <input value={evalForm.action}
                      onChange={e => setEvalForm(f => ({ ...f, action: e.target.value }))}
                      style={{ width: '100%' }} />
                  </div>
                  <div>
                    <label style={elbl}>Agent</label>
                    <input value={evalForm.agent_id}
                      onChange={e => setEvalForm(f => ({ ...f, agent_id: e.target.value }))}
                      style={{ width: '100%' }} />
                  </div>
                </div>
                <label style={elbl}>Input Text</label>
                <textarea
                  value={evalForm.input_text}
                  onChange={e => setEvalForm(f => ({ ...f, input_text: e.target.value }))}
                  style={{ width: '100%', marginBottom: 12, fontFamily: 'var(--mono)', fontSize: 12, minHeight: 64 }}
                />
                <button className="btn btn-primary" onClick={evaluate} disabled={evalLoading}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: evalResult ? 16 : 0 }}>
                  <Play size={13} /> {evalLoading ? 'Evaluating…' : 'Evaluate'}
                </button>

                {evalResult && (
                  <div className="animate-in" style={{
                    marginTop: 14, padding: 14, borderRadius: 8,
                    background: evalResult.allowed ? 'var(--green-dim)' : 'var(--red-dim)',
                    border: `1px solid ${evalResult.allowed ? 'var(--green)' : 'var(--red)'}44`,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                      <span className={`tag ${evalResult.allowed ? 'allow' : 'deny'}`} style={{ fontSize: 13 }}>
                        {evalResult.action?.toUpperCase()}
                      </span>
                      {evalResult.rule_name && (
                        <code style={{ fontSize: 12, color: 'var(--text-2)' }}>rule: {evalResult.rule_name}</code>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 10 }}>{evalResult.reason}</div>

                    <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>
                      Policy gate only. {(evalResult.other_gates || []).join(', ')} run first and can
                      still deny a call this allows.
                    </div>

                    {evalResult.context && (
                      <details>
                        <summary style={{ fontSize: 11, color: 'var(--text-3)', cursor: 'pointer' }}>
                          Context the rules were evaluated against
                        </summary>
                        <pre style={{ fontSize: 11, background: 'var(--bg-3)', padding: 10, borderRadius: 6,
                          overflow: 'auto', marginTop: 8 }}>
                          {JSON.stringify(evalResult.context, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
