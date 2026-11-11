import { useState, useEffect } from 'react';
import { Plus, Trash2, Play, AlertTriangle, X, Pencil, FileCode, GitMerge, ListTree, CheckCircle, FlaskConical } from '../icons';
import { api } from '../api';
import ConditionBuilder from './policy/ConditionBuilder';
import { PageHeader, Panel, Modal, Badge, Field, Notice, Empty, actionTone } from '../ui';

export default function PolicyPanel() {
  const [policies, setPolicies] = useState([]);
  const [selected, setSelected] = useState(null);
  const [evalForm, setEvalForm] = useState({ action: 'read', input_text: 'User SSN: 123-45-6789', agent_id: 'data-agent' });
  const [evalResult, setEvalResult] = useState(null);
  const [evalLoading, setEvalLoading] = useState(false);
  // extends / conflict_strategy / scope were accepted by the backend from the
  // start; the form simply never offered them.
  const EMPTY_POLICY = {
    name: '', default_action: 'allow', rules: [],
    extends: [], conflict_strategy: '', scope: '',
  };
  const [newPolicy, setNewPolicy] = useState(EMPTY_POLICY);
  const [showCreate, setShowCreate] = useState(false);
  // The create form is two steps: details, then rules.
  const [step, setStep] = useState(1);
  // Editing reuses the same modal; the only difference is PUT instead of POST.
  const [editing, setEditing] = useState('');
  // Which view of the selected policy: what was authored, what AGT resolves it
  // to after inheritance, or the file itself.
  const [view, setView] = useState('rules');
  const [resolved, setResolved] = useState(null);
  const [yaml, setYaml] = useState(null);
  // Checked before saving rather than discovered by a 400 afterwards.
  const [validation, setValidation] = useState(null);
  // What this draft would change if it were saved.
  const [shadow, setShadow] = useState(null);
  const [shadowing, setShadowing] = useState(false);
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

  // The resolved and YAML views are fetched per policy, not held with the list:
  // resolution depends on the parents, which can change under it.
  useEffect(() => {
    setResolved(null); setYaml(null); setView('rules');
    if (!selected) return;
    api.policies.resolved(selected).then(setResolved).catch(() => setResolved({ error: true }));
    api.policies.yaml(selected).then(setYaml).catch(() => setYaml({ error: true }));
  }, [selected]);

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

  // Optional fields are omitted rather than sent empty: an empty scope is not
  // the same request as scope "global".
  const policyBody = () => ({
    name: newPolicy.name,
    default_action: newPolicy.default_action,
    rules: newPolicy.rules,
    ...(newPolicy.extends.length ? { extends: newPolicy.extends } : {}),
    ...(newPolicy.conflict_strategy ? { conflict_strategy: newPolicy.conflict_strategy } : {}),
    ...(newPolicy.scope ? { scope: newPolicy.scope } : {}),
  });

  const savePolicy = async () => {
    if (!newPolicy.name) return setMsg('Policy name required');
    try {
      if (editing) {
        await api.policies.update(editing, policyBody());
        setMsg(`Policy ${editing} updated — the change is in force from the next call.`);
      } else {
        await api.policies.create(policyBody());
        setMsg('Policy created');
      }
      setShowCreate(false);
      setEditing('');
      setValidation(null);
      setShadow(null);
      setNewPolicy(EMPTY_POLICY);
      load();
      if (editing === selected) {
        api.policies.resolved(selected).then(setResolved).catch(() => {});
        api.policies.yaml(selected).then(setYaml).catch(() => {});
      }
    } catch (e) {
      // A rejected policy returns structured lint output, not a plain string.
      const d = e.message;
      if (d && typeof d === 'object' && d.warnings) {
        setMsg(`${d.error}: ` + d.warnings.map(w =>
          `${w.rule} (${(w.unparsable || []).join(', ') || w.effect || 'see below'})`).join('; ') + ` — ${d.grammar}`);
      } else {
        setMsg(typeof d === 'string' ? d : JSON.stringify(d));
      }
    }
  };

  const openEdit = async (name) => {
    try {
      const doc = await api.policies.get(name);
      setNewPolicy({
        name: doc.name,
        default_action: doc.default_action || 'allow',
        rules: doc.rules || [],
        extends: doc.extends || [],
        conflict_strategy: doc.conflict_strategy || '',
        scope: doc.scope || '',
      });
      setEditing(name);
      setValidation(null);
      setShadow(null);
      setStep(1);
      setShowCreate(true);
    } catch (e) { setMsg(e.message); }
  };

  const validateDraft = async () => {
    setShadow(null);
    try { setValidation(await api.policies.validate(policyBody())); }
    catch (e) { setValidation({ valid: false, error: String(e.message || e) }); }
  };

  // Evaluate the draft against the policy in force, over contexts replayed from
  // the audit chain. Nothing is saved and nothing is enforced.
  const dryRun = async () => {
    setValidation(null);
    setShadowing(true);
    try {
      setShadow(await api.policies.shadow({
        baseline: editing || 'default-policy',
        candidate: policyBody(),
        limit: 200,
      }));
    } catch (e) { setShadow({ error: String(e.message || e) }); }
    finally { setShadowing(false); }
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

  return (
    <div className="page">
      <PageHeader
        title="Policy Engine"
        subtitle="Author governance policies and evaluate them against a real call context."
        actions={
          <button className="btn btn-primary"
            onClick={() => { setNewPolicy(EMPTY_POLICY); setEditing(''); setValidation(null); setShadow(null); setStep(1); setShowCreate(true); }}>
            <Plus size={15} /> New policy
          </button>
        }
      />

      {msg && <Notice tone="info" onClose={() => setMsg('')}>{msg}</Notice>}

      {/* Three equal-height columns: the list, the selected policy, the
          evaluator. Nothing scrolls inside a column — the page is one
          screen and each panel sizes to its share of it. */}
      <div className="page-fill cols-policy">
        {/* Policy list */}
        <Panel title="Policies" bodyStyle={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {policies.length === 0
            ? <Empty>No policies loaded.</Empty>
            : policies.map(p => {
              const active = selected === p.name;
              return (
                <div
                  key={p.name}
                  onClick={() => setSelected(p.name)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(p.name); } }}
                  className={`policy-item ${active ? 'active' : ''}`}
                >
                  <div className="cluster" style={{ justifyContent: 'space-between', flexWrap: 'nowrap' }}>
                    <span className="mono truncate" style={{ color: 'var(--text)' }}>{p.name}</span>
                    {p.name !== 'default-policy' && (
                      <button className="btn btn-quiet btn-icon sm" title={`Delete ${p.name}`}
                        onClick={e => { e.stopPropagation(); deletePolicy(p.name); }}>
                        <Trash2 size={13} color="var(--text-3)" />
                      </button>
                    )}
                  </div>
                  <div className="cluster cluster-6" style={{ marginTop: 8 }}>
                    <Badge tone={actionTone(p.default_action)} size="sm">default {p.default_action}</Badge>
                    <span className="meta">{(p.rules || []).length} rules</span>
                  </div>
                </div>
              );
            })}
        </Panel>

        {/* Selected policy */}
          <Panel
            title={sel ? <span className="mono">{sel.name}</span> : 'Rules'}
            desc={sel ? (view === 'resolved'
              ? 'What AGT actually enforces after inheritance is merged.'
              : view === 'yaml'
                ? 'The file on disk, exactly as AGT loads it.'
                : 'Highest priority first — the first match decides.') : undefined}
            bodyStyle={{ padding: '4px 20px', overflow: 'hidden' }}
            actions={sel && (
              <>
                <button className={`btn btn-ghost btn-sm ${view === 'rules' ? 'is-on' : ''}`}
                  onClick={() => setView('rules')}>
                  <ListTree size={13} /> Authored
                </button>
                <button className={`btn btn-ghost btn-sm ${view === 'resolved' ? 'is-on' : ''}`}
                  onClick={() => setView('resolved')}>
                  <GitMerge size={13} /> Resolved
                </button>
                <button className={`btn btn-ghost btn-sm ${view === 'yaml' ? 'is-on' : ''}`}
                  onClick={() => setView('yaml')}>
                  <FileCode size={13} /> YAML
                </button>
                <button className="btn btn-secondary btn-sm" onClick={() => openEdit(sel.name)}>
                  <Pencil size={13} /> Edit
                </button>
              </>
            )}
          >
            {!sel
              ? <Empty>Select a policy to see its rules.</Empty>
              : (
                <>
                  {(sel.warnings || []).length > 0 && (
                    <Notice tone="warn" icon={<AlertTriangle size={15} color="var(--yellow)" />}
                      style={{ margin: '16px 0' }}>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>
                        {sel.warnings.length} rule{sel.warnings.length > 1 ? 's' : ''} that will not fire as written
                      </div>
                      {sel.warnings.map((w, i) => (
                        <div key={`${w.rule}-${i}`} className="meta"><code>{w.rule}</code> — {w.effect}</div>
                      ))}
                    </Notice>
                  )}
                  {/* What AGT actually enforces: parents merged in, with the
                      origin of every rule and the ones AGT silently dropped. */}
                  {view === 'resolved' && (
                    !resolved
                      ? <Empty>Resolving…</Empty>
                      : resolved.error
                        ? <Empty>Could not resolve this policy.</Empty>
                        : (
                          <>
                            <div className="meta cluster cluster-6" style={{ margin: '14px 0' }}>
                              <span>Inheritance chain:</span>
                              {(resolved.chain || []).map((n, i) => (
                                <span key={n} className="cluster cluster-6">
                                  {i > 0 && <span className="faint">→</span>}
                                  <code className={n === sel.name ? '' : 'muted'}>{n}</code>
                                </span>
                              ))}
                              <Badge tone="neutral" size="sm">{resolved.conflict_strategy}</Badge>
                              <Badge tone="neutral" size="sm">scope {resolved.scope}</Badge>
                            </div>

                            {(resolved.dropped_rules || []).length > 0 && (
                              <Notice tone="warn" icon={<AlertTriangle size={15} color="var(--yellow)" />}
                                style={{ margin: '0 0 16px' }}>
                                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                                  {resolved.dropped_rules.length} rule
                                  {resolved.dropped_rules.length > 1 ? 's' : ''} AGT dropped
                                </div>
                                {resolved.dropped_rules.map(r => (
                                  <div key={r.name} className="meta" style={{ marginBottom: 4 }}>
                                    <code>{r.name}</code> — {r.reason}
                                  </div>
                                ))}
                              </Notice>
                            )}

                            {(resolved.rules || []).map((r, i) => (
                              <div key={`${r.origin}-${r.name}-${i}`} className="row"
                                style={{ alignItems: 'flex-start' }}>
                                <Badge tone={actionTone(r.action)} size="sm"
                                  style={{ marginTop: 2, minWidth: 56, justifyContent: 'center' }}>
                                  {r.action}
                                </Badge>
                                <div className="rule-body">
                                  <div className="cluster cluster-6">
                                    <span className="rule-name">{r.name}</span>
                                    {r.inherited && (
                                      <Badge tone="neutral" size="sm">from {r.origin}</Badge>
                                    )}
                                  </div>
                                  <code className="rule-cond">{r.condition}</code>
                                </div>
                                <span className="rule-prio nums nowrap">
                                  priority {r.priority}
                                </span>
                              </div>
                            ))}
                          </>
                        )
                  )}

                  {view === 'yaml' && (
                    !yaml
                      ? <Empty>Loading…</Empty>
                      : yaml.error
                        ? <Empty>Could not read the file.</Empty>
                        : <pre className="code-block" style={{ margin: '14px 0', maxHeight: 'none' }}>{yaml.yaml}</pre>
                  )}

                  {view === 'rules' && ((sel.rules || []).length === 0
                    ? <Empty>No rules — every action falls through to the default: <strong>{sel.default_action}</strong></Empty>
                    : (sel.rules || []).map((r, i) => (
                      <div key={i} className="row" style={{ alignItems: 'flex-start' }}>
                        <Badge tone={actionTone(r.action)} size="sm"
                          style={{ marginTop: 2, minWidth: 56, justifyContent: 'center' }}>
                          {r.action}
                        </Badge>
                        <div className="rule-body">
                          <div className="rule-name">{r.name}</div>
                          <code className="rule-cond">{r.condition}</code>
                          {r.description && <p className="rule-desc">{r.description}</p>}
                        </div>
                        <span className="rule-prio nums nowrap"
                          title="Higher priority is evaluated first">
                          priority {r.priority}
                        </span>
                      </div>
                    )))}
                </>
              )}
          </Panel>

          {sel && (
            <Panel title="Evaluate">
              <div className="grid-form">
                <Field label="Action">
                  <input className="mono" value={evalForm.action}
                    onChange={e => setEvalForm(f => ({ ...f, action: e.target.value }))} />
                </Field>
                <Field label="Agent">
                  <input className="mono" value={evalForm.agent_id}
                    onChange={e => setEvalForm(f => ({ ...f, agent_id: e.target.value }))} />
                </Field>
                <Field label="Input text">
                  <input className="mono" value={evalForm.input_text}
                    onChange={e => setEvalForm(f => ({ ...f, input_text: e.target.value }))} />
                </Field>
              </div>

              <div className="cluster" style={{ marginTop: 4 }}>
                <button className="btn btn-primary" onClick={evaluate} disabled={evalLoading}>
                  <Play size={14} /> {evalLoading ? 'Evaluating' : 'Evaluate'}
                </button>
                <span className="meta">
                  Same PolicyEngine instance the Tool Playground enforces with.
                </span>
              </div>

              {evalResult && (
                <div className={`animate-in result-box ${evalResult.allowed ? 'ok' : 'bad'}`} style={{ marginTop: 16 }}>
                  <div className="cluster" style={{ marginBottom: 8 }}>
                    <Badge tone={evalResult.allowed ? 'success' : 'danger'}>
                      {evalResult.action?.toUpperCase()}
                    </Badge>
                    {evalResult.rule_name && <code className="muted">rule {evalResult.rule_name}</code>}
                    <span className="meta spacer">
                      Policy gate only — {(evalResult.other_gates || []).join(', ')} run first
                    </span>
                  </div>
                  <div style={{ fontSize: 16, marginBottom: 10 }}>{evalResult.reason}</div>
                  {evalResult.context && (
                    <details>
                      <summary>Context the rules were evaluated against</summary>
                      <pre className="code-block" style={{ marginTop: 10, maxHeight: 180 }}>
                        {JSON.stringify(evalResult.context, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              )}
            </Panel>
          )}
      </div>

      {/* Create policy */}
      {showCreate && (
        <Modal
          title={editing ? `Edit ${editing}` : 'Create policy'}
          subtitle={step === 1
            ? 'Step 1 of 2 — name it and choose what happens when no rule matches.'
            : 'Step 2 of 2 — add the rules. Highest priority runs first.'}
          onClose={() => { setShowCreate(false); setEditing(''); setValidation(null); setShadow(null); }}
          footer={step === 1
            ? (
              <>
                <button className="btn btn-ghost"
                  onClick={() => { setShowCreate(false); setEditing(''); setValidation(null); setShadow(null); }}>
                  Cancel
                </button>
                <button className="btn btn-primary" onClick={() => setStep(2)}
                  disabled={!newPolicy.name}>
                  Next
                </button>
              </>
            ) : (
              <>
                <button className="btn btn-ghost" onClick={() => setStep(1)}>Back</button>
                <button className="btn btn-primary" onClick={savePolicy}>
                  {editing ? 'Save changes' : 'Create policy'}
                </button>
              </>
            )}
        >
          {step === 1 && (
          <>
          <div className="grid-form">
            <Field label="Policy name">
              <input className="mono" placeholder="pii-protection" value={newPolicy.name}
                onChange={e => setNewPolicy(p => ({ ...p, name: e.target.value }))} />
            </Field>
            <Field label="Default action" hint="Applied when no rule matches">
              <select value={newPolicy.default_action}
                onChange={e => setNewPolicy(p => ({ ...p, default_action: e.target.value }))}>
                <option value="allow">allow</option>
                <option value="deny">deny</option>
              </select>
            </Field>
          </div>

          {/* Accepted by the backend from the start; the form never offered
              them, so inheritance was unreachable from the browser. */}
          <div className="grid-form">
            <Field label="Conflict strategy" hint="How competing rules are resolved">
              <select value={newPolicy.conflict_strategy}
                onChange={e => setNewPolicy(p => ({ ...p, conflict_strategy: e.target.value }))}>
                <option value="">default ({schema?.default_conflict_strategy || 'deny_overrides'})</option>
                {(schema?.conflict_strategies || []).map(x => <option key={x}>{x}</option>)}
              </select>
            </Field>
            <Field label="Scope" hint="Only used by the most_specific_wins strategy">
              <select value={newPolicy.scope}
                onChange={e => setNewPolicy(p => ({ ...p, scope: e.target.value }))}>
                <option value="">unset</option>
                {(schema?.scopes || []).map(x => <option key={x}>{x}</option>)}
              </select>
            </Field>
          </div>

          <Field label="Inherits from"
            hint="Parent rules merge first and cannot be weakened.">
            {policies.filter(p => p.name !== newPolicy.name).length === 0
              ? <span className="meta">No other policies to inherit from.</span>
              : (
                <div className="cluster cluster-6">
                  {policies.filter(p => p.name !== newPolicy.name).map(p => {
                    const on = newPolicy.extends.includes(p.name);
                    return (
                      <button key={p.name} type="button"
                        className={`btn btn-xs ${on ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => setNewPolicy(prev => ({
                          ...prev,
                          extends: on ? prev.extends.filter(n => n !== p.name)
                                      : [...prev.extends, p.name],
                        }))}>
                        {p.name}
                      </button>
                    );
                  })}
                </div>
              )}
          </Field>

          </>
          )}

          {step === 2 && (
          <>
          {/* Pre-flight checks on the draft. They belong with the rules they
              check, not in the commit bar — the footer stays two clear
              choices. */}
          <div className="cluster" style={{ marginBottom: 12 }}>
            <button className="btn btn-quiet btn-sm" onClick={validateDraft} disabled={!newPolicy.name}>
              <CheckCircle size={14} /> Validate
            </button>
            <button className="btn btn-quiet btn-sm" onClick={dryRun}
              disabled={shadowing || !newPolicy.name}>
              <FlaskConical size={14} /> {shadowing ? 'Running' : 'Dry run'}
            </button>
          </div>

          {validation && (
            <Notice tone={validation.valid ? 'success' : 'warn'}
              icon={validation.valid
                ? <CheckCircle size={15} color="var(--green)" />
                : <AlertTriangle size={15} color="var(--yellow)" />}
              style={{ margin: '4px 0 12px' }}
              onClose={() => setValidation(null)}>
              {validation.valid
                ? <>Valid — {validation.resolved_rule_count} rule
                    {validation.resolved_rule_count === 1 ? '' : 's'} after inheritance is merged.</>
                : (
                  <>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>
                      {validation.error || 'This policy would be rejected'}
                    </div>
                    {(validation.warnings || []).map((w, i) => (
                      <div key={`${w.rule}-${i}`} className="meta">
                        <code>{w.rule}</code> — {w.effect
                          || `AGT cannot parse ${(w.unparsable || []).join(', ')}`}
                      </div>
                    ))}
                    {validation.grammar && <div className="meta" style={{ marginTop: 6 }}>{validation.grammar}</div>}
                  </>
                )}
            </Notice>
          )}

          {shadow && (
            <Notice tone={shadow.error ? 'warn' : shadow.diverged ? 'warn' : 'success'}
              icon={<FlaskConical size={15} color={shadow.diverged ? 'var(--yellow)' : 'var(--green)'} />}
              style={{ margin: '4px 0 12px' }}
              onClose={() => setShadow(null)}>
              {shadow.error
                ? <code style={{ color: 'var(--yellow)' }}>{shadow.error}</code>
                : shadow.replayed === 0
                  ? <>Nothing to replay — no governed calls have been made yet, so there is no
                      traffic to compare this draft against.</>
                  : (
                    <>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>
                        {shadow.diverged === 0
                          ? `No change — this draft decides all ${shadow.replayed} replayed calls the same way as ${shadow.baseline}.`
                          : `${shadow.diverged} of ${shadow.replayed} replayed calls would be decided differently.`}
                      </div>
                      {shadow.diverged > 0 && (
                        <div className="meta">
                          {shadow.would_newly_deny > 0 && <>{shadow.would_newly_deny} newly denied. </>}
                          {shadow.would_newly_allow > 0 && <>{shadow.would_newly_allow} newly allowed. </>}
                          Divergence {(shadow.divergence_rate * 100).toFixed(1)}%
                          {' '}vs AGT&rsquo;s {(shadow.divergence_target * 100).toFixed(0)}% target
                          {shadow.within_target ? ' — within it.' : ' — a material change.'}
                        </div>
                      )}
                      {shadow.uncertain > 0 && (
                        <div className="meta" style={{ marginTop: 6 }}>
                          {shadow.uncertain} comparison{shadow.uncertain === 1 ? '' : 's'} could not be
                          replayed faithfully and {shadow.uncertain === 1 ? 'is' : 'are'} not counted —{' '}
                          {shadow.replay_limitation}
                        </div>
                      )}
                      {shadow.diverged > 0 && (
                        <details style={{ marginTop: 8 }}>
                          <summary className="meta">Which calls change</summary>
                          <div style={{ marginTop: 8 }}>
                            {shadow.comparisons.filter(c => c.diverged).slice(0, 12).map((c, i) => (
                              <div key={i} className="meta" style={{ marginBottom: 3 }}>
                                <code>{c.agent_id}</code> {c.tool} · <code>{c.action}</code>{' '}
                                {c.production_allowed ? 'allowed' : 'denied'}
                                {' → '}
                                <strong style={{ color: c.candidate_allowed ? 'var(--green)' : 'var(--red)' }}>
                                  {c.candidate_allowed ? 'allowed' : 'denied'}
                                </strong>
                                {c.candidate_rule ? ` (${c.candidate_rule})` : ''}
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    </>
                  )}
            </Notice>
          )}

          <div className="section-head" style={{ marginTop: 8 }}>
            <h3 className="section-title">Rules</h3>
            <span className="section-note">{newPolicy.rules.length} added</span>
          </div>

          {newPolicy.rules.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              {newPolicy.rules.map((r, i) => (
                <div key={i} className="row" style={{ padding: '10px 0' }}>
                  <Badge tone={actionTone(r.action)} size="sm">{r.action}</Badge>
                  <span className="mono">{r.name}</span>
                  <code className="faint truncate" style={{ flex: 1 }}>{r.condition}</code>
                  <span className="meta nums">p{r.priority}</span>
                  <button className="btn btn-quiet btn-icon sm" title="Remove rule"
                    onClick={() => setNewPolicy(p => ({ ...p, rules: p.rules.filter((_, j) => j !== i) }))}>
                    <X size={14} color="var(--red)" />
                  </button>
                </div>
              ))}
            </div>
          )}

          <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--r)', padding: 18 }}>
            <div className="grid-form">
              <Field label="Rule name">
                <input className="mono" placeholder="block-destructive" value={newRule.name}
                  onChange={e => setNewRule(r => ({ ...r, name: e.target.value }))} />
              </Field>
              <Field label="Action">
                <select value={newRule.action}
                  onChange={e => setNewRule(r => ({ ...r, action: e.target.value }))}>
                  {(schema?.actions || ['deny', 'allow', 'warn', 'require_approval'])
                    .map(a => <option key={a}>{a}</option>)}
                </select>
              </Field>
              <Field label="Priority" hint="Higher runs first">
                <input type="number" value={newRule.priority} title="Priority"
                  onChange={e => setNewRule(r => ({ ...r, priority: Number(e.target.value) }))} />
              </Field>
            </div>

            <div className="field-label" style={{ marginTop: 6 }}>Condition</div>
            <ConditionBuilder
              schema={schema}
              value={newRule.condition}
              onChange={condition => setNewRule(r => ({ ...r, condition }))}
            />

            <button className="btn btn-ghost btn-sm" onClick={addRuleToNew}
              disabled={!newRule.name || !newRule.condition}
              style={{ marginTop: 16 }}>
              <Plus size={13} /> Add rule
            </button>
          </div>
          </>
          )}
        </Modal>
      )}
    </div>
  );
}
