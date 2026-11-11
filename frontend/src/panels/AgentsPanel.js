import { useState, useEffect, useCallback } from 'react';
import { Plus, Fingerprint, Cloud, Trash2, History, PauseCircle, PlayCircle, Check, X, User } from '../icons';
import { api } from '../api';
import Slider from '../Slider';
import { PageHeader, Panel, Modal, Badge, Field, Notice, Empty, Meter, scoreColor, statusTone } from '../ui';

const EMPTY_FORM = {
  id: '', name: '', trust_score: 0.8, policy: 'default-policy',
  capabilities: '', project_endpoint: '', foundry_agent_id: '',
};

// One line each, so the trail reads as a sentence rather than a payload dump.
const EVENT_LABEL = {
  requested: 'Registration requested',
  approved: 'Approved',
  rejected: 'Rejected',
  activated: 'Activated',
  suspended: 'Suspended',
  resumed: 'Resumed',
  decommissioned: 'Decommissioned',
  owner_changed: 'Owner changed',
  credentials_rotated: 'Credentials rotated',
};

const isPending = (a) => a.status === 'pending_approval';
const isRetired = (a) => a.status === 'decommissioned';

export default function AgentsPanel() {
  const [agents, setAgents] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [showCreate, setShowCreate] = useState(false);
  const [msg, setMsg] = useState('');
  const [syncFor, setSyncFor] = useState(null);
  const [syncText, setSyncText] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [trailFor, setTrailFor] = useState(null);
  const [trail, setTrail] = useState(null);
  const [busy, setBusy] = useState({});
  const [showRetired, setShowRetired] = useState(false);

  const load = useCallback(async () => {
    try {
      const [ag, po] = await Promise.all([api.agents.list(), api.policies.list()]);
      setAgents(ag);
      setPolicies(po);
    } catch (e) { setMsg(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!form.id || !form.name) return setMsg('ID and name required');
    try {
      const body = {
        ...form,
        capabilities: form.capabilities.split(',').map(c => c.trim()).filter(Boolean),
      };
      const created = await api.agents.create(body);
      setMsg(created?.status === 'pending_approval'
        ? `${created.id} registered and is awaiting approval — it cannot call anything until an admin admits it.`
        : created?.did
          ? `Agent registered · identity ${created.did} (private key issued once)`
          : 'Agent registered');
      setForm(EMPTY_FORM);
      setShowCreate(false);
      load();
    } catch (e) { setMsg(e.message); }
  };

  const act = async (id, fn, done) => {
    setBusy(b => ({ ...b, [id]: true }));
    try { await fn(); if (done) setMsg(done); await load(); }
    catch (e) { setMsg(e.message); }
    finally { setBusy(b => ({ ...b, [id]: false })); }
  };

  const del = (id) => {
    if (!window.confirm(
      `Decommission ${id}?\n\nThis is an AGT lifecycle transition, not a delete — the record and its audit trail are kept, and the agent stops being able to call anything.`)) return;
    act(id, () => api.agents.delete(id), `${id} decommissioned`);
  };

  const reject = (id) => {
    const reason = window.prompt(`Reject ${id}? Reason recorded in the lifecycle trail:`, 'Not approved');
    if (reason === null) return;
    act(id, () => api.agents.reject(id, reason), `${id} rejected`);
  };

  const openTrail = async (id) => {
    setTrailFor(id); setTrail(null);
    try { setTrail(await api.agents.lifecycle(id)); }
    catch (e) { setTrail({ error: e.message }); }
  };

  const openSync = (id) => { setSyncFor(id); setSyncText(''); };

  const doSync = async () => {
    let steps;
    try { steps = JSON.parse(syncText); }
    catch { return setMsg('Run steps must be valid JSON'); }
    if (!Array.isArray(steps)) return setMsg('Paste a JSON array of run steps');
    setSyncing(true);
    try {
      const r = await api.agents.foundrySync(syncFor, steps);
      setMsg(`Synced ${syncFor} · ${r.accepted} tool call(s), ${r.denied_reported} failed`);
      setSyncFor(null); setSyncText('');
      load();
    } catch (e) { setMsg(e.message); }
    finally { setSyncing(false); }
  };

  const pending = agents.filter(isPending);
  const visible = agents.filter(a => !isPending(a) && (showRetired || !isRetired(a)));
  const retiredCount = agents.filter(isRetired).length;

  const card = (a) => (
    <section key={a.id} className="agent-card" style={isRetired(a) ? { opacity: 0.55 } : undefined}>
      <div className="cluster" style={{ justifyContent: 'space-between', flexWrap: 'nowrap', alignItems: 'flex-start' }}>
        <div style={{ minWidth: 0 }}>
          <div className="agent-id truncate">{a.id}</div>
          {/* Only worth a second line when it says something the id does not. */}
          {a.name && a.name !== a.id && (
            <div className="meta truncate" style={{ marginTop: 2 }}>{a.name}</div>
          )}
        </div>
        <div className="cluster cluster-6" style={{ flexWrap: 'nowrap' }}>
          <Badge tone={statusTone(a.status)} dot size="sm">{a.status.replace(/_/g, ' ')}</Badge>
          <button className="btn btn-quiet btn-icon sm" onClick={() => openTrail(a.id)}
            title="AGT lifecycle trail — who moved this agent, and why">
            <History size={13} color="var(--text-3)" />
          </button>
          {!isRetired(a) && (
            <button className="btn btn-quiet btn-icon sm" disabled={busy[a.id]}
              onClick={() => a.status === 'suspended'
                ? act(a.id, () => api.agents.resume(a.id), `${a.id} resumed`)
                : act(a.id, () => api.agents.suspend(a.id), `${a.id} suspended — the kill switch is AGT's SUSPENDED state`)}
              title={a.status === 'suspended'
                ? 'Resume — returns the agent to ACTIVE'
                : 'Suspend — the kill switch, enforced before policy'}>
              {a.status === 'suspended'
                ? <PlayCircle size={13} color="var(--green)" />
                : <PauseCircle size={13} color="var(--yellow)" />}
            </button>
          )}
          {!isRetired(a) && (
            <button className="btn btn-quiet btn-icon sm" onClick={() => del(a.id)}
              title={`Decommission ${a.id}`}>
              <Trash2 size={13} color="var(--text-3)" />
            </button>
          )}
        </div>
      </div>

      <div style={{ marginTop: 18 }}>
        <div className="cluster" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
          <span className="meta">Trust score</span>
          <span className="meter-value" style={{ color: scoreColor(a.trust_score) }}>
            {(a.trust_score * 100).toFixed(0)}%
          </span>
        </div>
        <Meter value={a.trust_score * 100} color={scoreColor(a.trust_score)} />
        <div className="meta" style={{ marginTop: 6 }}>{a.ring?.replace(/_/g, ' ').toLowerCase()}</div>
      </div>

      <dl className="kv-row">
        <div>
          <dt>Policy</dt>
          <dd className="mono truncate">{a.policy}</dd>
        </div>
        <div>
          <dt>Calls</dt>
          <dd className="mono nums">{a.calls}</dd>
        </div>
        <div>
          <dt>Denials</dt>
          <dd className="mono nums" style={{ color: a.denials > 0 ? 'var(--red)' : undefined }}>{a.denials}</dd>
        </div>
      </dl>

      {a.capabilities?.length > 0 && (
        <div className="cluster cluster-6" style={{ marginTop: 10 }}>
          {a.capabilities.map(c => <Badge key={c} tone="neutral" size="sm">{c}</Badge>)}
        </div>
      )}

      <div className="agent-card-foot">
        {/* AGT requires an owner so every agent is attributable — which is
            only worth requiring if the attribution is visible. */}
        <div className="meta cluster cluster-6" style={{ flexWrap: 'nowrap' }} title={a.owner}>
          <User size={12} color="var(--text-3)" />
          <code className="truncate">{a.owner}</code>
        </div>
        <div className="meta">Created {new Date(a.created_at).toLocaleString()}</div>
        {a.did && (
          <div className="meta cluster cluster-6" style={{ flexWrap: 'nowrap' }} title={a.did}>
            <Fingerprint size={12} color="var(--text-3)" />
            <code className="truncate">{a.did}</code>
          </div>
        )}
        {a.foundry && (
          <>
            <div className="meta cluster cluster-6" style={{ flexWrap: 'nowrap' }} title={a.foundry.project_endpoint}>
              <Cloud size={12} color="var(--text-3)" />
              <code className="truncate">{a.foundry.foundry_agent_id || 'Foundry'}</code>
            </div>
            <button className="btn btn-ghost btn-sm btn-block" onClick={() => openSync(a.id)}>
              Sync from Foundry
            </button>
          </>
        )}
      </div>
    </section>
  );

  return (
    <div className="page">
      <PageHeader
        title="Agents"
        subtitle="Every registered agent, the policy that governs it, and the AGT lifecycle transitions it has been through."
        actions={
          <>
            {retiredCount > 0 && (
              <button className={`btn btn-ghost btn-sm ${showRetired ? 'is-on' : ''}`}
                onClick={() => setShowRetired(v => !v)}>
                {showRetired ? 'Hide' : 'Show'} decommissioned ({retiredCount})
              </button>
            )}
            <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
              <Plus size={15} /> Register agent
            </button>
          </>
        }
      />

      {msg && <Notice tone="info" onClose={() => setMsg('')}>{msg}</Notice>}

      {/* Awaiting admission. Only appears when AGT_REQUIRE_APPROVAL is on, so
          the shipped default is untouched. */}
      {pending.length > 0 && (
        <Panel
          title={`Awaiting approval (${pending.length})`}
          desc="Registered but not admitted. AGT's state machine refuses to activate these, so they cannot call anything until an admin approves."
          bodyStyle={{ padding: 16 }}
        >
          {pending.map(a => (
            <div key={a.id} className="row" style={{ alignItems: 'center' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <code style={{ color: 'var(--text)' }}>{a.id}</code>
                <div className="meta" style={{ marginTop: 2 }}>
                  {a.name} · owner {a.owner} · trust {(a.trust_score * 100).toFixed(0)}% · policy {a.policy}
                </div>
              </div>
              <button className="btn btn-primary btn-sm" disabled={busy[a.id]}
                onClick={() => act(a.id, () => api.agents.approve(a.id), `${a.id} approved and activated`)}>
                <Check size={13} /> Approve
              </button>
              <button className="btn btn-danger btn-sm" disabled={busy[a.id]}
                onClick={() => reject(a.id)}>
                <X size={13} /> Reject
              </button>
            </div>
          ))}
        </Panel>
      )}

      {/* The cards are the surface here — wrapping them in a panel would
          just draw a second border around a grid of borders. */}
      <div className="page-fill fill-start scroll-y">
        {visible.length === 0
          ? <Panel><Empty>No agents registered yet.</Empty></Panel>
          : <div className="grid-cards">{visible.map(card)}</div>}
      </div>

      {/* Lifecycle trail */}
      {trailFor && (
        <Modal title="Lifecycle trail" subtitle={trailFor} onClose={() => setTrailFor(null)}
          footer={<button className="btn btn-ghost" onClick={() => setTrailFor(null)}>Close</button>}>
          <p className="muted" style={{ fontSize: 16, marginBottom: 14 }}>
            AGT's <code className="inline-code">LifecycleManager</code> records every state change with
            its actor and reason. Separate from the governance audit chain: this tracks who changed the
            agent, not what the agent did.
          </p>
          {!trail && <div className="meta">Loading…</div>}
          {trail?.error && <code style={{ color: 'var(--yellow)' }}>{trail.error}</code>}
          {trail?.events && (
            <table className="table">
              <thead>
                <tr><th>When</th><th>Event</th><th>Transition</th><th>Actor</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {trail.events.map((e, i) => (
                  <tr key={i}>
                    <td className="meta">{new Date(e.timestamp).toLocaleString()}</td>
                    <td>{EVENT_LABEL[e.event_type] || e.event_type}</td>
                    <td className="meta mono">
                      {e.previous_state || '—'} → {e.new_state || '—'}
                    </td>
                    <td className="mono">{e.actor}</td>
                    <td className="meta">
                      {Object.entries(e.details || {}).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 10 }}>
                          <span className="faint">{k}</span>{' '}
                          <span className="mono muted">{String(v)}</span>
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Modal>
      )}

      {/* Register */}
      {showCreate && (
        <Modal
          title="Register agent"
          onClose={() => setShowCreate(false)}
          footer={
            <>
              <button className="btn btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={create}>Register agent</button>
            </>
          }
        >
          <div className="grid-form">
            <Field label="Agent ID">
              <input className="mono" value={form.id} onChange={e => setForm(f => ({ ...f, id: e.target.value }))}
                placeholder="my-agent-1" />
            </Field>
            <Field label="Display name">
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="My Agent" />
            </Field>
          </div>
          <div className="grid-form">
            <Field label={`Trust score — ${form.trust_score}`}>
              <Slider min={0} max={1} step={0.01} value={form.trust_score}
                ariaLabel="Trust score"
                onChange={v => setForm(f => ({ ...f, trust_score: v }))} />
            </Field>
            <Field label="Policy">
              <select value={form.policy} onChange={e => setForm(f => ({ ...f, policy: e.target.value }))}>
                {policies.map(p => <option key={p.name}>{p.name}</option>)}
              </select>
            </Field>
          </div>
          <Field label="Capabilities"
            hint="Comma-separated. An imported MCP tool may require one; the dispatch gate checks it.">
            <input className="mono" value={form.capabilities}
              onChange={e => setForm(f => ({ ...f, capabilities: e.target.value }))}
              placeholder="db:read, notes:write" />
          </Field>

          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 18, marginTop: 6 }}>
            <div className="section-head" style={{ marginBottom: 12 }}>
              <h3 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Cloud size={15} color="var(--text-3)" /> Azure AI Foundry
              </h3>
              <span className="section-note">Optional</span>
            </div>
            <div className="grid-form">
              <Field label="Project endpoint">
                <input className="mono" value={form.project_endpoint}
                  onChange={e => setForm(f => ({ ...f, project_endpoint: e.target.value }))}
                  placeholder="https://<res>.services.ai.azure.com/api/projects/<project>" />
              </Field>
              <Field label="Foundry agent ID">
                <input className="mono" value={form.foundry_agent_id}
                  onChange={e => setForm(f => ({ ...f, foundry_agent_id: e.target.value }))}
                  placeholder="asst_abc123" />
              </Field>
            </div>
            <p className="meta">
              Links a Foundry agent so its run-step telemetry can be streamed from the card. Descriptive only — the backend never calls Azure.
            </p>
          </div>
        </Modal>
      )}

      {/* Foundry sync */}
      {syncFor && (
        <Modal
          title="Sync run steps"
          subtitle={syncFor}
          busy={syncing}
          onClose={() => setSyncFor(null)}
          footer={
            <>
              <button className="btn btn-ghost" onClick={() => setSyncFor(null)} disabled={syncing}>Cancel</button>
              <button className="btn btn-primary" onClick={doSync} disabled={syncing || !syncText.trim()}>
                {syncing ? 'Syncing' : 'Sync telemetry'}
              </button>
            </>
          }
        >
          <p className="muted" style={{ fontSize: 16, marginBottom: 12 }}>Paste the run steps exported from Foundry:</p>
          <pre className="code-block" style={{ marginBottom: 14 }}>
            {'[s.as_dict() for s in project.agents.run_steps.list(thread_id=..., run_id=...)]'}
          </pre>
          <textarea className="mono" value={syncText} onChange={e => setSyncText(e.target.value)}
            placeholder='[ { "type": "tool_calls", "status": "completed", ... } ]'
            style={{ height: 220, resize: 'vertical' }} />
        </Modal>
      )}
    </div>
  );
}
