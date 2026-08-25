import { useState, useEffect, useRef } from 'react';
import { FileText, Trash2, RefreshCw, ShieldCheck, ShieldAlert, Download } from 'lucide-react';
import { api } from '../api';

const EVENT_COLORS = {
  'tool.call.allowed': 'var(--green)',
  'tool.call.denied': 'var(--red)',
  'tool.call.denied.lifecycle': 'var(--red)',
  'tool.call.denied.ring': 'var(--yellow)',
  'tool.call.denied.trust': 'var(--red)',
  'tool.call.denied.unregistered': 'var(--yellow)',
  'audit.chain.reset': 'var(--yellow)',
  'trust.evaluated': 'var(--purple)',
  'trust.updated': 'var(--purple)',
  'policy.created': 'var(--accent)',
  'agent.registered': 'var(--accent)',
  'agent.removed': 'var(--yellow)',
  'agent.decommissioned': 'var(--yellow)',
  'sre.kill_switch': 'var(--red)',
  'sre.resumed': 'var(--green)',
  'sre.signal': 'var(--text-2)',
  'sre.slo.created': 'var(--yellow)',
  'compliance.scan': 'var(--accent)',
};

export default function AuditPanel() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState({ agent_id: '', event_type: '' });
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [root, setRoot] = useState(null);
  const [chain, setChain] = useState(null);
  const [verifying, setVerifying] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.audit.get(100, filter.agent_id || undefined, filter.event_type || undefined);
      setEvents(res.events);
      setTotal(res.total);
      setRoot(res.merkle_root);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [autoRefresh, filter]);

  const reset = async () => {
    if (!window.confirm(
      'Start a new audit chain? The current chain is not erased in place — the new chain opens with an entry recording the root hash and size of the one it replaces.'
    )) return;
    await api.audit.clear();
    setChain(null);
    load();
  };

  const verify = async () => {
    setVerifying(true);
    try { setChain(await api.audit.verify()); }
    catch (e) { setChain({ valid: false, error: e.message }); }
    setVerifying(false);
  };

  const exportChain = async () => {
    const data = await api.audit.export();
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-chain-${data.merkle_root?.slice(0, 12) || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const color = (et) => EVENT_COLORS[et] || 'var(--text-2)';

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <FileText size={22} color="var(--text-2)" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Audit Log</h2>
          <p style={{ color: 'var(--text-2)', fontSize: 12 }}>
            Hash-chained governance event stream — every entry links to the one before it
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <button className={`btn btn-ghost`} style={{ fontSize: 11, background: autoRefresh ? 'var(--accent-dim)' : '' }}
            onClick={() => setAutoRefresh(v => !v)}>
            <RefreshCw size={12} style={{ marginRight: 4 }} />
            {autoRefresh ? 'Live' : 'Paused'}
          </button>
          <button className="btn btn-ghost" onClick={load} style={{ fontSize: 11 }}>Refresh</button>
          <button className="btn btn-ghost" onClick={exportChain} style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
            <Download size={11} /> Export
          </button>
          <button className="btn btn-danger" onClick={reset} style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
            <Trash2 size={11} /> New chain
          </button>
        </div>
      </div>

      {/* Chain integrity */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap',
        padding: '12px 16px', marginBottom: 16, borderRadius: 8,
        background: chain ? (chain.valid ? 'var(--green-dim)' : 'var(--red-dim)') : 'var(--bg-2)',
        border: `1px solid ${chain ? (chain.valid ? 'var(--green)' : 'var(--red)') + '44' : 'var(--border)'}`,
      }}>
        {chain
          ? (chain.valid ? <ShieldCheck size={18} color="var(--green)" /> : <ShieldAlert size={18} color="var(--red)" />)
          : <ShieldCheck size={18} color="var(--text-3)" />}

        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2, color: chain ? (chain.valid ? 'var(--green)' : 'var(--red)') : 'var(--text-2)' }}>
            {chain
              ? (chain.valid
                  ? `Chain intact — ${chain.entry_count} ${chain.entry_count === 1 ? 'entry' : 'entries'} verified`
                  : `Chain broken — ${chain.error}`)
              : 'Chain integrity not yet checked'}
          </div>
          <code style={{ fontSize: 10, color: 'var(--text-3)', wordBreak: 'break-all' }}>
            merkle root: {root || '—'}
          </code>
        </div>

        <button className="btn btn-ghost" onClick={verify} disabled={verifying}
          style={{ marginLeft: 'auto', fontSize: 11, whiteSpace: 'nowrap' }}>
          {verifying ? 'Verifying…' : 'Verify chain'}
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <input placeholder="Filter by agent ID" value={filter.agent_id}
          onChange={e => setFilter(f => ({ ...f, agent_id: e.target.value }))} style={{ flex: 1 }} />
        <select value={filter.event_type} onChange={e => setFilter(f => ({ ...f, event_type: e.target.value }))}
          style={{ width: 200 }}>
          <option value="">All event types</option>
          {Object.keys(EVENT_COLORS).map(k => <option key={k}>{k}</option>)}
        </select>
        <div style={{ display: 'flex', alignItems: 'center', padding: '0 12px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
          {total} total
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        {[
          { label: 'Total', value: events.length, color: 'var(--text)' },
          { label: 'Allowed', value: events.filter(e => e.allowed).length, color: 'var(--green)' },
          { label: 'Denied', value: events.filter(e => !e.allowed).length, color: 'var(--red)' },
          { label: 'Tool Calls', value: events.filter(e => e.event_type?.startsWith('tool.')).length, color: 'var(--yellow)' },
        ].map(({ label, value, color: c }) => (
          <div key={label} style={{ flex: 1, padding: '10px 14px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 8, textAlign: 'center' }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: c, fontFamily: 'var(--mono)' }}>{value}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '.5px' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Event list */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ maxHeight: 520, overflowY: 'auto' }}>
          {loading && events.length === 0 && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)' }}>Loading events…</div>
          )}
          {events.length === 0 && !loading && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)' }}>
              No audit events yet. Interact with the Tool Playground or Trust panel to generate events.
            </div>
          )}
          {events.map((e, i) => (
            <div key={e.id} className="animate-in" style={{
              display: 'grid',
              gridTemplateColumns: '7px 90px 170px 120px 1fr 92px',
              alignItems: 'center',
              gap: 16,
              padding: '10px 20px',
              borderBottom: '1px solid var(--border)',
              borderLeft: `3px solid ${e.allowed ? 'transparent' : 'var(--red)'}`,
            }}>
              {/* indicator */}
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: color(e.event_type) }} />

              {/* time */}
              <code style={{ fontSize: 10, color: 'var(--text-3)' }}>
                {new Date(e.timestamp).toLocaleTimeString()}
              </code>

              {/* event type */}
              <div style={{ fontSize: 11, fontFamily: 'var(--mono)', color: color(e.event_type), fontWeight: 600 }}>
                {e.event_type}
              </div>

              {/* agent */}
              <code style={{ fontSize: 11, color: 'var(--text-2)' }}>{e.agent_id}</code>

              {/* details */}
              <div style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {Object.entries(e.details || {}).map(([k, v]) => (
                  <span key={k} style={{ marginRight: 12 }}>
                    <span style={{ color: 'var(--text-3)' }}>{k}:</span>{' '}
                    <span style={{ color: 'var(--text-2)', fontFamily: 'var(--mono)' }}>
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </span>
                  </span>
                ))}
              </div>

              {/* entry hash — links this entry to the one before it */}
              <code
                title={`entry:    ${e.entry_hash || ''}
previous: ${e.previous_hash || '(genesis)'}`}
                style={{ fontSize: 10, color: 'var(--text-3)', textAlign: 'right', overflow: 'hidden' }}>
                {e.entry_hash ? e.entry_hash.slice(0, 10) : '—'}
              </code>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
