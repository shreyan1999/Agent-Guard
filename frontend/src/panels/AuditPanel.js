import { useState, useEffect, useMemo } from 'react';
import {
  Trash2, RefreshCw, ShieldCheck, ShieldAlert, Download, FileCheck, Link2,
  HardDrive, Scale, Route, GitCompare, Power, Fingerprint, Lock, Plug,
  Terminal, Ban, Play, PauseCircle,
} from '../icons';
import { api } from '../api';
import { PageHeader, Panel, Modal, Badge, StatStrip, Stat, Empty } from '../ui';

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

/* Why the receipt controls are inert on a fresh instance. A receipt is issued
   per *MCP* tool-call decision, so a platform that has only ever called its
   built-in tools has an empty ledger and nothing to verify or export. */
const NO_RECEIPTS_HINT =
  'The receipt ledger is empty: a receipt is issued for each MCP tool-call '
  + 'decision, and no MCP tool has been called on this instance. Import an MCP '
  + 'server from the Tool Playground, or load the demo data from the Overview.';

/* -- trace replay --------------------------------------------------------- */

/* What each gate in a governed call is, in the words the rest of the platform
   uses for it. Keyed by the name the recorder writes after `gate:` - the set
   `/tools/call` can actually produce, no more.

   `ring`, `policy` and `mcp_proxy` appear as their own span only when one of
   them denied; an allowed call records the single `govern` span instead,
   because AGT decides all three inside `govern()` and returns one outcome. */
const REPLAY_STAGE = {
  lifecycle: {
    label: 'Lifecycle', icon: Power,
    note: 'The agent must be registered and ACTIVE. A kill switch that policy '
      + 'could override is not a kill switch, so this runs before policy does.',
  },
  identity: {
    label: 'Identity', icon: Fingerprint,
    note: 'A self-asserted agent id is only honoured when no attestation is '
      + 'offered. If the caller presents one it must verify against the '
      + 'agent’s registered public key.',
  },
  tenant: {
    label: 'Tenant', icon: Lock,
    note: 'The caller’s tenant must own the agent the call claims to be.',
  },
  trust: {
    label: 'Trust', icon: ShieldCheck,
    note: 'The shared TrustPolicy — the same object /trust/evaluate uses, '
      + 'so the panel and the gate cannot disagree.',
  },
  govern: {
    label: 'Ring · Policy · MCP proxy', icon: Scale,
    note: 'All three decide inside AGT’s govern(), which returns a single '
      + 'outcome — so they share one measured span rather than three '
      + 'invented ones.',
  },
  ring: {
    label: 'Ring', icon: Scale,
    note: 'AGT derives the execution ring from trust and enforces its resource '
      + 'constraints before policy is evaluated.',
  },
  policy: {
    label: 'Policy', icon: Scale,
    note: 'AGT’s PolicyEngine, evaluating the rules as this specific agent.',
  },
  mcp_proxy: {
    label: 'MCP proxy', icon: Plug,
    note: 'AGT’s trust proxy — the one gate an MCP tool passes that a '
      + 'built-in tool does not.',
  },
};

/**
 * The steps to walk, built from the spans this trace actually holds.
 *
 * Nothing is drawn that was not recorded: a call stopped at the trust gate has
 * four spans and so gets four steps, which is what happened to it. The one
 * addition is a terminal marker, and only where the trace itself proves it -
 * a stopped call with no `tool_call` span never reached the tool.
 */
function replaySteps(trace) {
  const spans = trace.spans || [];
  const steps = spans.map(sp => {
    const gate = sp.name.startsWith('gate:') ? sp.name.slice(5) : null;
    const stage = gate ? REPLAY_STAGE[gate] : null;
    const stopped = sp.status === 'error';
    let label = sp.name;
    let icon = Route;
    let note = '';

    if (stage) {
      ({ label, icon, note } = stage);
    } else if (sp.name === 'record:governance') {
      label = 'Record';
      icon = HardDrive;
      note = 'Written after the decision — ' + (sp.attributes?.writes
        || 'the governance record') + '. Not a gate, and it never changes an '
        + 'outcome, but on a fast local deny it is most of the elapsed time.';
    } else if (sp.kind === 'tool_call') {
      label = sp.name.split('.').pop();
      icon = Terminal;
      note = 'The call itself. This span is the round trip the connector '
        + 'measured, which is why it is not charged to governance overhead.';
    }

    return {
      key: sp.span_id,
      label,
      icon,
      stopped,
      ms: sp.duration_ms,
      tone: stopped ? 'red'
        : sp.kind === 'tool_call' ? 'green'
          : sp.kind === 'internal' ? 'muted' : 'accent',
      // On a stopped step the gate's own reason beats anything written here.
      note: stopped ? (sp.error || note) : note,
      attrs: Object.entries(sp.attributes || {}),
    };
  });

  const stop = steps.findIndex(s => s.stopped);
  if (stop >= 0 && !spans.some(sp => sp.kind === 'tool_call')) {
    steps.splice(stop + 1, 0, {
      key: '__not-dispatched',
      label: 'Not dispatched',
      icon: Ban,
      tone: 'muted',
      ms: null,
      attrs: [],
      note: 'The gate before this one stopped the call, so the tool was never '
        + 'invoked. The decision is still recorded: a denial earns an audit '
        + 'entry, and an MCP denial a signed receipt, exactly as an allow does.',
    });
  }
  return steps;
}

const REPLAY_STEP_MS = 800;

const prefersReducedMotion = () => (
  typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : false
);

/**
 * The call, replayed step by step along its own spans.
 *
 * The playback is evenly paced, and that is a deliberate choice rather than a
 * shortcut: four of these gates routinely measure 0.000 ms, so pacing the
 * animation by duration would flash them past invisibly and then sit for a
 * third of a second on the audit write. What the animation is faithful to is
 * the *order*, which is the one thing a reader cannot recover from a list of
 * bars. The measured time rides on each step and the bars below the rail are
 * drawn to scale, so the timing is still shown - just not by the wall clock.
 */
function TraceReplay({ trace }) {
  const steps = useMemo(() => replaySteps(trace), [trace]);
  const [at, setAt] = useState(0);        // how many steps have been revealed
  const [playing, setPlaying] = useState(false);

  // A newly opened trace replays from the start. Reduced motion gets the
  // finished rail immediately - the information, without the travel.
  useEffect(() => {
    const still = prefersReducedMotion();
    setAt(still ? steps.length : 0);
    setPlaying(!still);
  }, [trace.trace_id, steps.length]);

  useEffect(() => {
    if (!playing) return undefined;
    if (at >= steps.length) { setPlaying(false); return undefined; }
    const t = setTimeout(() => setAt(v => v + 1), at === 0 ? 240 : REPLAY_STEP_MS);
    return () => clearTimeout(t);
  }, [playing, at, steps.length]);

  if (steps.length === 0) return null;

  const done = at >= steps.length;
  const current = steps[Math.min(at, steps.length) - 1] || null;
  const toggle = () => {
    if (done) { setAt(0); setPlaying(true); } else setPlaying(p => !p);
  };

  return (
    <div className="treplay">
      <div className="treplay-bar">
        <button type="button" className="btn btn-secondary btn-sm" onClick={toggle}>
          {playing ? <PauseCircle size={13} /> : done ? <RefreshCw size={13} /> : <Play size={13} />}
          {playing ? 'Pause' : done ? 'Replay' : 'Play'}
        </button>
        <span className="treplay-count nums">
          {Math.min(at, steps.length)}<i>/{steps.length}</i>
        </span>
        <span className="treplay-caption">
          Evenly paced, because several of these gates measure 0.000&nbsp;ms and
          a faithful clock would flash them past. The order is real; the measured
          time is on each step, and the bars below are drawn to scale.
        </span>
      </div>

      <ol className="treplay-rail">
        {steps.map((s, i) => {
          const state = i < at - 1 ? 'done' : i === at - 1 ? 'active' : 'pending';
          const Icon = s.icon;
          return (
            <li key={s.key}
              className={`treplay-step tone-${s.tone} is-${state}`
                + (s.stopped ? ' is-stopped' : '')}>
              <span className="treplay-link" aria-hidden />
              {/* Watching it once is the point; being stuck watching it is not.
                  A step can be clicked to park the replay there and read it. */}
              <button type="button" className="treplay-hit"
                onClick={() => { setPlaying(false); setAt(i + 1); }}
                aria-current={state === 'active' ? 'step' : undefined}
                title={`Step ${i + 1} of ${steps.length}: ${s.label}`}>
                <span className="treplay-node">
                  <Icon size={17} />
                  {state === 'active' && !done && <span className="treplay-halo" />}
                </span>
                <span className="treplay-label">{s.label}</span>
                <span className="treplay-ms nums">{s.ms == null ? '—' : `${s.ms} ms`}</span>
              </button>
            </li>
          );
        })}
      </ol>

      <div className={`treplay-readout tone-${current ? current.tone : 'muted'}`}>
        {current ? (
          <>
            <p className="treplay-readout-title">
              {current.label}
              {current.stopped && <Badge tone="danger" size="sm">stopped here</Badge>}
            </p>
            <p className="treplay-readout-note">{current.note}</p>
            {current.attrs.length > 0 && (
              <div className="cluster cluster-6" style={{ marginTop: 6 }}>
                {current.attrs.map(([k, v]) => (
                  <span key={k} className="meta faint">
                    {k} <span className="mono muted">{String(v)}</span>
                  </span>
                ))}
              </div>
            )}
          </>
        ) : (
          <p className="treplay-readout-note">
            Ready to replay {steps.length} recorded steps.
          </p>
        )}
      </div>
    </div>
  );
}

export default function AuditPanel() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState({ agent_id: '', event_type: '' });
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [root, setRoot] = useState(null);
  const [chain, setChain] = useState(null);
  const [verifying, setVerifying] = useState(false);
  // Signed MCP governance receipts. A separate artefact from the chain above:
  // the chain proves this log was not edited and you must trust this instance
  // to read it; a receipt carries its own signature and signer public key, so
  // one decision can be verified by a third party offline.
  const [receipts, setReceipts] = useState({ receipts: [], total: 0 });
  const [receiptChain, setReceiptChain] = useState(null);
  // A Merkle inclusion proof for one entry: checkable without the whole log.
  const [proof, setProof] = useState(null);
  // The durable signed file on disk, verified separately from the in-memory chain.
  const [fileCheck, setFileCheck] = useState(null);
  const [checkingFile, setCheckingFile] = useState(false);
  // AGT agent_sre.replay: the path a decision took, span by span. The chain
  // above proves a decision happened and was not edited; a trace shows how it
  // was reached and where the time went.
  const [traces, setTraces] = useState({ enabled: false, traces: [] });
  const [trace, setTrace] = useState(null);
  // Two selected traces can be handed to AGT's ReplayEngine, which returns
  // typed findings rather than a text diff.
  const [picked, setPicked] = useState([]);
  const [diff, setDiff] = useState(null);

  // Aggregate the loaded traces to surface the MCP governance story the row
  // list buries: how many traced calls went through the fifth gate, how many
  // it stopped, and how the extra hop shows up in latency. Every field is a
  // count or mean over real rows — nothing here is modelled.
  const traceStats = useMemo(() => {
    const rows = traces.traces || [];
    if (!rows.length) return null;
    const mean = xs => (xs.length
      ? Math.round(xs.reduce((s, t) => s + (t.duration_ms || 0), 0) / xs.length)
      : null);
    const mcp = rows.filter(t => t.is_mcp);
    const native = rows.filter(t => !t.is_mcp);
    const mcpDenied = mcp.filter(t => !t.success);
    return {
      total: rows.length,
      mcp: mcp.length,
      mcpAllowed: mcp.length - mcpDenied.length,
      mcpDenied: mcpDenied.length,
      proxyBlocked: mcp.filter(t => t.denied_by === 'mcp_proxy').length,
      earlierGate: mcpDenied.filter(t => t.denied_by && t.denied_by !== 'mcp_proxy').length,
      mcpAvgMs: mean(mcp),
      nativeAvgMs: mean(native),
    };
  }, [traces]);

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

  useEffect(() => { load(); loadReceipts(); loadTraces(); }, [filter]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(() => { load(); loadReceipts(); loadTraces(); }, 3000);
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

  const showProof = async (id) => {
    setProof({ id, loading: true });
    try { setProof({ id, ...(await api.audit.proof(id)) }); }
    catch (e) { setProof({ id, error: String(e.message || e) }); }
  };

  // Distinct from `Verify chain`, which re-walks the chain held in memory.
  const verifyFile = async () => {
    setCheckingFile(true);
    try { setFileCheck(await api.audit.verifyFile()); }
    catch (e) { setFileCheck({ valid: false, errors: [String(e.message || e)] }); }
    finally { setCheckingFile(false); }
  };

  const exportAccountability = async () => {
    const data = await api.audit.accountability(500);
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `accountability-export-${data.merkle_root?.slice(0, 12) || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const loadTraces = async () => {
    try { setTraces(await api.traces.list(50)); } catch (e) { /* keep UI responsive */ }
  };

  const showTrace = async (id) => {
    setTrace({ trace_id: id, loading: true });
    try { setTrace(await api.traces.get(id)); }
    catch (e) { setTrace({ trace_id: id, error: String(e.message || e) }); }
  };

  const pick = (id) => setPicked(p =>
    p.includes(id) ? p.filter(x => x !== id) : [...p, id].slice(-2));

  const runDiff = async () => {
    setDiff({ loading: true });
    try { setDiff(await api.traces.diff(picked[0], picked[1])); }
    catch (e) { setDiff({ error: String(e.message || e) }); }
  };

  const deleteTrace = async (id) => {
    try { await api.traces.remove(id); } catch (e) { /* surfaced by the reload */ }
    setPicked(p => p.filter(x => x !== id));
    loadTraces();
  };

  const loadReceipts = async () => {
    try { setReceipts(await api.receipts.list(50)); } catch (e) { /* keep UI responsive */ }
  };

  const verifyReceipts = async () => {
    try { setReceiptChain(await api.receipts.verify()); }
    catch (e) { setReceiptChain({ valid: false, errors: [String(e.message || e)] }); }
  };

  const exportReceipts = async () => {
    const data = await api.receipts.export();
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-receipts-${data.signer_public_key?.slice(0, 12) || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
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
    <div className="page">
      <PageHeader
        title="Audit Log"
        subtitle="A hash-chained event stream — every entry links to the one before it."
        actions={
          <>
            <button className={`btn btn-ghost btn-sm ${autoRefresh ? 'is-on' : ''}`}
              onClick={() => setAutoRefresh(v => !v)}>
              <RefreshCw size={13} className={autoRefresh ? 'spin' : ''} />
              {autoRefresh ? 'Live' : 'Paused'}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={load}>Refresh</button>
            <button className="btn btn-ghost btn-sm" onClick={exportChain}
              title="The raw hash-linked chain">
              <Download size={13} /> Export
            </button>
            {/* AGT turns each entry into an external accountability record —
                actor, operation, a digest of the policy that decided it — and
                an EEOAP-profile statement. Evidence rather than a dump. */}
            <button className="btn btn-ghost btn-sm" onClick={exportAccountability}
              title="Export as AGT accountability records with EEOAP statements">
              <Scale size={13} /> Accountability
            </button>
            <button className="btn btn-danger btn-sm" onClick={reset}>
              <Trash2 size={13} /> New chain
            </button>
          </>
        }
      />

      {/* Chain integrity */}
      <div className={`chain-bar ${chain ? (chain.valid ? 'ok' : 'bad') : ''}`}>
        {chain
          ? (chain.valid ? <ShieldCheck size={18} color="var(--green)" /> : <ShieldAlert size={18} color="var(--red)" />)
          : <ShieldCheck size={18} color="var(--text-3)" />}

        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 16, fontWeight: 600, color: chain ? (chain.valid ? 'var(--green)' : 'var(--red)') : 'var(--text-2)' }}>
            {chain
              ? (chain.valid
                  ? `Chain intact — ${chain.entry_count} ${chain.entry_count === 1 ? 'entry' : 'entries'} verified`
                  : `Chain broken — ${chain.error}`)
              : 'Chain integrity not yet checked'}
          </div>
          <code className="meta truncate" style={{ display: 'block' }}>merkle root {root || '—'}</code>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={verify} disabled={verifying}>
          {verifying ? 'Verifying' : 'Verify chain'}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={verifyFile} disabled={checkingFile}
          title="Re-read the durable HMAC-signed file and check it against its key">
          <HardDrive size={13} /> {checkingFile ? 'Checking' : 'Verify file'}
        </button>
      </div>

      {/* Two artefacts, verified two ways: the chain above is held in memory,
          this is what FileAuditSink actually wrote to disk. */}
      {fileCheck && (
        <div className={`chain-bar ${fileCheck.valid === true ? 'ok' : fileCheck.valid === false ? 'bad' : ''}`}
          style={{ marginTop: 'calc(var(--gap) * -0.5)' }}>
          {fileCheck.valid === true
            ? <ShieldCheck size={18} color="var(--green)" />
            : fileCheck.valid === false
              ? <ShieldAlert size={18} color="var(--red)" />
              : <HardDrive size={18} color="var(--text-3)" />}
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: 16, fontWeight: 600,
              color: fileCheck.valid === true ? 'var(--green)'
                : fileCheck.valid === false ? 'var(--red)' : 'var(--text-2)' }}>
              {fileCheck.valid === true ? 'Durable audit file verified'
                : fileCheck.valid === false ? 'Durable audit file does not verify'
                : 'Durable audit file not checked'}
            </div>
            <div className="meta">{fileCheck.reason}</div>
            {(fileCheck.errors || []).slice(0, 3).map((e, i) => (
              <div key={i} className="meta mono" style={{ color: 'var(--red)' }}>{e}</div>
            ))}
            {fileCheck.path && <code className="meta truncate" style={{ display: 'block' }}>{fileCheck.path}</code>}
          </div>
          <button className="btn btn-quiet btn-icon sm" onClick={() => setFileCheck(null)} title="Dismiss">
            <Trash2 size={13} color="var(--text-3)" />
          </button>
        </div>
      )}

      <StatStrip>
        <Stat label="Shown" value={events.length} sub={`${total} in chain`} />
        <Stat label="Allowed" value={events.filter(e => e.allowed).length} color="var(--green)" />
        <Stat label="Denied" value={events.filter(e => !e.allowed).length} color="var(--red)" />
        <Stat label="Tool calls" value={events.filter(e => e.event_type?.startsWith('tool.')).length} />
      </StatStrip>

      <div className="page-fill cols-audit">
        <Panel
          title="Events"
          scroll
          bodyClass="flush"
          actions={
            <>
              <input placeholder="Filter by agent ID" value={filter.agent_id}
                onChange={e => setFilter(f => ({ ...f, agent_id: e.target.value }))}
                className="mono audit-filter" />
              <select value={filter.event_type} onChange={e => setFilter(f => ({ ...f, event_type: e.target.value }))}
                className="mono audit-filter">
                <option value="">All event types</option>
                {Object.keys(EVENT_COLORS).map(k => <option key={k}>{k}</option>)}
              </select>
            </>
          }
        >
          {loading && events.length === 0 && <Empty>Loading events</Empty>}
          {events.length === 0 && !loading && (
            <Empty>No audit events yet. Interact with the Tool Playground or Trust panel to generate events.</Empty>
          )}
          {events.length > 0 && (
            <table className="table audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Agent</th>
                  <th>Decision</th>
                  <th>Details</th>
                  <th className="num">Entry</th>
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <tr key={e.id} className={e.allowed ? '' : 'denied'}>
                    <td className="mono meta nowrap">{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td>
                      <span className="cluster cluster-6" style={{ flexWrap: 'nowrap' }}>
                        <span className="badge-dot" style={{ background: color(e.event_type) }} />
                        <code style={{ color: color(e.event_type) }}>{e.event_type}</code>
                      </span>
                    </td>
                    <td><code className="muted">{e.agent_id}</code></td>
                    <td>
                      <Badge tone={e.allowed ? 'success' : 'danger'} size="sm">
                        {e.allowed ? 'allowed' : 'denied'}
                      </Badge>
                    </td>
                    <td className="detail-cell">
                      {Object.entries(e.details || {}).map(([k, v]) => (
                        <span key={k} className="detail-kv">
                          <span className="faint">{k}</span>{' '}
                          <span className="mono muted">
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        </span>
                      ))}
                    </td>
                    <td className="num meta">
                      <span className="cluster cluster-6" style={{ flexWrap: 'nowrap', justifyContent: 'flex-end' }}>
                        <code
                          title={`entry:    ${e.entry_hash || ''}
previous: ${e.previous_hash || '(genesis)'}`}
                        >
                          {e.entry_hash ? e.entry_hash.slice(0, 10) : '—'}
                        </code>
                        {/* Proves this one entry belongs to the chain without
                            handing over the rest of the log. */}
                        <button className="btn btn-quiet btn-icon sm" onClick={() => showProof(e.id)}
                          title="Merkle inclusion proof for this entry">
                          <Link2 size={12} color="var(--text-3)" />
                        </button>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        {/* Receipts and traces are checked less often than Events, so they
            share the right column instead of each claiming a full-width row. */}
        <div className="col-audit-right">
        {/* Signed MCP receipts — a second, portable evidence artefact. */}
        <Panel
          title="MCP governance receipts"
          desc="Ed25519-signed proof of one tool-call decision, hash-chained. Verifiable by a third party without this platform."
          scroll
          bodyClass="flush"
          actions={
            <>
              {/* Both are disabled with an empty ledger. A dimmed button that
                  says nothing reads as broken -- which is how this one was
                  reported -- so the reason it cannot run is on the control
                  itself rather than left for the reader to infer. */}
              <button className="btn btn-ghost btn-sm" onClick={verifyReceipts}
                disabled={!receipts.total}
                title={receipts.total
                  ? 'Re-check every signature and the parent-hash chain.'
                  : NO_RECEIPTS_HINT}>
                Verify receipts
              </button>
              <button className="btn btn-ghost btn-sm" onClick={exportReceipts}
                disabled={!receipts.total}
                title={receipts.total
                  ? 'Download the ledger, plus each receipt as SLSA provenance.'
                  : NO_RECEIPTS_HINT}>
                <Download size={13} /> Export
              </button>
            </>
          }
        >
          {receiptChain && (
            <div className="meta" style={{ padding: '8px 14px', display: 'flex',
              alignItems: 'center', gap: 7,
              color: receiptChain.valid ? 'var(--green)' : 'var(--red)' }}>
              {receiptChain.valid
                ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
              {receiptChain.valid
                ? `All ${receiptChain.count} receipt${receiptChain.count === 1 ? '' : 's'} verified — signatures and chain intact`
                : `Receipt ledger broken — ${receiptChain.errors?.join('; ')}`}
            </div>
          )}
          {receipts.signer_public_key && (
            <div className="meta mono truncate" style={{ padding: '0 14px 8px' }}>
              signer {receipts.signer_public_key}
              {!receipts.durable_key && ' · ephemeral key (set AGT_RECEIPT_KEY or AGT_STATE_DIR to pin)'}
            </div>
          )}
          {receipts.receipts.length === 0
            ? <Empty>No MCP tool calls decided yet — receipts are issued for MCP tools only.</Empty>
            : (
              <table className="table table-receipts">
                <thead>
                  <tr><th>Receipt</th><th>Tool</th><th>Decision</th><th>Agent DID</th><th className="num">Args hash</th></tr>
                </thead>
                <tbody>
                  {receipts.receipts.map(r => (
                    <tr key={r.receipt_id}>
                      <td className="meta">
                        <code title={`payload hash ${r.payload_hash}`}>{r.receipt_id.slice(0, 8)}</code>
                        {' '}
                        <FileCheck size={11}
                          color={r.signature_valid ? 'var(--green)' : 'var(--red)'} />
                      </td>
                      <td className="mono">{r.tool_name}</td>
                      <td>
                        <Badge tone={r.cedar_decision === 'allow' ? 'success' : 'danger'} size="sm">
                          {r.cedar_decision}
                        </Badge>
                      </td>
                      <td className="meta mono truncate" title={r.agent_did || undefined}>{r.agent_did || '—'}</td>
                      <td className="num meta"><code title={r.args_hash || undefined}>{r.args_hash?.slice(0, 10)}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </Panel>

        {/* AGT agent_sre.replay — the other half of an audit trail. */}
        <Panel
          title="Decision traces"
          desc="AGT ReplayEngine · which gate ran, in what order, and where the time went"
          scroll
          bodyClass="flush"
          actions={
            <button className="btn btn-ghost btn-sm" onClick={runDiff}
              disabled={picked.length !== 2}
              title="Diff the two selected traces with AGT's ReplayEngine">
              <GitCompare size={13} /> Diff {picked.length === 2 ? '2 selected' : `(${picked.length}/2)`}
            </button>
          }
        >
          {!traces.enabled
            ? <Empty>{traces.note || 'Tracing is off.'}</Empty>
            : traces.traces.length === 0
              ? <Empty>No governed calls traced yet. Make a call from the Tool Playground.</Empty>
              : (
                <>
                {traceStats && traceStats.mcp > 0 && (
                  <div className="trace-mcp-summary" title="Aggregated over the traces loaded below — MCP tools are the only ones that run the fifth gate (mcp_proxy).">
                    <StatStrip>
                      <Stat label="MCP tool calls" value={traceStats.mcp}
                        sub={`of ${traceStats.total} traced`} color="var(--purple)" />
                      <Stat label="Allowed by proxy" value={traceStats.mcpAllowed}
                        color="var(--green)" />
                      <Stat label="Blocked at MCP proxy" value={traceStats.proxyBlocked}
                        sub={traceStats.earlierGate
                          ? `+${traceStats.earlierGate} at an earlier gate`
                          : 'the fifth gate'}
                        color="var(--red)" />
                      <Stat label="Avg MCP latency"
                        value={traceStats.mcpAvgMs == null ? '—' : `${traceStats.mcpAvgMs} ms`}
                        sub={traceStats.nativeAvgMs == null
                          ? 'MCP-governed calls'
                          : `native ${traceStats.nativeAvgMs} ms`}
                        color="var(--purple)" />
                    </StatStrip>
                  </div>
                )}
                <table className="table">
                  <thead>
                    <tr>
                      <th style={{ width: 34 }} />
                      <th>Time</th>
                      <th>Call</th>
                      <th>Agent</th>
                      <th>Outcome</th>
                      <th className="num">Spans</th>
                      <th className="num">Duration</th>
                      <th className="num" />
                    </tr>
                  </thead>
                  <tbody>
                    {traces.traces.map(t => (
                      <tr key={t.trace_id} className={t.success ? '' : 'denied'}>
                        <td>
                          <input type="checkbox" checked={picked.includes(t.trace_id)}
                            onChange={() => pick(t.trace_id)}
                            title="Select two traces to diff" />
                        </td>
                        <td className="mono meta nowrap">
                          {new Date(t.written_at).toLocaleTimeString()}
                        </td>
                        <td>
                          <button className="btn btn-quiet btn-sm" onClick={() => showTrace(t.trace_id)}>
                            <Route size={12} /> {t.task_input}
                          </button>
                          {t.is_mcp && <Badge tone="purple" size="sm" title="Governed as an MCP tool — runs the fifth gate (mcp_proxy) before dispatch.">MCP</Badge>}
                        </td>
                        <td><code className="muted">{t.agent_id}</code></td>
                        <td>
                          <Badge tone={t.success ? 'success' : 'danger'} size="sm"
                            title={t.denied_by ? `Stopped at the ${t.denied_by} gate` : undefined}>
                            {t.success ? 'allowed' : t.denied_by ? `denied · ${t.denied_by}` : 'denied'}
                          </Badge>
                        </td>
                        <td className="num meta">{t.span_count}</td>
                        <td className="num meta mono">{t.duration_ms} ms</td>
                        <td className="num">
                          <button className="btn btn-quiet btn-icon sm" onClick={() => deleteTrace(t.trace_id)}
                            title="Delete this trace">
                            <Trash2 size={12} color="var(--text-3)" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </>
              )}
        </Panel>
        </div>
      </div>

      {proof && (
        <Modal title="Merkle inclusion proof" subtitle={proof.id}
          onClose={() => setProof(null)}
          footer={<button className="btn btn-ghost" onClick={() => setProof(null)}>Close</button>}>
          <p className="muted" style={{ fontSize: 16, marginBottom: 14 }}>
            An inclusion proof shows this entry belongs to the chain, using only the
            sibling hashes on the path to the root — so it can be checked without
            being given the rest of the log.
          </p>
          {proof.loading && <div className="meta">Loading…</div>}
          {proof.error && <code style={{ color: 'var(--yellow)' }}>{proof.error}</code>}
          {proof.merkle_root && (
            <>
              <div className="cluster cluster-6" style={{ marginBottom: 14 }}>
                {proof.verified === true
                  ? <Badge tone="success"><ShieldCheck size={12} /> proof verifies</Badge>
                  : proof.verified === false
                    ? <Badge tone="danger"><ShieldAlert size={12} /> proof does not verify</Badge>
                    : <Badge tone="neutral">no sibling path</Badge>}
              </div>
              {proof.reason && <div className="meta" style={{ marginBottom: 14 }}>{proof.reason}</div>}
              <div className="field-label">Merkle root</div>
              <code className="inline-code" style={{ wordBreak: 'break-all', display: 'block', marginBottom: 14 }}>
                {proof.merkle_root}
              </code>
              {(proof.merkle_proof || []).length > 0 && (
                <>
                  <div className="field-label">
                    Path to the root — {proof.merkle_proof.length} sibling
                    {proof.merkle_proof.length === 1 ? '' : 's'}
                  </div>
                  <table className="table">
                    <thead><tr><th>Step</th><th>Sibling hash</th><th>Side</th></tr></thead>
                    <tbody>
                      {proof.merkle_proof.map(([hash, side], i) => (
                        <tr key={i}>
                          <td className="meta nums">{i + 1}</td>
                          <td className="mono truncate"><code>{hash}</code></td>
                          <td><Badge tone="neutral" size="sm">{side}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </>
          )}
        </Modal>
      )}

      {trace && (
        <Modal title="Decision trace" subtitle={trace.trace_id}
          width="min(920px, 100%)"
          onClose={() => setTrace(null)}
          footer={<button className="btn btn-ghost" onClick={() => setTrace(null)}>Close</button>}>
          {trace.loading && <div className="meta">Loading…</div>}
          {trace.error && <code style={{ color: 'var(--yellow)' }}>{trace.error}</code>}
          {trace.spans && (
            <>
              {/* The path first, walked in order, then the same spans as bars.
                  The rail answers "where did it go and where did it stop"; the
                  bars answer "where did the time go". Reading the second
                  without the first is what made a trace hard to follow. */}
              <TraceReplay trace={trace} />

              <p className="muted" style={{ fontSize: 16, marginBottom: 14 }}>
                Every bar is measured, not modelled. Ring, policy and the MCP proxy
                share one span because AGT decides all three inside{' '}
                <code>govern()</code> and returns a single outcome — three bars here
                would be three invented durations. The remote call gets its own bar
                because the connector really did time it, and the audit, alert and
                receipt writes get theirs, so the bars account for the whole trace
                rather than leaving a gap to guess at.
              </p>
              <div className="cluster cluster-6" style={{ marginBottom: 14 }}>
                <Badge tone={trace.success ? 'success' : 'danger'}>
                  {trace.metadata?.['agent.policy.decision'] || (trace.success ? 'allow' : 'deny')}
                </Badge>
                <span className="meta mono">{trace.duration_ms} ms total</span>
                <span className="meta">{trace.agent_id}</span>
                <span className="meta">{trace.task_output}</span>
              </div>

              {trace.spans.map(sp => {
                const pct = trace.duration_ms > 0
                  ? Math.max(1, (sp.duration_ms / trace.duration_ms) * 100) : 1;
                const tone = sp.status === 'error' ? 'var(--red)'
                  : sp.kind === 'tool_call' ? 'var(--green)'
                    : sp.kind === 'internal' ? 'var(--text-3)' : 'var(--accent)';
                return (
                  <div key={sp.span_id} style={{ marginBottom: 10 }}>
                    <div className="cluster cluster-6" style={{ justifyContent: 'space-between' }}>
                      <code style={{ color: tone }}>{sp.name}</code>
                      <span className="meta mono">{sp.duration_ms} ms</span>
                    </div>
                    <div style={{ height: 6, background: 'var(--surface-2)', borderRadius: 3,
                      overflow: 'hidden', margin: '4px 0 3px' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: tone }} />
                    </div>
                    <div className="cluster cluster-6">
                      {Object.entries(sp.attributes || {}).map(([k, v]) => (
                        <span key={k} className="meta faint">
                          {k} <span className="mono muted">{String(v)}</span>
                        </span>
                      ))}
                    </div>
                    {sp.error && (
                      <div className="meta mono" style={{ color: 'var(--red)' }}>{sp.error}</div>
                    )}
                  </div>
                );
              })}

              <div className="field-label" style={{ marginTop: 14 }}>Content hash</div>
              <code className="inline-code" style={{ wordBreak: 'break-all', display: 'block' }}>
                {trace.content_hash}
              </code>
              <p className="meta" style={{ marginTop: 8 }}>
                AGT hashes the trace content, so two structurally identical calls hash
                the same and a call that decided differently does not.
              </p>
            </>
          )}
        </Modal>
      )}

      {diff && (
        <Modal title="Replay diff" subtitle="AGT ReplayEngine"
          onClose={() => setDiff(null)}
          footer={<button className="btn btn-ghost" onClick={() => setDiff(null)}>Close</button>}>
          {diff.loading && <div className="meta">Comparing…</div>}
          {diff.error && <code style={{ color: 'var(--yellow)' }}>{diff.error}</code>}
          {diff.a && (
            <>
              <p className="muted" style={{ fontSize: 16, marginBottom: 14 }}>
                Typed findings from AGT rather than a text diff, so &ldquo;the same call
                decided differently&rdquo; is a machine-readable fact rather than
                something a reader has to spot.
              </p>
              <div className="cluster cluster-6" style={{ marginBottom: 14 }}>
                <code className="muted">A {diff.a.trace_id.slice(0, 8)}</code>
                <Badge tone={diff.a.success ? 'success' : 'danger'} size="sm">
                  {diff.a.success ? 'allowed' : 'denied'}
                </Badge>
                <code className="muted">B {diff.b.trace_id.slice(0, 8)}</code>
                <Badge tone={diff.b.success ? 'success' : 'danger'} size="sm">
                  {diff.b.success ? 'allowed' : 'denied'}
                </Badge>
              </div>
              {diff.identical
                ? <Empty>No differences. The two calls took the same path to the same outcome.</Empty>
                : (
                  <table className="table">
                    <thead><tr><th>Finding</th><th>Span</th><th>What differs</th></tr></thead>
                    <tbody>
                      {diff.diffs.map((d, i) => (
                        <tr key={i}>
                          <td><Badge tone="warn" size="sm">{d.type.replace(/_/g, ' ')}</Badge></td>
                          <td><code className="muted">{d.span}</code></td>
                          <td className="meta">{d.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
            </>
          )}
        </Modal>
      )}
    </div>
  );
}
