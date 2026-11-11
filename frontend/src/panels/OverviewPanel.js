/**
 * Overview — live governance posture, and nothing else.
 *
 * Laid out as a bento grid (see ../BentoGrid.js): the audit feed in a tall
 * column, the decision flow across the top of the rest, and counts, allow rate,
 * attention, policy and agent posture packed beneath it.
 *
 * Every number here is read from an endpoint. That constraint removed several
 * things a governance dashboard is normally expected to show, and they are
 * listed rather than quietly approximated:
 *
 *   · **No week-over-week deltas.** Nothing stores a historical snapshot, so
 *     "+3 this week" could only be invented. The tiles show the current count.
 *   · **No risk score.** The platform scores *trust* (0–1, what the gate
 *     enforces) and AGT scores *reputation* (0–1000, advisory). An inverted
 *     "risk" number would be a third score nothing computes.
 *   · **No environment / agent-group / time-range filters.** The API has no
 *     such concepts; a selector that changed nothing would be furniture.
 *   · **Policy compliance reads "no measurements" until an agent has made
 *     governed calls.** A fresh SLO reports `compliance: null`, and rendering
 *     that as 100% is how a dashboard starts lying.
 *
 * The decision-flow diagram is one of five real traces through the system
 * (see ./pipelines.js), refreshed on each visit.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  Check, Ban, AlertTriangle, Minus, User, ShieldCheck, ShieldAlert,
  Power, RefreshCw, BellRing, FlaskConical, Trash2,
} from '../icons';
import { api } from '../api';
import {
  Panel, Badge, Empty, Meter, ScoreMeter, Notice,
  actionTone, scoreColor,
} from '../ui';
import { BOARD, NODE_R, nextPipeline } from './pipelines';
import { BentoGrid } from '../BentoGrid';

/* ── formatting ──────────────────────────────────────────────────────────── */

/** `RING_2_STANDARD` → `Ring 2`. The panel shows the number; the tooltip the name. */
const ringLabel = (ring) => {
  const m = /RING_(\d)/.exec(ring || '');
  return m ? `Ring ${m[1]}` : '—';
};

const pct = (n, total) => (total > 0 ? Math.round((n / total) * 100) : 0);

const clock = (ts) => {
  const d = ts instanceof Date ? ts : new Date(ts);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString();
};

/** Alert timestamps are epoch seconds; audit timestamps are ISO strings. */
const ago = (value) => {
  if (value == null) return '';
  const then = typeof value === 'number' ? value * 1000 : Date.parse(value);
  if (Number.isNaN(then)) return '';
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
};

const SEVERITY_TONE = { critical: 'danger', error: 'danger', warning: 'warn', info: 'info' };
const SEVERITY_ICON = { critical: ShieldAlert, error: ShieldAlert, warning: AlertTriangle, info: BellRing };

/* ── KPI tile ────────────────────────────────────────────────────────────── */

function Kpi({ icon: Icon, tone = 'accent', label, value, sub, title }) {
  return (
    <div className={`gov-kpi tone-${tone}`} title={title}>
      <span className="gov-kpi-icon"><Icon size={20} /></span>
      <div className="gov-kpi-text">
        <p className="gov-kpi-label">{label}</p>
        <p className="gov-kpi-value">{value}</p>
        {sub && <p className="gov-kpi-sub">{sub}</p>}
      </div>
    </div>
  );
}

/**
 * Allow rate across the audit chain, as a dial.
 *
 * This deliberately does *not* show the SOC 2 compliance score. That number is
 * real and AGT computes it, but producing it means calling
 * `/compliance/report`, which re-hashes the whole audit chain **and appends a
 * `compliance.report` entry to it**. A read-only dashboard must not write to
 * the tamper-evident record simply because somebody opened a page, nor make
 * every page view cost a full chain verification. The compliance score lives
 * on the Compliance panel, where generating a report is the deliberate act it
 * should be.
 *
 * It is also not `/stats.allow_rate`. That field divides by *every* audit
 * entry, and the chain holds far more than decisions — policy edits, agent
 * registrations, compliance reports. A single report with an unmet control is
 * written `denied`, so a quiet instance can show an allow rate near zero
 * without a single call having been refused. The rate below is computed over
 * `tool.call.*` entries only, which is the population the word "allow" refers
 * to, and the window it covers is named rather than implied.
 */
function DecisionDial({ events }) {
  const decisions = events.filter(e => (e.event_type || '').startsWith('tool.call.'));
  const denials = decisions.filter(e => (e.event_type || '').startsWith('tool.call.denied')).length;
  const total = decisions.length;
  const rate = total > 0 ? Math.round(((total - denials) / total) * 100) : null;
  const R = 26;
  const C = 2 * Math.PI * R;
  const tone = rate == null ? 'var(--text-3)'
    : rate >= 90 ? 'var(--green)' : rate >= 60 ? 'var(--yellow)' : 'var(--red)';

  return (
    <div className="gov-kpi gov-kpi-dial"
      title="Share of governed tool calls that were allowed, over the audit entries currently loaded.">
      <svg className="gov-dial" viewBox="0 0 64 64" aria-hidden>
        <circle cx="32" cy="32" r={R} className="gov-dial-track" />
        {rate != null && (
          <circle cx="32" cy="32" r={R} className="gov-dial-fill"
            stroke={tone} strokeDasharray={`${(rate / 100) * C} ${C}`} />
        )}
      </svg>
      <div className="gov-kpi-text">
        <p className="gov-kpi-label">Allow rate</p>
        <p className="gov-kpi-value" style={{ color: tone }}>
          {rate == null ? 'No decisions' : `${rate}`}
          {rate != null && <i className="gov-kpi-unit">%</i>}
        </p>
        <p className="gov-kpi-sub">
          {total > 0
            ? `${denials} denied of ${total} recent decisions`
            : 'no governed calls yet'}
        </p>
      </div>
    </div>
  );
}

/* ── governance decision flow ────────────────────────────────────────────── */

function PipelineCard({ pipeline }) {
  const [i, setI] = useState(0);

  // The stage counts differ between variants, so the timer is rebuilt when the
  // pipeline changes rather than closing over a stale length.
  useEffect(() => {
    setI(0);
    const n = pipeline.stages.length;
    const t = setInterval(() => setI(p => (p + 1) % n), 1700);
    return () => clearInterval(t);
  }, [pipeline]);

  const stage = pipeline.stages[i] ?? pipeline.stages[0];
  const liveEdges = pipeline.edges.filter(e => stage.live.includes(e.id));

  return (
    <div className="pipe">
      <svg className="pipe-svg" viewBox={`0 0 ${BOARD.w} ${BOARD.h}`}
        preserveAspectRatio="xMidYMid meet" aria-hidden>
        <defs>
          <pattern id="pipe-dots" width="20" height="20" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.7" className="pipe-dot" />
          </pattern>
          <linearGradient id="pipe-scan" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0%" className="pipe-scan-edge" />
            <stop offset="50%" className="pipe-scan-mid" />
            <stop offset="100%" className="pipe-scan-edge" />
          </linearGradient>
        </defs>

        <rect width={BOARD.w} height={BOARD.h} fill="url(#pipe-dots)" />

        {/* HUD brackets — four corners, drawn as open right angles. */}
        <g className="pipe-hud">
          <path d="M 8 30 V 8 H 30" />
          <path d={`M ${BOARD.w - 30} 8 H ${BOARD.w - 8} V 30`} />
          <path d={`M ${BOARD.w - 8} ${BOARD.h - 30} V ${BOARD.h - 8} H ${BOARD.w - 30}`} />
          <path d={`M 30 ${BOARD.h - 8} H 8 V ${BOARD.h - 30}`} />
        </g>

        {/* A slow sweep across the field, purely atmospheric. */}
        <rect className="pipe-scanline" x="-170" y="0" width="170" height={BOARD.h}
          fill="url(#pipe-scan)" />

        <text className="pipe-board-name" x="34" y="28">
          {pipeline.name.toUpperCase()}
        </text>

        {/* Every edge carries its own hue at rest, so the whole route reads
            as a coloured circuit rather than grey pipework with one lit link. */}
        {pipeline.edges.map(e => (
          <g key={e.id} className={`tone-${e.tone}`}>
            <path d={e.d} className="pipe-edge-tinted" />
          </g>
        ))}

        {liveEdges.map(e => (
          <g key={`live-${e.id}`} className={`tone-${e.tone}`}>
            {/* pathLength 1 normalises every edge, so one keyframe fits them all. */}
            <path d={e.d} pathLength="1" fill="none" className="pipe-edge-live" />
            <path d={e.d} pathLength="1" fill="none" className="pipe-packet" />
          </g>
        ))}

        {pipeline.nodes.map(n => {
          const on = stage.lit.includes(n.id);
          // The node the packet is leaving is the one that gets the halo.
          const active = on && stage.lit[stage.lit.length - 1] === n.id;
          const Icon = n.icon;
          return (
            <g key={n.id}
              className={`pipe-node tone-${n.tone} ${on ? 'lit' : ''} ${active ? 'active' : ''}`}>
              {active && (
                <>
                  <circle cx={n.x} cy={n.y} r={NODE_R} className="pipe-pulse" />
                  <circle cx={n.x} cy={n.y} r={NODE_R + 7} className="pipe-ring" />
                </>
              )}
              <rect x={n.x - NODE_R} y={n.y - NODE_R} width={NODE_R * 2} height={NODE_R * 2}
                rx="19" className="pipe-node-box" />
              <g transform={`translate(${n.x - 12} ${n.y - 12})`}><Icon size={24} /></g>
              <text x={n.x} y={n.y + NODE_R + 20} className="pipe-node-label">{n.label}</text>
            </g>
          );
        })}
      </svg>

      <div className={`pipe-readout tone-${stage.tone}`}>
        <span className="pipe-stage-n">
          {String(i + 1).padStart(2, '0')}<i>/{pipeline.stages.length}</i>
        </span>
        <div className="pipe-stage-text">
          <p className="pipe-stage-title">{stage.title}</p>
          <p className="pipe-stage-note">{stage.note}</p>
        </div>
        <div className="pipe-ticks">
          {pipeline.stages.map((s, k) => (
            <span key={s.title}
              className={`pipe-tick ${k === i ? 'on' : ''} ${k < i ? 'done' : ''}`} />
          ))}
        </div>
      </div>
    </div>
  );
}

/* ── attention required ──────────────────────────────────────────────────── */

/**
 * AGT's AlertManager feed, deduplicated upstream. `suppressed` is what the
 * deduplicator swallowed — a retrying agent raises one alert and a rising
 * suppression count, which is the whole reason to route through AGT rather
 * than keep a list.
 */
function AttentionList({ alerts, stats, loaded }) {
  if (!loaded) return <Empty>Loading…</Empty>;
  if (!alerts.length) {
    return <Empty>Nothing to act on. Gate denials, error-budget burn and behavioural anomalies all surface here.</Empty>;
  }
  return (
    <>
      <ul className="gov-attn">
        {alerts.map((a, i) => {
          const Icon = SEVERITY_ICON[a.severity] || BellRing;
          const tone = SEVERITY_TONE[a.severity] || 'neutral';
          return (
            <li key={`${a.dedup_key || a.title}-${i}`} className={`gov-attn-row tone-${tone}`}>
              <span className="gov-attn-icon"><Icon size={16} /></span>
              <div className="gov-attn-text">
                <p className="gov-attn-title">{a.title}</p>
                <p className="gov-attn-msg">{a.message}</p>
                <p className="gov-attn-meta">
                  {a.agent_id && <span className="mono">{a.agent_id}</span>}
                  {a.metadata?.gate && <> · gate <span className="mono">{a.metadata.gate}</span></>}
                  {a.source && <> · {a.source}</>}
                </p>
              </div>
              <div className="gov-attn-side">
                <Badge tone={tone} size="sm">{a.severity}</Badge>
                <span className="gov-attn-ago">{ago(a.timestamp)}</span>
              </div>
            </li>
          );
        })}
      </ul>
      {stats?.suppressed > 0 && (
        <p className="gov-note">
          {stats.suppressed} duplicate {stats.suppressed === 1 ? 'alert' : 'alerts'} suppressed by AGT&apos;s deduplicator.
        </p>
      )}
    </>
  );
}

/* ── policy posture + reliability ────────────────────────────────────────── */

function PolicyPosture({ policy, slos, events, loaded }) {
  const rules = policy?.rules ?? [];
  // Event counts come from the audit chain: how many decisions each rule has
  // actually made. A rule with no hits reads as 0 rather than being hidden.
  const hits = events.reduce((acc, e) => {
    const rule = e.details?.rule;
    if (rule) acc[rule] = (acc[rule] || 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <p className="gov-sub">Policy posture{policy?.name ? <> · <span className="mono">{policy.name}</span></> : null}</p>
      {!loaded ? <Empty>Loading…</Empty>
        : !rules.length ? <Empty>This policy has no rules, so its default action decides every call.</Empty>
          : (
            <table className="table table-flush gov-table">
              <thead>
                <tr><th>Rule</th><th>Action</th><th className="num">Decisions</th></tr>
              </thead>
              <tbody>
                {rules.map(r => (
                  <tr key={r.name}>
                    <td>
                      <span className="gov-rule">{r.name}</span>
                      {r.condition && <span className="gov-rule-cond mono">{r.condition}</span>}
                    </td>
                    <td><Badge tone={actionTone(r.action)} size="sm">{r.action}</Badge></td>
                    <td className="num">{hits[r.name] || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

      <p className="gov-sub gov-sub-gap">Reliability &amp; SLO</p>
      {!slos.length
        ? <Empty>No SLOs yet. One is created per agent as it is registered.</Empty>
        : (
          <ul className="gov-slos">
            {slos.slice(0, 4).map(s => {
              const budget = s.error_budget || {};
              const remaining = budget.remaining_percent ?? budget.remaining ?? null;
              return (
                <li key={s.name} className="gov-slo">
                  <div className="gov-slo-head">
                    <span className="mono">{s.agent_id}</span>
                    <Badge tone={s.status === 'healthy' ? 'success' : s.status === 'unknown' ? 'neutral' : 'warn'} size="sm" dot>
                      {s.status}
                    </Badge>
                  </div>
                  {remaining == null
                    ? <p className="gov-slo-none">No measurements yet — error budget is unset until governed calls land.</p>
                    : <Meter value={remaining} color={remaining >= 50 ? 'var(--green)' : remaining >= 20 ? 'var(--yellow)' : 'var(--red)'} />}
                  {s.evidence_only === false && (
                    <p className="gov-slo-none">{s.synthetic_measurements} synthetic measurement(s) included.</p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
    </>
  );
}

/* ── agent posture ───────────────────────────────────────────────────────── */

function AgentPosture({ agents, trust, slos, loaded }) {
  if (!loaded) return <Empty>Loading…</Empty>;
  if (!agents.length) return <Empty>No agents registered yet.</Empty>;

  const trustBy = Object.fromEntries((trust?.agents ?? []).map(a => [a.agent_id, a]));
  const sloBy = Object.fromEntries((slos ?? []).map(s => [s.agent_id, s]));

  return (
    <div className="table-wrap">
      <table className="table table-flush gov-table">
        <thead>
          <tr>
            <th>Agent</th><th>Trust</th><th>Ring</th>
            <th>Policy compliance</th><th>State</th>
          </tr>
        </thead>
        <tbody>
          {agents.map(a => {
            const t = trustBy[a.id];
            const slo = sloBy[a.id];
            const ind = (slo?.indicators ?? []).find(x => x.name === 'policy_compliance');
            const compliance = ind?.compliance;
            return (
              /* Keyed on the AGT lifecycle id, not the readable name.
                 Decommissioning keeps the record, so registering an agent of
                 the same name again leaves two rows sharing `id` and only
                 `agent_id` tells them apart -- React was rendering duplicate
                 keys and warning about it. */
              <tr key={a.agent_id || a.id}>
                <td>
                  <span className="gov-agent mono">{a.name}</span>
                  <span className="gov-agent-sub">{a.owner}</span>
                </td>
                <td><ScoreMeter score={a.trust_score} width={56} /></td>
                <td>
                  <Badge tone="neutral" size="sm" title={a.ring}>{ringLabel(a.ring)}</Badge>
                  {t && !t.passes_trust_gate && <Badge tone="danger" size="sm">below gate</Badge>}
                </td>
                <td>
                  {compliance == null
                    ? <span className="gov-none" title="A fresh SLO has no measurements; showing a percentage here would be invented.">no measurements</span>
                    : (
                      <div className="meter-row">
                        <Meter value={compliance * 100} color={scoreColor(compliance)} width={56} />
                        <span className="meter-value">{Math.round(compliance * 100)}%</span>
                      </div>
                    )}
                </td>
                <td>
                  <Badge tone={a.state === 'active' ? 'success' : 'danger'} size="sm" dot>{a.state}</Badge>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ── recent audit activity ───────────────────────────────────────────────── */

const EVENT_STYLE = {
  allowed: { icon: Check, tone: 'success', label: 'allowed' },
  denied: { icon: Ban, tone: 'danger', label: 'denied' },
  other: { icon: Minus, tone: 'neutral', label: 'recorded' },
};

/**
 * Only a governed tool call has a verdict.
 *
 * Every audit entry carries an `allowed` flag, but it means different things
 * per event type: on `tool.call.*` it is the gate decision, while on
 * `compliance.report` it means "every control was met" and on `agent.rejected`
 * it means the agent was refused. Reading that flag as a verdict painted a
 * compliance report with an unmet control as a red DENIED, which is not what
 * happened. So the decision styling is keyed off the event type, and
 * everything else is reported as recorded.
 */
const eventKind = (e) => {
  const type = e.event_type || '';
  if (type.startsWith('tool.call.denied')) return 'denied';
  if (type === 'tool.call.allowed') return 'allowed';
  return 'other';
};

const TABS = [
  { id: 'all', label: 'All' },
  { id: 'allowed', label: 'Allowed' },
  { id: 'denied', label: 'Denied' },
];

function AuditActivity({ events, loaded }) {
  const [tab, setTab] = useState('all');
  // The feed lives in the tall bento column and scrolls inside it, so it can
  // show more than a short card could.
  const rows = events.filter(e => tab === 'all' || eventKind(e) === tab).slice(0, 20);

  return (
    <>
      <div className="gov-tabs" role="tablist">
        {TABS.map(t => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id}
            className={`gov-tab ${tab === t.id ? 'on' : ''}`}
            onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {!loaded ? <Empty>Loading…</Empty>
        : !rows.length ? <Empty>No {tab === 'all' ? '' : tab} decisions recorded yet.</Empty>
          : (
            <ul className="gov-feed">
              {rows.map(e => {
                const kind = EVENT_STYLE[eventKind(e)];
                const Icon = kind.icon;
                return (
                  <li key={e.id} className={`gov-feed-row tone-${kind.tone}`}>
                    <span className="gov-feed-time mono">{clock(e.timestamp)}</span>
                    <span className="gov-feed-icon"><Icon size={14} /></span>
                    <div className="gov-feed-text">
                      <p className="gov-feed-agent mono">{e.agent_id}</p>
                      <p className="gov-feed-type">{e.event_type}</p>
                    </div>
                    <Badge tone={kind.tone} size="sm">{kind.label}</Badge>
                  </li>
                );
              })}
            </ul>
          )}
    </>
  );
}

/* ── page ────────────────────────────────────────────────────────────────── */

export default function OverviewPanel() {
  const [pipeline] = useState(nextPipeline);
  const [stats, setStats] = useState(null);
  const [trust, setTrust] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [alertStats, setAlertStats] = useState(null);
  const [slos, setSlos] = useState([]);
  const [events, setEvents] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [online, setOnline] = useState(null);
  // The worked demo scenario: whether it is loaded, whether a load/unload is
  // in flight, and the last thing the endpoint said about it.
  const [demo, setDemo] = useState(null);
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoNote, setDemoNote] = useState(null);

  const load = useCallback(async () => {
    const [st, tr, al, sl, au, po, dm] = await Promise.allSettled([
      api.stats(),
      api.trust.overview(),
      api.sre.alerts(6),
      api.sre.slos(),
      api.audit.get(25),
      api.policies.list().then(r => {
        const first = (r.policies ?? r ?? [])[0];
        const name = typeof first === 'string' ? first : first?.name;
        return name ? api.policies.get(name) : null;
      }),
      api.demo.status(),
    ]);

    if (st.status === 'fulfilled') setStats(st.value);
    if (tr.status === 'fulfilled') setTrust(tr.value);
    if (al.status === 'fulfilled') {
      setAlerts(al.value.alerts ?? []);
      setAlertStats(al.value.stats ?? null);
    }
    if (sl.status === 'fulfilled') setSlos(Array.isArray(sl.value) ? sl.value : []);
    if (au.status === 'fulfilled') setEvents(au.value.events ?? []);
    if (po.status === 'fulfilled') setPolicy(po.value);
    if (dm.status === 'fulfilled') setDemo(dm.value);

    const ok = st.status === 'fulfilled';
    setOnline(ok);
    if (ok) setUpdatedAt(new Date());
    setLoaded(true);
  }, []);

  useEffect(() => {
    let live = true;
    const tick = () => { if (live) load(); };
    tick();
    const timer = setInterval(tick, 8000);
    return () => { live = false; clearInterval(timer); };
  }, [load]);

  /**
   * Load or unload the demo scenario.
   *
   * Loading fires real governed calls, so it takes a moment and the button
   * says so rather than appearing to do nothing. Unloading reports what it
   * could not remove: the decisions those agents made are in an append-only
   * chain, and that message is surfaced rather than swallowed, because a
   * button that implied a clean slate would be the dishonest part.
   */
  const toggleDemo = async () => {
    setDemoBusy(true);
    setDemoNote(null);
    try {
      if (demo?.loaded) {
        const body = await api.demo.unload();
        setDemoNote({ tone: 'info', text: body.note });
      } else {
        const body = await api.demo.load();
        const gates = (body.gates_exercised || []).join(', ');
        const mcp = body.mcp || {};
        const mcpNote = mcp.skipped
          ? ` MCP receipts were skipped: ${mcp.skipped}`
          : mcp.calls?.length
            ? ` ${mcp.calls.length} MCP call(s) decided — signed receipts are in the Audit panel.`
            : '';
        setDemoNote(body.surprises?.length
          ? { tone: 'warn',
              text: `${body.surprises.length} call(s) did not match the scenario's `
                  + 'expected verdict. The data is real, but check the console.' }
          : { tone: 'success',
              text: `${body.calls} governed calls decided. Gates that denied: ${gates}.${mcpNote}` });
      }
      await load();
    } catch (err) {
      setDemoNote({ tone: 'danger',
        text: typeof err.message === 'string' ? err.message
          : 'The request failed. Loading and removing demo data need the admin role.' });
    } finally {
      setDemoBusy(false);
    }
  };

  const total = stats?.total_agents ?? 0;
  const byState = stats?.lifecycle?.by_state ?? {};
  const active = byState.active ?? 0;
  const suspended = byState.suspended ?? 0;
  const belowGate = (trust?.agents ?? []).filter(a => !a.passes_trust_gate).length;
  const minTrust = trust?.min_trust ?? 0.3;

  return (
    <div className="page gov">
      {/* Title and actions on their own line, the tiles on the next at full
          width -- they used to share a row with the title, which is exactly
          what was squeezing them small. Counts only -- no deltas: nothing
          stores history. */}
      <header className="page-head gov-head">
        <div className="gov-head-top">
          <div className="page-head-text">
            <h1 className="page-title">AgentGuard</h1>
            <p className="page-sub">Real-time governance posture across every registered agent.</p>
          </div>
          <div className="page-actions">
            <span className={`gov-live ${online === false ? 'off' : ''}`}>
              <span className="status-dot" />
              {online === false ? 'API offline' : 'Live'}
              {updatedAt && <i>Updated {clock(updatedAt)}</i>}
            </span>
            <button type="button" className="btn btn-ghost btn-sm"
              onClick={toggleDemo} disabled={demoBusy || demo == null}
              title={demo?.loaded
                ? 'Decommission the demo agents and delete their policy. Their '
                  + 'decisions stay in the audit chain -- it is append-only.'
                : 'Register a small fleet and run real governed calls through '
                  + 'every gate, so the panels have something to show.'}>
              {demo?.loaded ? <Trash2 size={14} /> : <FlaskConical size={14} />}
              {demoBusy ? 'Working...' : demo?.loaded ? 'Remove demo data' : 'Load demo data'}
            </button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={load}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        </div>

        <div className="gov-kpis">
          <Kpi icon={User} tone="accent" label="Total agents" value={total}
            sub="registered" title="Registered with the lifecycle manager." />
          <Kpi icon={ShieldCheck} tone="green" label="Active" value={active}
            sub={`${pct(active, total)}% of the estate`}
            title="AGT lifecycle state ACTIVE — the only state that passes gate 1." />
          <Kpi icon={ShieldAlert} tone="yellow" label="Below trust gate" value={belowGate}
            sub={`trust < ${minTrust}`}
            title="Denied at gate 2 before policy runs." />
          <Kpi icon={Power} tone="red" label="Suspended" value={suspended}
            sub="kill switch engaged"
            title="AGT lifecycle state SUSPENDED — not overridable by policy." />
          <DecisionDial events={events} />
        </div>
      </header>

      {demoNote && (
        <Notice tone={demoNote.tone} onClose={() => setDemoNote(null)}>
          {demoNote.text}
        </Notice>
      )}

      {/* Bento layout: every section from the previous dashboard is still here,
          regrouped so the counts sit together and the audit feed gets the tall
          column. Counts only in the tiles -- no deltas: nothing stores history. */}
      <BentoGrid
        hero={
          <Panel title="Governance decision flow"
            desc="From agent request to final decision, every step is governed."
            className="gov-flow">
            <PipelineCard pipeline={pipeline} />
          </Panel>
        }
        tall={
          <Panel title="Recent audit activity" scroll className="gov-activity">
            <AuditActivity events={events} loaded={loaded} />
          </Panel>
        }
        attention={
          <Panel
            title="Attention required"
            actions={alerts.length ? <Badge tone="danger" size="sm">{alerts.length}</Badge> : null}
            className="gov-attn-panel">
            <AttentionList alerts={alerts} stats={alertStats} loaded={loaded} />
          </Panel>
        }
        policy={
          <Panel title="Policy &amp; reliability" className="gov-policy">
            <PolicyPosture policy={policy} slos={slos} events={events} loaded={loaded} />
          </Panel>
        }
        wide={
          <Panel title="Agent posture" className="gov-posture">
            <AgentPosture agents={stats?.agents ?? []} trust={trust} slos={slos} loaded={loaded} />
          </Panel>
        }
      />
    </div>
  );
}
