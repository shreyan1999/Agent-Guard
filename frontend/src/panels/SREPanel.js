import { useState, useEffect } from 'react';
import { Power, Play, TrendingUp, TrendingDown, AlertTriangle, BellRing, Activity, FlaskConical, Swords, ShieldCheck, ShieldX } from '../icons';
import { api } from '../api';
import Slider from '../Slider';
import { PageHeader, Panel, Badge, Field, Notice, Empty, Meter } from '../ui';

export default function SREPanel() {
  const [slos, setSlos] = useState([]);
  const [agents, setAgents] = useState([]);
  const [newSlo, setNewSlo] = useState({ agent_id: '', slo_name: '', target: 0.99 });
  const [msg, setMsg] = useState('');
  // AGT's AlertManager feed and AnomalyDetector findings.
  const [alerts, setAlerts] = useState({ alerts: [], stats: {} });
  const [anomalies, setAnomalies] = useState({ anomalies: [], summary: {} });
  // AGT AdversarialEvaluator: attacks fired at the real gates.
  const [chaos, setChaos] = useState(null);
  const [attacking, setAttacking] = useState(false);

  const load = async () => {
    const [sl, ag, al, an] = await Promise.all([
      api.sre.slos(), api.agents.list(), api.sre.alerts(50), api.sre.anomalies(),
    ]);
    setSlos(sl);
    setAgents(ag);
    setAlerts(al);
    setAnomalies(an);
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

  const clearAlerts = async () => {
    await api.sre.clearAlerts();
    setMsg('Alert feed cleared — AGT\u2019s deduplicator was rearmed, so a still-firing condition alerts again.');
    load();
  };

  const runChaos = async () => {
    setAttacking(true);
    try {
      const r = await api.sre.runChaos({});
      setChaos(r);
      setMsg(r.breached === 0
        ? `Every vector was blocked \u2014 grade ${r.grade}.`
        : `${r.breached} of ${r.total} vectors were not blocked \u2014 grade ${r.grade}.`);
      load();
    } catch (e) { setMsg(e.message); }
    finally { setAttacking(false); }
  };

  const gradeTone = (g) => g === 'A' ? 'success' : g === 'B' ? 'success'
    : g === 'C' ? 'warn' : 'danger';

  const alertTone = (sev) => sev === 'critical' ? 'danger'
    : sev === 'warning' ? 'warn'
    : sev === 'resolved' ? 'success' : 'neutral';

  const budgetColor = (pct) => pct <= 20 ? 'var(--red)' : pct <= 40 ? 'var(--yellow)' : 'var(--green)';
  const statusTone = (s) => s === 'healthy' ? 'success'
    : s === 'warning' ? 'warn'
    : (s === 'critical' || s === 'exhausted') ? 'danger' : 'neutral';
  // normal → warning → critical, expressed as how loudly a card is drawn
  const emphasis = (s) => s === 'warning' ? 'warn'
    : (s === 'critical' || s === 'exhausted') ? 'critical' : '';

  return (
    <div className="page">
      <PageHeader
        title="Agent SRE"
        subtitle="Error budgets, burn rate, deduplicated alerts, behavioural anomalies, adversarial evaluation and the per-agent kill switch."
      />

      {msg && <Notice tone="info" onClose={() => setMsg('')}>{msg}</Notice>}

      <div className="page-fill cols-sre">
        {/* Control column */}
        {/* Four panels in a viewport-locked page: the column scrolls rather
            than crushing the first one to nothing. */}
        <div className="col sre-left">
          <Panel
            title="Agent control"
            desc="Halting an agent stops every governed call it makes"
            scroll
            bodyStyle={{ padding: agents.length ? '4px 20px' : 20 }}
          >
            {agents.length === 0
              ? <Empty>No agents registered.</Empty>
              : agents.map(a => (
                <div key={a.id} className="row">
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="mono truncate" style={{ color: 'var(--text)' }}>{a.id}</div>
                    <div className="meta">trust {(a.trust_score * 100).toFixed(0)}% · {a.calls} calls</div>
                  </div>
                  <Badge tone={a.status === 'active' ? 'success' : 'danger'} dot size="sm">{a.status}</Badge>
                  {a.status === 'active'
                    ? <button className="btn btn-danger btn-sm" onClick={() => kill(a.id)}>
                        <Power size={12} /> Kill
                      </button>
                    : <button className="btn btn-secondary btn-sm" onClick={() => resume(a.id)}>
                        <Play size={12} /> Resume
                      </button>}
                </div>
              ))}
          </Panel>


          {/* The empirical counterpart to every other panel: the rest report
              what the platform would do, this attacks it and reports what it
              did. A run that could not fail would prove nothing, so a breach is
              shown as plainly as a block. */}
          <Panel
            title="Adversarial evaluation"
            desc="AGT fires attack vectors at the real gates. Throwaway attackers; no real agent’s numbers are touched."
            scroll
            actions={
              <button className="btn btn-danger btn-sm" onClick={runChaos} disabled={attacking}>
                <Swords size={13} /> {attacking ? 'Attacking' : 'Run attack'}
              </button>
            }
            bodyStyle={{ padding: chaos ? '4px 16px 12px' : 20 }}
          >
            {!chaos
              ? <Empty>
                  Fires AGT&rsquo;s eight built-in vectors plus four aimed at this platform&rsquo;s
                  own gates, as a registered, high-trust attacker — so an attack that is
                  blocked is blocked by a gate worth testing, not by &ldquo;who are you&rdquo;.
                </Empty>
              : (
                <>
                  <div className="cluster cluster-6" style={{ padding: '10px 0 14px' }}>
                    <Badge tone={gradeTone(chaos.grade)}>grade {chaos.grade}</Badge>
                    <span className="meter-value"
                      style={{ color: chaos.breached ? 'var(--red)' : 'var(--green)' }}>
                      {(chaos.resilience_score * 100).toFixed(0)}%
                    </span>
                    <span className="meta">
                      {chaos.held}/{chaos.total} vectors blocked
                      {chaos.breached > 0 && ` · ${chaos.breached} got through`}
                    </span>
                  </div>

                  {Object.keys(chaos.gates_that_held || {}).length > 0 && (
                    <div className="meta cluster cluster-6" style={{ marginBottom: 12 }}>
                      <span>Stopped by:</span>
                      {Object.entries(chaos.gates_that_held).map(([gate, n]) => (
                        <Badge key={gate} tone="neutral" size="sm">{gate} &times;{n}</Badge>
                      ))}
                    </div>
                  )}

                  {chaos.results.map(v => (
                    <div key={v.vector} className="row" style={{ alignItems: 'flex-start' }}>
                      {v.held
                        ? <ShieldCheck size={14} color="var(--green)" style={{ flexShrink: 0, marginTop: 3 }} />
                        : <ShieldX size={14} color="var(--red)" style={{ flexShrink: 0, marginTop: 3 }} />}
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="cluster cluster-6">
                          <code style={{ color: 'var(--text)' }}>{v.vector}</code>
                          <Badge tone="neutral" size="sm">
                            {String(v.category).replace(/_/g, ' ').toLowerCase()}
                          </Badge>
                        </div>
                        <div className="meta" style={{ marginTop: 2 }}>
                          {v.held
                            ? <>blocked at the <strong>{v.denied_by}</strong> gate
                                {v.rule ? ` · ${v.rule}` : ''}</>
                            : <span style={{ color: 'var(--red)' }}>
                                not blocked — no gate refused this payload
                              </span>}
                        </div>
                      </div>
                    </div>
                  ))}

                  {chaos.recommendations?.length > 0 && (
                    <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
                      <div className="meta" style={{ marginBottom: 6 }}>AGT recommends</div>
                      {chaos.recommendations.map((r, i) => (
                        <div key={i} className="meta" style={{ marginBottom: 4 }}>&bull; {r}</div>
                      ))}
                    </div>
                  )}
                </>
              )}
          </Panel>

          {/* AGT AlertManager. The suppressed count is the reason this is not
              just a list: a retrying agent would otherwise flood the feed. */}
          <Panel
            title="Alerts"
            desc={alerts.stats?.suppressed
              ? `${alerts.stats.suppressed} duplicate${alerts.stats.suppressed === 1 ? '' : 's'} suppressed by AGT\u2019s deduplicator`
              : 'Deduplicated governance events, newest first'}
            scroll
            actions={
              <button className="btn btn-ghost btn-sm" onClick={clearAlerts}
                disabled={!alerts.alerts?.length}>Clear</button>
            }
            bodyStyle={{ padding: alerts.alerts?.length ? '4px 16px 12px' : 20 }}
          >
            {!alerts.alerts?.length
              ? <Empty>No alerts. Denials, burning error budgets and behavioural anomalies land here.</Empty>
              : alerts.alerts.slice(0, 12).map((a, i) => (
                <div key={`${a.dedup_key}-${i}`} className="row" style={{ alignItems: 'flex-start' }}>
                  {a.source === 'anomaly'
                    ? <Activity size={14} color="var(--purple)" style={{ flexShrink: 0, marginTop: 3 }} />
                    : <BellRing size={14}
                        color={a.severity === 'critical' ? 'var(--red)' : 'var(--yellow)'}
                        style={{ flexShrink: 0, marginTop: 3 }} />}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="cluster cluster-6">
                      <Badge tone={alertTone(a.severity)} size="sm">{a.severity}</Badge>
                      <span style={{ fontSize: 16 }}>{a.title}</span>
                    </div>
                    <div className="meta" style={{ marginTop: 2 }}>{a.message}</div>
                    <div className="meta faint" style={{ marginTop: 2 }}>
                      {a.source}{a.agent_id ? ` \u00b7 ${a.agent_id}` : ''}
                    </div>
                  </div>
                </div>
              ))}
          </Panel>

          {/* Behavioural deviation. Distinct from the SLO: every one of these
              calls may be compliant, and the agent still stopped behaving like
              itself. Advisory — it never denies. */}
          {anomalies.anomalies?.length > 0 && (
            <Panel
              title="Behavioural anomalies"
              desc="AGT AnomalyDetector · advisory, never denies a call"
              scroll
              bodyStyle={{ padding: '4px 16px 12px' }}
            >
              {anomalies.anomalies.slice(0, 6).map((an, i) => (
                <div key={i} className="row" style={{ alignItems: 'flex-start' }}>
                  <Activity size={14} color="var(--purple)" style={{ flexShrink: 0, marginTop: 3 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="cluster cluster-6">
                      <Badge tone={alertTone(an.severity)} size="sm">
                        {String(an.anomaly_type).replace(/_/g, ' ')}
                      </Badge>
                      {typeof an.score === 'number' && <code className="meta">score {an.score.toFixed(2)}</code>}
                    </div>
                    <div className="meta" style={{ marginTop: 2 }}>{an.message}</div>
                  </div>
                </div>
              ))}
            </Panel>
          )}
        </div>

        {/* Right column: the SLO you are about to create, over the ones that
            already exist. */}
        <div className="col sre-right">
          <Panel title="Create or reset an SLO" desc="Re-using a name resets its measurements">
            <div className="grid-form">
              <Field label="Agent">
                <select value={newSlo.agent_id} onChange={e => setNewSlo(s => ({ ...s, agent_id: e.target.value }))}>
                  <option value="">Select agent</option>
                  {agents.map(a => <option key={a.id}>{a.id}</option>)}
                </select>
              </Field>
              <Field label="SLO name">
                <input className="mono" value={newSlo.slo_name}
                  onChange={e => setNewSlo(s => ({ ...s, slo_name: e.target.value }))}
                  placeholder="research-agent-reliability" />
              </Field>
            </div>
            <Field label={`Task-success target — ${(newSlo.target * 100).toFixed(1)}%`}>
              <Slider min={0.9} max={0.9999} step={0.0001} value={newSlo.target}
                band="high" ariaLabel="Task-success target"
                onChange={v => setNewSlo(s => ({ ...s, target: v }))} />
              <div className="range-scale"><span>90%</span><span>99.99%</span></div>
            </Field>
            <button className="btn btn-primary btn-block" onClick={createSlo} style={{ marginTop: 6 }}>
              Create or reset SLO
            </button>
          </Panel>

        <Panel
          title="Active SLOs"
          desc={`${slos.length} tracked · refreshed every 5s`}
          scroll
          bodyStyle={{ padding: 20 }}
        >
          {slos.length === 0
            ? <Empty>No SLOs yet. Create one, or make a governed tool call to start recording measurements.</Empty>
            : (
              <div className="grid-cards">
                {slos.map(s => {
                  const eb = s.error_budget || {};
                  const remaining = eb.remaining_percent ?? 100;
                  const agentId = s.agent_id;
                  const alerts = eb.firing_alerts || [];
                  return (
                    <section key={s.name} className={`slo-card ${emphasis(s.status)}`}>
                      <div className="cluster" style={{ justifyContent: 'space-between', flexWrap: 'nowrap', alignItems: 'flex-start' }}>
                        <div style={{ minWidth: 0 }}>
                          <div className="truncate" style={{ fontWeight: 600, fontSize: 16 }}>{s.name}</div>
                          {agentId && <code className="meta truncate" style={{ display: 'block', marginTop: 2 }}>{agentId}</code>}
                        </div>
                        <Badge tone={statusTone(s.status)} dot size="sm">{s.status}</Badge>
                      </div>

                      <div style={{ marginTop: 18 }}>
                        <div className="cluster" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
                          <span className="meta">Error budget remaining</span>
                          <span className="meter-value" style={{ color: budgetColor(remaining) }}>{remaining.toFixed(1)}%</span>
                        </div>
                        <Meter value={remaining} color={budgetColor(remaining)} />
                        {typeof eb.burn_rate === 'number' && (
                          <div className="meta" style={{ marginTop: 8 }}>
                            Burn rate {eb.burn_rate.toFixed(2)}×
                            {eb.is_exhausted && <span style={{ color: 'var(--red)', fontWeight: 600 }}> · exhausted</span>}
                          </div>
                        )}
                      </div>

                      {/* An SLO built partly from demo clicks is not evidence,
                          and has to say so where the number is read. */}
                      {s.synthetic_measurements > 0 && (
                        <div className="meta cluster cluster-6" style={{ marginTop: 10, color: 'var(--yellow)' }}>
                          <FlaskConical size={12} />
                          <span>
                            {s.synthetic_measurements} of {s.task_measurements} measurements
                            hand-entered — not evidence
                          </span>
                        </div>
                      )}

                      {(s.indicators || []).length > 0 && (
                        <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
                          {(s.indicators || []).map(ind => {
                            const compliant = ind.compliance != null ? ind.compliance >= 1 : null;
                            const pct = ind.compliance != null ? (ind.compliance * 100).toFixed(0) : '—';
                            return (
                              <div key={ind.name} className="cluster"
                                style={{ justifyContent: 'space-between', flexWrap: 'nowrap', padding: '4px 0' }}>
                                <span className="muted truncate" style={{ fontSize: 16 }}>
                                  {ind.name}
                                  {ind.window && (
                                    <span className="muted" style={{ marginLeft: 6, fontSize: 12, opacity: 0.7 }}>
                                      ({ind.window})
                                    </span>
                                  )}
                                </span>
                                <span className="meter-value"
                                  style={{ color: compliant === null ? 'var(--text-3)' : compliant ? 'var(--green)' : 'var(--red)' }}>
                                  {ind.measurement_count === 0
                                    ? 'no data'
                                    : `${ind.current_value != null ? `${ind.current_value} · ` : ''}${pct}% · n=${ind.measurement_count}`}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {alerts.length > 0 && (
                        <div className="cluster cluster-6" style={{ marginTop: 14 }}>
                          {alerts.map(a => (
                            <Badge key={a} tone="danger" size="sm"><AlertTriangle size={10} /> {a}</Badge>
                          ))}
                        </div>
                      )}

                      {agentId && (
                        <div style={{ marginTop: 'auto', paddingTop: 16 }}>
                          <div className="meta" style={{ marginBottom: 6 }}>
                            Demo signals — recorded as synthetic
                          </div>
                          <div className="cluster" style={{ flexWrap: 'nowrap', gap: 8 }}>
                            <button className="btn btn-ghost btn-sm" style={{ flex: 1 }}
                              title="Records a hand-entered success. Tagged synthetic; it moves the budget but is not evidence."
                              onClick={() => signal(agentId, true)}>
                              <TrendingUp size={12} color="var(--green)" /> Success
                            </button>
                            <button className="btn btn-ghost btn-sm" style={{ flex: 1 }}
                              title="Records a hand-entered failure. Tagged synthetic; it moves the budget but is not evidence."
                              onClick={() => signal(agentId, false)}>
                              <TrendingDown size={12} color="var(--red)" /> Failure
                            </button>
                          </div>
                        </div>
                      )}
                    </section>
                  );
                })}
              </div>
            )}
        </Panel>
        </div>
      </div>
    </div>
  );
}
