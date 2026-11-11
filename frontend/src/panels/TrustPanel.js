import { useState, useEffect, useCallback } from 'react';
import { Play, ShieldCheck, ShieldAlert, TrendingUp, KeyRound } from '../icons';
import { api } from '../api';
import Slider from '../Slider';
import { PageHeader, Panel, Badge, Field, Empty, scoreColor } from '../ui';

// AGT's verification ladder. Every rung above the first is earned by a
// cryptographic act, not by configuration — which is what makes it worth
// showing next to the score it feeds.
const LEVEL_LABEL = {
  unknown: 'Unknown',
  registered: 'Registered',
  verified: 'Verified',
  verified_partner: 'Verified partner',
};
const LEVEL_TONE = {
  unknown: 'danger',
  registered: 'neutral',
  verified: 'warn',
  verified_partner: 'success',
};
const LEVEL_WHY = {
  unknown: 'No identity has been minted for this agent.',
  registered: 'An Ed25519 identity and DID exist. Attest to reach the next rung.',
  verified: 'The agent has proved possession of its private key by signing a challenge.',
  verified_partner: 'Attested, and carrying a signed card whose signature still verifies.',
};

const TIER_TONE = {
  VERIFIED_PARTNER: 'success',
  TRUSTED: 'success',
  STANDARD: 'warn',
  PROBATIONARY: 'warn',
  UNTRUSTED: 'danger',
};

const tierLabel = (t) => (t || '').replace(/_/g, ' ').toLowerCase();

export default function TrustPanel() {
  const [overview, setOverview] = useState(null);
  const [form, setForm] = useState({ agent_id: 'research-agent', trust_score: 0.85, delegation_depth: 0, namespace: 'production' });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState({});
  const [selected, setSelected] = useState('research-agent');
  const [identity, setIdentity] = useState(null);
  const [agentPage, setAgentPage] = useState(0);
  const [challenge, setChallenge] = useState(null);

  const load = useCallback(async () => {
    try { setOverview(await api.trust.overview()); } catch { /* keep UI responsive */ }
  }, []);
  useEffect(() => { load(); }, [load]);

  const loadIdentity = useCallback(async (agentId) => {
    if (!agentId) return;
    setChallenge(null);
    try { setIdentity(await api.identity.card(agentId)); }
    catch (e) { setIdentity({ error: String(e.message || e) }); }
  }, []);
  useEffect(() => { loadIdentity(selected); }, [selected, loadIdentity]);


  const evaluate = async () => {
    setLoading(true);
    try { setResult(await api.trust.evaluate(form)); }
    catch (e) { setResult({ error: e.message }); }
    setLoading(false);
  };

  const updateScore = async (agent_id, score) => {
    setUpdating(u => ({ ...u, [agent_id]: true }));
    try { await api.trust.update(agent_id, score); await load(); } catch { /* noop */ }
    setUpdating(u => ({ ...u, [agent_id]: false }));
  };

  const promote = async (agent_id) => {
    setUpdating(u => ({ ...u, [agent_id]: true }));
    try { await api.trust.promote(agent_id); await load(); } catch { /* noop */ }
    setUpdating(u => ({ ...u, [agent_id]: false }));
  };

  const issueChallenge = async () => {
    try { setChallenge(await api.identity.challenge(selected)); }
    catch (e) { setChallenge({ error: String(e.message || e) }); }
  };

  const agents = overview?.agents || [];
  // The scores advance on their own; the arrows step through them manually.
  // Any manual step restarts the dwell, so it never yanks mid-read.
  useEffect(() => {
    if (agents.length < 2) return undefined;
    const t = setTimeout(() => setAgentPage(p => (p + 1) % agents.length), 4000);
    return () => clearTimeout(t);
  }, [agentPage, agents.length]);
  // The real gate threshold, from the API. The old hardcoded 0.6 was the ring
  // boundary, not the threshold, so the scale contradicted every verdict.
  const minTrust = overview?.min_trust ?? 0.3;
  const ringThreshold = overview?.ring_threshold ?? 0.6;
  const card = identity?.card;

  return (
    <div className="page">
      <PageHeader
        title="Trust & Identity"
        subtitle={`Trust gates every governed call below ${minTrust}, and selects the execution ring at ${ringThreshold}.`}
      />

      <div className="page-fill cols-play">
        <div className="col play-left">
        {/* ── Scores, what they buy, and what AGT computes ──────────────── */}
        <Panel
          title="Agent trust scores"
          desc="One agent at a time — it advances on its own, or use the arrows."
          bodyStyle={{ padding: agents.length ? '6px 20px 16px' : 20 }}
        >
          {agents.length === 0
            ? <Empty>No agents to score yet.</Empty>
            : (
            <div className="agent-carousel">
              <button className="agent-arrow" aria-label="Previous agent"
                onClick={() => setAgentPage(p => (p - 1 + agents.length) % agents.length)}>
                &#8249;
              </button>
              <div className="agent-viewport">
                <div className="agent-track"
                  style={{ transform: `translateX(-${agentPage * 100}%)` }}>
            {agents.map(a => {
              const rep = a.reputation || {};
              const drifted = rep.evidenced &&
                Math.abs((rep.score_normalised ?? a.trust_score) - a.trust_score) >= 0.05;
              return (
                <div key={a.agent_id} className="row" style={{ display: 'block', padding: '16px 0' }}>
                  <div className="cluster" style={{ justifyContent: 'space-between', flexWrap: 'nowrap' }}>
                    <span className="mono truncate" style={{ color: 'var(--text)', fontSize: 18 }}>{a.agent_id}</span>
                    <span className="cluster cluster-6" style={{ flexWrap: 'nowrap' }}>
                      {updating[a.agent_id] && <span className="meta">saving</span>}
                      <Badge tone={a.level === 'high' ? 'success' : a.level === 'medium' ? 'warn' : 'danger'} size="sm">
                        {a.level}
                      </Badge>
                      <span className="meter-value" style={{ color: scoreColor(a.trust_score), width: 36, textAlign: 'right' }}>
                        {(a.trust_score * 100).toFixed(0)}%
                      </span>
                    </span>
                  </div>

                  <Slider
                    min={0} max={100} step={1}
                    ariaLabel={`Trust score for ${a.agent_id}`}
                    defaultValue={Math.round(a.trust_score * 100)}
                    style={{ marginTop: 12 }}
                    onCommit={v => updateScore(a.agent_id, v / 100)}
                  />

                  {/* What the score buys — the consequence the tab never showed. */}
                  <div className="meta cluster cluster-6" style={{ marginTop: 8 }}>
                    <Badge tone={a.ring === 'RING_2_STANDARD' ? 'success' : 'warn'} size="sm">
                      {a.ring?.replace('RING_', 'Ring ').replace('_', ' ').toLowerCase()}
                    </Badge>
                    <span>{a.ring_grants}</span>
                    {!a.passes_trust_gate && (
                      <Badge tone="danger" size="sm">below gate — every call denied</Badge>
                    )}
                  </div>

                  {/* AGT's independently computed reputation. Advisory until
                      an operator promotes it, so it never moves a ring on its own. */}
                  <div className="meta cluster cluster-6" style={{ marginTop: 6 }}>
                    <TrendingUp size={12} color="var(--text-3)" />
                    <span>AGT reputation</span>
                    <Badge tone={TIER_TONE[rep.tier] || 'neutral'} size="sm">{tierLabel(rep.tier)}</Badge>
                    <code>{rep.score}/1000</code>
                    <Badge tone={LEVEL_TONE[rep.verification_level]} size="sm">
                      {LEVEL_LABEL[rep.verification_level] || rep.verification_level}
                    </Badge>
                    {rep.evidenced
                      ? <span>{rep.successful_tasks} ok · {rep.failed_tasks} denied</span>
                      : <span>no calls yet — identity only</span>}
                    {drifted && (
                      <button className="btn btn-ghost btn-xs" onClick={() => promote(a.agent_id)}
                        title="Adopt AGT's computed reputation as the enforced trust score. This can lower the score as well as raise it.">
                        adopt {(rep.score_normalised * 100).toFixed(0)}%
                        {rep.score_normalised < a.trust_score ? ' ↓' : ' ↑'}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
                </div>
              </div>
              <button className="agent-arrow" aria-label="Next agent"
                onClick={() => setAgentPage(p => (p + 1) % agents.length)}>
                &#8250;
              </button>
            </div>
            )}
        </Panel>

        {/* ── Evaluate against the same TrustPolicy the gate enforces ────── */}
        <Panel title="Evaluate trust policy" className="play-form">
          <Field label="Agent ID">
            <input className="mono" value={form.agent_id}
              onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))} />
          </Field>

          <Field label={`Trust score — ${form.trust_score}`}>
            <Slider min={0} max={1} step={0.01} value={form.trust_score}
              ariaLabel="Trust score"
              onChange={v => setForm(f => ({ ...f, trust_score: v }))} />
            {/* Both real boundaries, read from the API rather than hardcoded. */}
            <div className="range-scale">
              <span>0 untrusted</span>
              <span>{minTrust} gate</span>
              <span>{ringThreshold} ring 2</span>
              <span>1.0 full</span>
            </div>
          </Field>

          <div className="grid-form">
            <Field label="Delegation depth"
              hint="Carried into the context; no rule reads it yet">
              <input type="number" min="0" max="5" value={form.delegation_depth}
                onChange={e => setForm(f => ({ ...f, delegation_depth: parseInt(e.target.value) || 0 }))} />
            </Field>
            <Field label="Namespace" hint="Carried into the context; no rule reads it yet">
              <input className="mono" value={form.namespace}
                onChange={e => setForm(f => ({ ...f, namespace: e.target.value }))} />
            </Field>
          </div>

          <button className="btn btn-primary btn-block" onClick={evaluate} disabled={loading} style={{ marginTop: 6 }}>
            <Play size={14} /> {loading ? 'Evaluating' : 'Run trust evaluation'}
          </button>

          {result && (
            <div className={`animate-in result-box ${result.error ? 'warn' : result.allowed ? 'ok' : 'bad'}`} style={{ marginTop: 18 }}>
              {result.error
                ? <code style={{ color: 'var(--yellow)' }}>{result.error}</code>
                : <>
                    <div className="cluster" style={{ marginBottom: 8 }}>
                      <Badge tone={result.allowed ? 'success' : 'danger'}>{result.action?.toUpperCase()}</Badge>
                      {result.rule_name && <code className="muted">{result.rule_name}</code>}
                    </div>
                    <div style={{ fontSize: 16 }}>{result.reason}</div>
                    <div className="meta" style={{ marginTop: 8 }}>
                      Minimum {result.min_trust} · this is the same <code className="inline-code">TrustPolicy</code>{' '}
                      object the tool gate enforces with, so the two cannot disagree.
                    </div>
                  </>}
            </div>
          )}
        </Panel>
        </div>

        {/* ── Identity: the half the tab was named after ─────────────────── */}
        <Panel
          title="Identity"
          desc="A signed AGT TrustedAgentCard, re-verified on every read."
          className="play-decision"
        >
          <Field label="Agent">
            <select value={selected} onChange={e => setSelected(e.target.value)}>
              {agents.map(a => <option key={a.agent_id} value={a.agent_id}>{a.agent_id}</option>)}
            </select>
          </Field>

          {identity?.error && <code style={{ color: 'var(--yellow)' }}>{identity.error}</code>}

          {card && (
            <>
              <div className="cluster cluster-6" style={{ marginBottom: 12 }}>
                {card.signature_valid
                  ? <Badge tone="success"><ShieldCheck size={12} /> signature verified</Badge>
                  : <Badge tone="danger"><ShieldAlert size={12} /> SIGNATURE INVALID</Badge>}
                <Badge tone={LEVEL_TONE[identity.verification_level]} size="sm">
                  {LEVEL_LABEL[identity.verification_level] || identity.verification_level}
                </Badge>
              </div>
              <div className="meta" style={{ marginBottom: 14 }}>
                {LEVEL_WHY[identity.verification_level]}
              </div>

              <Field label="DID">
                <code className="inline-code" style={{ wordBreak: 'break-all' }}>{card.agent_did}</code>
              </Field>
              <Field label="Public key">
                <code className="inline-code" style={{ wordBreak: 'break-all' }}>{card.public_key}</code>
              </Field>
              <Field label="Capabilities">
                {card.capabilities?.length
                  ? <div className="cluster cluster-6">
                      {card.capabilities.map(c => <Badge key={c} tone="neutral" size="sm">{c}</Badge>)}
                    </div>
                  : <span className="meta">none declared</span>}
              </Field>
              <Field label="Card signature">
                <code className="inline-code" style={{ wordBreak: 'break-all' }}>{card.card_signature}</code>
              </Field>

              <Field label="Attestation">
                {identity.attested
                  ? <span style={{ color: 'var(--green)' }}>
                      Proved key possession on {new Date(identity.attested_at * 1000).toLocaleString()}
                    </span>
                  : <span className="meta">
                      Never attested — this agent has a DID but has not proved it holds the key.
                    </span>}
              </Field>

              <button className="btn btn-secondary btn-block" onClick={issueChallenge}>
                <KeyRound size={13} /> Issue a challenge nonce
              </button>

              {challenge && !challenge.error && (
                <div className="animate-in" style={{ marginTop: 12 }}>
                  <code className="inline-code" style={{ wordBreak: 'break-all' }}>{challenge.nonce}</code>
                  <div className="meta" style={{ marginTop: 8 }}>
                    Single-use, expires in {challenge.ttl_seconds}s. The agent signs it with the
                    private key issued once at registration — which this platform does not hold,
                    and which is deliberately not pasted into a browser:
                  </div>
                  <pre className="code-block" style={{ marginTop: 8 }}>
{`agent.authorize("db_query", action="read")
# or, by hand:
sig = AgentIdentity.from_jwk(private_jwk).sign(
    "${String(challenge.nonce).slice(0, 16)}…".encode())
POST /identity/attest {agent_id, nonce, signature}`}
                  </pre>
                </div>
              )}
              {challenge?.error && <code style={{ color: 'var(--yellow)' }}>{challenge.error}</code>}
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}
