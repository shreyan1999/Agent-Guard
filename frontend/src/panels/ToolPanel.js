import { useState, useEffect, useMemo } from 'react';
import { Terminal, Play, CheckCircle, XCircle, Clock, Plus, Trash2, Globe, ShieldOff, Plug, ShieldAlert, RefreshCw, ShieldCheck, FileCheck, EyeOff, AlertTriangle, History } from '../icons';
import { api } from '../api';
import { PageHeader, Panel, Modal, Badge, Field, Empty, riskTone } from '../ui';
import { humanize } from './policy/conditionModel';
import MCPConnector from './tools/MCPConnector';

const DEMO_CALLS = [
  { label: 'READ (allowed)', tool: 'db_query', action: 'read', input_text: 'SELECT * FROM users', agent_id: 'research-agent' },
  { label: 'DROP (denied)', tool: 'db_query', action: 'drop', input_text: 'DROP TABLE users', agent_id: 'data-agent' },
  { label: 'SEND EMAIL (warn = deny)', tool: 'send_email', action: 'send_email', input_text: 'Hello team', agent_id: 'email-agent' },
  { label: 'WEB SEARCH (allowed)', tool: 'web_search', action: 'read', input_text: 'AI governance news', agent_id: 'research-agent' },
  { label: 'LOW TRUST (deny)', tool: 'db_query', action: 'read', input_text: '', agent_id: 'untrusted-agent' },
  { label: 'UNREGISTERED (deny)', tool: 'db_query', action: 'read', input_text: '', agent_id: 'ghost-agent' },
  { label: 'RING 3 / NETWORK (deny)', tool: 'web_search', action: 'web_search', input_text: '', agent_id: 'email-agent' },
  { label: 'RING 3 / SUBPROCESS (deny)', tool: 'db_query', action: 'shell_exec', input_text: '', agent_id: 'email-agent' },
];

const GATE_LABEL = {
  signature: 'Signature',
  lifecycle: 'Lifecycle',
  identity: 'Identity',
  tenant: 'Tenant',
  trust: 'Trust',
  ring: 'Ring',
  policy: 'Policy',
  mcp_parameters: 'Parameters',
  mcp_proxy: 'MCP proxy',
  mcp_budget: 'Budget',
};
// Every gate the backend can deny at, in the order it runs them. The order is
// what decides which gates a denial means never ran, so a gate missing from
// this list is not merely unlabelled — it makes the whole strip wrong. That is
// not hypothetical: a denial at `identity` used to render all four gates green,
// because an unrecognised name was treated as coming last.
const GATE_ORDER = [
  'signature', 'lifecycle', 'identity', 'tenant', 'trust', 'ring', 'policy',
  'mcp_parameters', 'mcp_proxy', 'mcp_budget',
];
// Shown for every call. The rest are conditional — a signature is only checked
// when one is offered or required, and the three MCP gates run only for a tool
// imported from an MCP server — so they appear when the result shows they ran
// or that one of them denied. Showing a gate that never ran would be the same
// lie as hiding one that did.
const GATES = ['lifecycle', 'trust', 'ring', 'policy'];
const MCP_GATES = ['mcp_parameters', 'mcp_proxy', 'mcp_budget'];

// A tool's findings come from two places, and the badge has to cover both or
// it misrepresents a grade it is standing next to.
function findingCount(tool) {
  return (tool?.evaluation?.findings?.length || 0)
    + (tool?.mcp?.security_scan?.length || 0);
}

function gatesFor(result, spec) {
  const shown = new Set(GATES);
  const passed = result?.passed_gates || [];
  const isMcp = spec?.kind === 'mcp'
    || MCP_GATES.includes(result?.denied_by)
    || passed.some(g => MCP_GATES.includes(g));
  if (isMcp) MCP_GATES.forEach(g => shown.add(g));
  passed.forEach(g => { if (GATE_LABEL[g]) shown.add(g); });
  if (result?.denied_by && GATE_LABEL[result.denied_by]) shown.add(result.denied_by);
  return GATE_ORDER.filter(g => shown.has(g));
}

/**
 * Say, in one sentence, why the call ended the way it did.
 *
 * Everything here is derived from the decision the backend returned and the
 * policy it named — never recomputed. A sentence this panel invents that the
 * runtime does not agree with is worse than no sentence at all, so an
 * unrecognised denial falls back to reporting the gate and rule verbatim.
 */
function explainDecision(result, policy, schema) {
  if (!result || result.error) return null;
  const policyName = result.policy || policy?.name;

  if (result.allowed) {
    if (policy && policy.default_action !== 'allow') {
      return `No rule in “${policyName}” denied this call, and the policy allowed it — note its default action is ${policy.default_action}, so an allow rule matched.`;
    }
    return `No rule in “${policyName}” matched this call, so the policy’s default action — allow — applied. The agent passed the lifecycle, trust and ring gates before policy ran.`;
  }

  const rule = result.rule || '';

  if (result.denied_by === 'lifecycle') {
    return rule === 'lifecycle:unregistered'
      ? `The agent is not registered, so the call stopped at the lifecycle gate. Unknown agents are untrusted, and this gate runs before any policy — no rule could have allowed it.`
      : `The agent is ${rule.split(':')[1] || 'not active'} rather than active, so the kill switch stopped the call. Lifecycle runs before the policy engine, so policy cannot override it.`;
  }

  if (result.denied_by === 'signature') {
    return rule === 'call_signature:replay'
      ? `This exact request has already been processed. The signature is valid — that is the point: a replayed call is a genuine request arriving a second time, and every gate below would pass it again. The nonce is what tells the two apart.`
      : rule === 'call_signature:incomplete'
        ? `Signed calls are required on this instance and this one did not carry all three of the nonce, timestamp and signature headers. Nothing was evaluated.`
        : rule === 'call_signature:timestamp'
          ? `The timestamp header is not milliseconds since the epoch, so the replay window could not be applied. The call was refused rather than evaluated without it.`
          : `The signature does not match the request body under the shared key, so the request was altered in flight or signed with a different key. Nothing was evaluated.`;
  }

  if (result.denied_by === 'identity') {
    if (rule === 'mcp_session:required') {
      return `An MCP session token is required on this instance and the call did not carry one. Mint one at POST /mcp/sessions; the agent proves itself once there instead of re-attesting on every call.`;
    }
    if (rule === 'mcp_session:invalid') {
      return `The session token is expired, revoked, or belongs to a different agent. A call carrying no token is decided on the self-asserted agent id, but a token that is presented has to verify — a broken credential is worse evidence than none.`;
    }
    return rule === 'identity:attestation_required'
      ? `Attestation is required on this instance and the call did not carry one, so the agent’s identity was never proven. The call stopped before trust or policy ran.`
      : `The signature did not verify against the agent’s registered public key, so the caller could not prove it is that agent. The call stopped before trust or policy ran.`;
  }

  if (result.denied_by === 'mcp_parameters') {
    return `The arguments carry something that should not leave in a tool call — a national ID, a payment card, or shell metacharacters. This is AGT’s MCP gateway, and it reads the payload for sensitive data and injection characters, which is a different question from the trust proxy’s scan for instructions aimed at the model. Nothing reached the server.`;
  }

  if (result.denied_by === 'mcp_budget') {
    return `The agent has spent its MCP call budget for the current window, across every MCP tool rather than this one alone. The window slides, so the budget recovers as the oldest calls age out. Nothing reached the server, and this call was not charged.`;
  }

  if (result.denied_by === 'trust') {
    return `The agent’s trust score is below the minimum this instance requires, so the call stopped at the trust gate — before the policy engine ran. Raising the agent’s trust, not editing the policy, is what changes this.`;
  }

  if (result.denied_by === 'ring') {
    return rule === 'ring_breaker'
      ? `The agent has repeatedly reached for resources its execution ring forbids, so the circuit breaker tripped. Every call from this agent is now denied, including ones its ring would normally permit.`
      : `The agent’s execution ring does not permit the resource this action needs. The ring is derived from the trust score, so no policy edit can grant it — only more trust can.`;
  }

  if (result.denied_by === 'mcp_proxy') {
    // AGT's mcp_trust_proxy runs after policy, immediately before the remote
    // dispatch — so the four gates all passed and nothing reached the server.
    const why = {
      'mcp_proxy:argument_injection':
        `The arguments carry a prompt-injection pattern, so AGT’s MCP trust proxy refused to send them. The tool itself graded clean at import — this gate reads the payload, which the descriptor evaluation never sees. Nothing reached the server.`,
      'mcp_proxy:rate_limit':
        `This agent has spent the tool’s per-minute call budget, derived from the tool’s descriptor risk. The budget refills on a rolling minute; nothing reached the server.`,
      'mcp_proxy:capability':
        `The tool requires a capability this agent does not hold. Capabilities are set when the agent is registered, and are checked at dispatch — no policy edit grants one.`,
      'mcp_proxy:min_trust':
        `The agent’s trust is below the floor derived from this tool’s own descriptor grade — a higher-risk tool demands more trust than the global minimum. Raising the agent’s trust, not editing the policy, is what changes this.`,
      'mcp_proxy:tool_blocked':
        `This tool’s descriptor graded critical, so it is refused at dispatch outright. Instruction-override, embedded-credential and hidden-character findings do not become acceptable at a higher trust score — the tool was onboarded, but it will never run.`,
      'mcp_proxy:no_did':
        `The agent has no minted DID, so the MCP proxy could not identify the caller and refused the dispatch.`,
      'mcp_proxy:quarantined':
        `The server changed this tool’s descriptor after it was imported — a rug pull. The grade an operator approved no longer describes the tool, so it is refused until someone re-imports it and accepts the new descriptor. Nothing reached the server.`,
    }[rule];
    return why || `AGT’s MCP trust proxy refused the dispatch after the four gates passed. Nothing reached the remote server.`;
  }

  if (result.denied_by === 'policy') {
    if (rule === 'policy:tenant_isolation') {
      return `Policy “${policyName}” belongs to a different tenant than this agent, so it was refused before any rule was evaluated.`;
    }
    const matched = (policy?.rules || []).find(r => r.name === rule);
    if (matched) {
      const english = humanize(matched.condition, schema);
      const because = english
        ? `because ${english}`
        : `because its condition matched: ${matched.condition}`;
      // AGT already reports the rule description as the denial reason, shown
      // directly above — repeating it here would read as two different facts.
      const note = matched.description && matched.description !== result.reason
        ? ` ${matched.description}.`
        : '';
      return `Policy “${policyName}” denied this call: rule “${rule}” matched ${because}.${note}`;
    }
    return `Policy “${policyName}” denied this call via rule “${rule}”.`;
  }

  return null;
}

/**
 * Sort the registry into the sections the Tool picker offers.
 *
 * A flat list is the wrong shape once MCP servers are onboarded: a handful of
 * built-ins get buried under every tool every server advertises, and the raw
 * registry names (`mcp.deepwiki.ask_question`) repeat a prefix that carries no
 * information once the section header has said "MCP".
 *
 * The *value* of every option stays the registry name — that is what the API
 * is called with, and what the presets below set — so only the label changes.
 */
function toolSections(registered) {
  const section = { builtin: [], api: [], mcp: [] };

  for (const spec of registered) {
    const mcp = spec.mcp || {};
    if (spec.kind === 'mcp') {
      // `<server>-<tool>`: the server is the half that disambiguates two
      // servers offering the same tool name, and the `mcp.` prefix is already
      // said by the group it sits in.
      const server = mcp.server || '';
      const tool = mcp.remote_tool || spec.name.replace(/^mcp\./, '');
      section.mcp.push({
        value: spec.name,
        label: server ? `${server}-${tool}` : tool,
        server,
        tool,
      });
    } else if (spec.endpoint_url) {
      section.api.push({ value: spec.name, label: spec.name, server: '', tool: spec.name });
    } else {
      section.builtin.push({ value: spec.name, label: spec.name, server: '', tool: spec.name });
    }
  }

  // Server first so one server's tools stay together, then tool name.
  const by = (a, b) => a.server.localeCompare(b.server) || a.tool.localeCompare(b.tool);
  return [
    // Built-ins first: they are the defaults, and the few that are always here.
    { id: 'builtin', label: 'Built-in', options: section.builtin.sort(by) },
    { id: 'api', label: 'API (webhook)', options: section.api.sort(by) },
    { id: 'mcp', label: 'MCP', options: section.mcp.sort(by) },
  ].filter(g => g.options.length > 0);
}

export default function ToolPanel() {
  const [tools, setTools] = useState({ tools: [], available: [], categories: [] });
  const [registered, setRegistered] = useState([]);
  // Result of the last rug-pull re-verification, keyed by server.
  const [verifying, setVerifying] = useState(null);
  const [verified, setVerified] = useState({});
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [policies, setPolicies] = useState([]);
  const [form, setForm] = useState({
    tool_name: 'db_query', policy_name: 'default-policy',
    action: 'read', input_text: '', agent_id: 'research-agent', kwargs: {},
  });
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [onb, setOnb] = useState({
    name: '', description: '', actions: '', risk: 'medium',
    category: 'uncategorised', endpoint_url: '', timeout_ms: 3000,
  });
  const [onbMsg, setOnbMsg] = useState(null);
  const [showOnboard, setShowOnboard] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [toolPage, setToolPage] = useState(0);
  const [showHistory, setShowHistory] = useState(false);
  const [showMcp, setShowMcp] = useState(false);
  const [servers, setServers] = useState([]);
  const [argsText, setArgsText] = useState('{}');
  // The tool whose descriptor findings are open, or null.
  const [findings, setFindings] = useState(null);
  // The published grammar, so a rule's condition can be worded rather than quoted.
  const [schema, setSchema] = useState(null);

  const selectedSpec = registered.find(t => t.name === form.tool_name);
  const toolGroups = useMemo(() => toolSections(registered), [registered]);
  const knownTools = useMemo(
    () => new Set(registered.map(t => t.name)), [registered]);

  const refreshTools = () => {
    api.tools.list().then(r => {
      setTools(r);
      setRegistered(r.registered || []);
      setAllowPrivate(!!r.allow_private_endpoints);
    }).catch(() => {});
    api.mcp.servers().then(r => setServers(r.servers || [])).catch(() => {});
  };

  useEffect(() => {
    refreshTools();
    api.policies.list().then(setPolicies).catch(() => {});
    api.policies.schema().then(setSchema).catch(() => {});
  }, []);

  const onboard = async () => {
    setOnbMsg(null);
    try {
      const spec = await api.tools.register({
        name: onb.name,
        description: onb.description,
        actions: onb.actions.split(',').map(s => s.trim()).filter(Boolean),
        risk: onb.risk,
        category: onb.category,
        endpoint_url: onb.endpoint_url.trim() || null,
        timeout_ms: Number(onb.timeout_ms) || 3000,
      });
      setOnbMsg({ ok: true, text: `Onboarded “${spec.name}”` });
      setOnb({ name: '', description: '', actions: '', risk: 'medium', category: 'uncategorised', endpoint_url: '', timeout_ms: 3000 });
      setForm(f => ({ ...f, tool_name: spec.name }));
      setShowOnboard(false);
      refreshTools();
    } catch (e) {
      setOnbMsg({ ok: false, text: typeof e.message === 'string' ? e.message : 'Registration failed' });
    }
  };

  const removeTool = async (name) => {
    try { await api.tools.remove(name); refreshTools(); } catch (e) { /* keep UI responsive */ }
  };

  const removeServer = async (server) => {
    try { await api.mcp.removeServer(server); refreshTools(); } catch (e) { /* keep UI responsive */ }
  };

  // Re-fetch the server's live descriptors and compare them with what each tool
  // was imported with. A changed descriptor quarantines the tool server-side,
  // so the tool list is refreshed to pick the flag up.
  const verifyServer = async (server) => {
    setVerifying(server);
    try {
      const res = await api.mcp.verifyServer(server);
      setVerified(v => ({ ...v, [server]: res }));
      refreshTools();
    } catch (e) {
      setVerified(v => ({ ...v, [server]: { error: String(e.message || e) } }));
    } finally {
      setVerifying(null);
    }
  };

  const run = async () => {
    setLoading(true);
    try {
      const body = { ...form };
      if (selectedSpec?.kind === 'mcp') {
        // Sent verbatim as the MCP tool's arguments, and visible to policy
        // rules in the call context.
        try {
          body.kwargs = { ...form.kwargs, arguments: JSON.parse(argsText || '{}') };
        } catch {
          setResult({ error: 'Arguments must be valid JSON' });
          setLoading(false);
          return;
        }
      }
      const res = await api.tools.call(body);
      const entry = { ...res, ...body, ts: new Date().toISOString() };
      setResult(res);
      setHistory(h => [entry, ...h].slice(0, 20));
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  const runDemo = (d) => {
    setForm(f => ({ ...f, tool_name: d.tool, action: d.action, input_text: d.input_text, agent_id: d.agent_id }));
    setTimeout(run, 50);
  };

  const decisionPolicy = policies.find(p => p.name === (result?.policy || form.policy_name));
  const explanation = explainDecision(result, decisionPolicy, schema);

  // Tools are shown two at a time and swapped on a dwell — a marquee reads
  // as a running queue and never sits still long enough to be read.
  const toolPages = [];
  for (let i = 0; i < registered.length; i += 2) toolPages.push(registered.slice(i, i + 2));

  useEffect(() => {
    if (toolPages.length < 2) return undefined;
    const t = setInterval(() => setToolPage(p => (p + 1) % toolPages.length), 3000);
    return () => clearInterval(t);
  }, [toolPages.length]);

  return (
    <div className="page">
      <PageHeader
        title="Tool Playground"
        subtitle={<>Run a governed tool call through <code className="inline-code">govern()</code> and see which gate decided it.</>}
        actions={
          <button className="btn btn-ghost" onClick={() => setShowHistory(true)}
            disabled={history.length === 0}
            title={history.length ? `${history.length} previous call${history.length === 1 ? '' : 's'}` : 'No calls yet'}>
            <History size={15} /> History{history.length ? ` (${history.length})` : ''}
          </button>
        }
      />

      <div className="page-fill cols-play">
        {/* Left column: what the platform governs, then the call to make. */}
        <div className="col play-left">
        {/* 1 — the tools the platform governs */}
        <Panel
          title="Registered tools"
          scroll
          bodyStyle={{ padding: registered.length ? '4px 16px 16px' : 20 }}
          actions={
            /* One Add button rather than two competing ones. */
            <div className="menu-wrap">
              <button className="btn btn-secondary btn-sm" onClick={() => setAddOpen(o => !o)}
                aria-haspopup="menu" aria-expanded={addOpen}>
                <Plus size={14} /> Add
              </button>
              {addOpen && (
                <>
                  <div className="menu-scrim" onClick={() => setAddOpen(false)} />
                  <div className="menu" role="menu">
                    <button className="menu-item" role="menuitem"
                      onClick={() => { setAddOpen(false); setShowMcp(true); }}>
                      <Plug size={15} />
                      <span>
                        <strong>Connect MCP server</strong>
                        <small>Import every tool a server advertises</small>
                      </span>
                    </button>
                    <button className="menu-item" role="menuitem"
                      onClick={() => { setAddOpen(false); setOnbMsg(null); setShowOnboard(true); }}>
                      <Plus size={15} />
                      <span>
                        <strong>Onboard a tool</strong>
                        <small>Register one tool by hand</small>
                      </span>
                    </button>
                  </div>
                </>
              )}
            </div>
          }
        >
          {servers.map(s => (
            <div key={s.server} className="row" style={{ alignItems: 'flex-start' }}>
              <Plug size={15} color="var(--purple)" style={{ flexShrink: 0, marginTop: 3 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="cluster cluster-6">
                  <code style={{ color: 'var(--text)', fontSize: 16 }}>{s.server}</code>
                  <Badge tone={riskTone(s.risk)} size="sm">{s.risk}</Badge>
                </div>
                <div className="meta" style={{ marginTop: 3 }}>
                  {s.local ? 'Local MCP server · stdio' : `MCP server · ${s.transport === 'sse' ? 'HTTP + SSE' : 'Streamable HTTP'}`}
                  {' · '}{s.tools.length} tool{s.tools.length === 1 ? '' : 's'}
                  {s.authenticated ? ' · authenticated' : ''}
                </div>
                {s.categories?.length > 0 && (
                  <div className="meta" style={{ marginTop: 3 }}>{s.categories.join(' · ')}</div>
                )}
                <div className="meta mono truncate"
                  title={s.local ? [s.command, ...(s.args || [])].join(' ') : s.server_url || ''}>
                  {s.local ? [s.command, ...(s.args || [])].join(' ') : s.server_url}
                </div>
                {verified[s.server] && (
                  <div className="meta" style={{ marginTop: 4 }}>
                    {verified[s.server].error
                      ? <span style={{ color: 'var(--red)' }}>
                          Re-verification failed: {verified[s.server].error}
                        </span>
                      : verified[s.server].clean
                        ? <span style={{ color: 'var(--green)' }}>
                            ✓ All {verified[s.server].checked.length} descriptor
                            {verified[s.server].checked.length === 1 ? '' : 's'} unchanged since import
                          </span>
                        : <span style={{ color: 'var(--red)' }}>
                            ⚠ {verified[s.server].changed} descriptor
                            {verified[s.server].changed === 1 ? '' : 's'} changed since import
                            {verified[s.server].withdrawn > 0 &&
                              `, ${verified[s.server].withdrawn} withdrawn by the server`}
                            {' '}— those tools are quarantined until re-imported
                          </span>}
                  </div>
                )}
              </div>
              <button className="btn btn-quiet btn-icon sm" disabled={verifying === s.server}
                onClick={() => verifyServer(s.server)}
                title="Re-check every imported descriptor against what this server advertises now (rug pull)"
                style={{ flexShrink: 0 }}>
                <RefreshCw size={13} color="var(--text-3)"
                  className={verifying === s.server ? 'spin' : undefined} />
              </button>
              <button className="btn btn-quiet btn-icon sm" onClick={() => removeServer(s.server)}
                title="Withdraw this server and every tool imported from it" style={{ flexShrink: 0 }}>
                <Trash2 size={13} color="var(--text-3)" />
              </button>
            </div>
          ))}

          {registered.length === 0
            ? <Empty>No tools onboarded yet.</Empty>
            : (
            <div className="tool-carousel">
              <div className="tool-carousel-track"
                style={{ transform: `translateX(-${toolPage * 100}%)` }}>
              {toolPages.map((pair, pageIdx) => (
              <div key={pageIdx} className="tool-page">
              {pair.map(t => (
              <div key={t.name} className="tool-chip">
                {t.kind === 'mcp'
                  ? <Plug size={15} color="var(--purple)" style={{ flexShrink: 0, marginTop: 3 }} />
                  : t.endpoint_url
                    ? <Globe size={15} color="var(--green)" style={{ flexShrink: 0, marginTop: 3 }} />
                    : <Terminal size={15} color="var(--text-3)" style={{ flexShrink: 0, marginTop: 3 }} />}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="cluster cluster-6">
                    <code style={{ color: 'var(--text)', fontSize: 16 }}>{t.name}</code>
                    <Badge tone={riskTone(t.risk)} size="sm">{t.risk}</Badge>
                    {t.category && t.category !== 'uncategorised' && (
                      <Badge tone="neutral" size="sm">{t.category}</Badge>
                    )}
                    {t.quarantined && (
                      <Badge tone="danger" size="sm"
                        title="This tool's descriptor changed on the server after it was imported. It is refused at dispatch until re-imported.">
                        quarantined
                      </Badge>
                    )}
{/* Two graders decide a tool's tier: the connector's own descriptor
                      evaluation and AGT's scan of the same text. Counting only
                      the first hid the case that matters most — a tool with no
                      connector findings whose tier was raised to critical by a
                      cross-server impersonation finding would have shown the
                      grade with no way to read why. */}
                    {findingCount(t) > 0 && (
                      /* Was a `title` tooltip, which meant the findings could
                         only be hovered for — not clicked, not focusable, and
                         gone the moment the pointer moved. They are the reason
                         a tool got its grade, so they get a real control. */
                      <button type="button" className="chip-findings"
                        onClick={() => setFindings(t)}
                        title={`${findingCount(t)} descriptor finding`
                          + `${findingCount(t) === 1 ? '' : 's'} — why this tool graded `
                          + `${t.risk}. Click to read them.`}>
                        <ShieldAlert size={12} color="var(--yellow)" />
                        {findingCount(t)}
                      </button>
                    )}
                  </div>
                  {t.description && (
                    <div className="meta tool-chip-desc" style={{ marginTop: 3 }}
                      title={t.description}>
                      {t.description}
                    </div>
                  )}
                  {/* One line: it wrapped only for MCP tools, whose server and
                      remote name are already spelled out in the code above, and
                      a wrapped line here set the height of every card in the
                      carousel. */}
                  <div className="meta truncate" style={{ marginTop: 3 }}>
                    {t.builtin ? 'built-in' : 'custom'} · {
                      t.kind === 'mcp'
                        ? `MCP ${t.mcp?.server} → ${t.mcp?.remote_tool}`
                        : t.endpoint_url ? 'webhook' : 'decision-only'
                    }
                  </div>
                  {t.endpoint_url && <div className="meta mono truncate">{t.endpoint_url}</div>}
                </div>
                {!t.builtin && (
                  <button className="btn btn-quiet btn-icon sm" onClick={() => removeTool(t.name)}
                    title="Remove tool" style={{ flexShrink: 0 }}>
                    <Trash2 size={13} color="var(--text-3)" />
                  </button>
                )}
              </div>
              ))}
              </div>
              ))}
              </div>
              {toolPages.length > 1 && (
                <div className="tool-dots">
                  {toolPages.map((_, i) => (
                    <button key={i} className={`tool-dot ${i === toolPage ? 'on' : ''}`}
                      onClick={() => setToolPage(i)} aria-label={`Tools ${i * 2 + 1}–${i * 2 + 2}`} />
                  ))}
                </div>
              )}
            </div>
            )}
        </Panel>

        {/* 2 — configure the call */}
        <Panel title="Configure call" className="play-form">
          <div className="grid-form">
            <Field label="Tool">
              <select value={form.tool_name} onChange={e => setForm(f => ({ ...f, tool_name: e.target.value }))}>
                {toolGroups.map(group => (
                  <optgroup key={group.id} label={group.label}>
                    {group.options.map(o => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </optgroup>
                ))}
                {/* A name the registry no longer has — a removed tool still
                    sitting in the form — would otherwise select silently as
                    whatever happens to be first. */}
                {!knownTools.has(form.tool_name) && form.tool_name && (
                  <option value={form.tool_name}>{form.tool_name} (not registered)</option>
                )}
              </select>
            </Field>
            <Field label="Action type">
              <input className="mono" value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}
                placeholder="read / drop / send_email" />
            </Field>
          </div>

          <Field label="Input text" hint="PII patterns are tested against this">
            <textarea value={form.input_text} onChange={e => setForm(f => ({ ...f, input_text: e.target.value }))}
              placeholder="Optional input content" style={{ minHeight: 76 }} />
          </Field>

          {selectedSpec?.kind === 'mcp' && (
            <Field label="MCP arguments" hint={`Sent to ${selectedSpec.mcp?.remote_tool} on ${selectedSpec.mcp?.server}`}>
              <textarea className="mono" value={argsText} onChange={e => setArgsText(e.target.value)}
                placeholder='{"query": "…"}' style={{ minHeight: 64 }} />
            </Field>
          )}

          <div className="grid-form">
            <Field label="Agent ID">
              <input className="mono" value={form.agent_id} onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))} />
            </Field>
            <Field label="Policy">
              <select value={form.policy_name} onChange={e => setForm(f => ({ ...f, policy_name: e.target.value }))}>
                {policies.map(p => <option key={p.name}>{p.name}</option>)}
              </select>
            </Field>
          </div>

          <button className="btn btn-primary btn-block" onClick={run} disabled={loading} style={{ marginTop: 18 }}>
            <Play size={14} /> {loading ? 'Executing' : 'Execute tool call'}
          </button>

          {/* Presets sit under the button they feed, not above the form. */}
          <div className="play-demos">
            <p className="play-demos-label">
              Or try one
              <span>each fills the form with a real agent, tool and action — run it to see which gate decides</span>
            </p>
            <div className="cluster cluster-6">
              {DEMO_CALLS.map(d => {
                /* The expected verdict is read from the label, which is the
                   same string `test_demo_claims.py` reads to assert the call
                   really ends that way. One source of truth: if a demo ever
                   stopped matching its label the suite fails, so the dot
                   cannot drift from what the backend actually decides. */
                const denies = /deny|denied/i.test(d.label);
                return (
                  /* The outcome in brackets doubles each label's width and
                     pushes the row onto a third line, so it becomes a dot and
                     the wording stays in the tooltip. */
                  <button key={d.label} type="button"
                    className={`btn btn-ghost btn-xs demo-chip ${denies ? 'demo-deny' : 'demo-allow'}`}
                    title={`${d.label} — ${d.agent_id} calls ${d.tool}.${d.action}`}
                    onClick={() => {
                      setForm(f => ({ ...f, tool_name: d.tool, action: d.action, input_text: d.input_text, agent_id: d.agent_id }));
                    }}>
                    <span className="demo-dot" aria-hidden />
                    {d.label.replace(/\s*\(.*\)$/, '')}
                  </button>
                );
              })}
            </div>
          </div>
        </Panel>
        </div>

        {/* 3 — the decision */}
          <Panel title="Decision" className="play-decision">
            {!result
              ? <Empty>Run a call to see which gate decided it, and why.</Empty>
              : (
                <div className={`animate-in result-box ${result.error ? 'warn' : result.allowed ? 'ok' : 'bad'}`}>
                  <div className="cluster" style={{ marginBottom: 14 }}>
                    {result.error
                      ? <Badge tone="warn">ERROR</Badge>
                      : result.allowed
                        ? <Badge tone="success"><CheckCircle size={13} /> ALLOWED</Badge>
                        : <Badge tone="danger"><XCircle size={13} /> DENIED</Badge>}
                    {result.latency_ms && (
                      <span className="meta mono spacer" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <Clock size={11} /> {result.latency_ms}ms
                      </span>
                    )}
                  </div>

                  {result.error && <code style={{ color: 'var(--yellow)' }}>{result.error}</code>}

                  {!result.error && (
                    <div className="cluster cluster-6" style={{ marginBottom: 14 }}>
                      {gatesFor(result, selectedSpec).map(g => {
                        const denied = result.denied_by === g;
                        const passed = result.allowed || (!denied && !reached(result.denied_by, g));
                        return (
                          <span key={g} className={`gate ${denied ? 'gate-fail' : passed ? 'gate-pass' : 'gate-skip'}`}>
                            {denied ? '✗' : passed ? '✓' : '·'} {GATE_LABEL[g]}
                          </span>
                        );
                      })}
                    </div>
                  )}

                  {result.reason && <div style={{ fontSize: 16, marginBottom: 10 }}>{result.reason}</div>}

                  {explanation && (
                    <div className="decision-why">{explanation}</div>
                  )}

                  {/* What the remote server sent back. Nothing governed this
                      before — everything else here decides what goes out.
                      What happens to an unsafe response is the gateway's
                      ResponsePolicy, so the wording follows the action that was
                      actually taken rather than assuming it was withheld: under
                      `sanitize` the content really is returned, and calling that
                      "withheld" would be the panel contradicting the payload. */}
                  {result.result?.response_scan && (() => {
                    const scan = result.result.response_scan;
                    const names = (scan.threats || [])
                      .map(t => t.category.replace(/_/g, ' ')).join(', ');
                    const tone = scan.safe ? 'var(--green)'
                      : scan.withheld ? 'var(--red)' : 'var(--yellow)';
                    const Icon = scan.safe ? ShieldCheck
                      : scan.withheld ? EyeOff : AlertTriangle;
                    return (
                      <div style={{ fontSize: 16, marginBottom: 10, display: 'flex',
                        alignItems: 'flex-start', gap: 7, color: tone }}>
                        <Icon size={14} style={{ flexShrink: 0, marginTop: 2 }} />
                        <div>
                          {scan.safe && 'Response scanned — clean'}
                          {!scan.safe && scan.withheld && (
                            <>
                              Response withheld — {names}
                              <div className="meta" style={{ marginTop: 3 }}>
                                The call already ran and its side effects are real; only the
                                content was held back before it could reach a model.
                              </div>
                            </>
                          )}
                          {!scan.safe && !scan.withheld && scan.action === 'sanitized' && (
                            <>
                              Response sanitized — {names} stripped
                              <div className="meta" style={{ marginTop: 3 }}>
                                The rest of the body was returned. What remains was
                                re-scanned and came back clean; anything the sanitizer
                                could not actually remove is withheld instead.
                              </div>
                            </>
                          )}
                          {!scan.safe && !scan.withheld && scan.action !== 'sanitized' && (
                            <>
                              Response flagged — {names}
                              <div className="meta" style={{ marginTop: 3 }}>
                                Reported but not withheld: the response policy is
                                “{scan.policy}”, which records threats and lets the
                                content through.
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })()}

                  {/* A signed, portable proof of this one decision — verifiable
                      without this platform, unlike the audit chain. */}
                  {result.receipt && (
                    <div className="meta" style={{ marginBottom: 10, display: 'flex',
                      alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <FileCheck size={13}
                        color={result.receipt.signature_valid ? 'var(--green)' : 'var(--red)'} />
                      <span>
                        Signed receipt{' '}
                        <code className="inline-code">{result.receipt.receipt_id.slice(0, 8)}</code>
                        {' · '}decision {result.receipt.cedar_decision}
                        {' · '}{result.receipt.signature_valid ? 'signature verified' : 'SIGNATURE INVALID'}
                      </span>
                    </div>
                  )}

                  {result.allowed && result.executed !== undefined && (
                    <div style={{ fontSize: 16, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 7,
                      color: result.executed ? (result.execution_ok ? 'var(--green)' : 'var(--red)') : 'var(--text-3)' }}>
                      {result.executed
                        ? (result.execution_ok
                            ? <><Globe size={12} /> {result.result?.kind === 'mcp'
                                ? `Dispatched to ${result.result.remote_tool} on the MCP server`
                                : `Endpoint invoked — HTTP ${result.result?.http_status}`}</>
                            : <><XCircle size={12} /> Endpoint call failed{result.result?.http_status ? ` — HTTP ${result.result.http_status}` : ''}{result.result?.error ? ` (${result.result.error})` : ''}</>)
                        : <>Governance decision only — no endpoint bound to this tool</>}
                    </div>
                  )}

                  {result.result && (
                    <pre className="code-block" style={{ maxHeight: 200 }}>{JSON.stringify(result.result, null, 2)}</pre>
                  )}
                  <div className="meta" style={{ marginTop: 10 }}>policy {result.policy || form.policy_name}</div>
                </div>
              )}
          </Panel>
      </div>

      {showHistory && (
        <Modal title="Call history" subtitle={`The last ${history.length} governed call${history.length === 1 ? '' : 's'} from this session.`}
          onClose={() => setShowHistory(false)}
          footer={<button className="btn btn-ghost" onClick={() => setShowHistory(false)}>Close</button>}>
          {history.map((h, i) => (
            <div key={i} className="row" style={{ padding: '11px 0' }}>
              {h.allowed ? <CheckCircle size={14} color="var(--green)" /> : <XCircle size={14} color="var(--red)" />}
              <code style={{ color: 'var(--text)' }}>{h.tool_name}({h.action})</code>
              <span className="meta mono spacer">{h.agent_id}</span>
            </div>
          ))}
        </Modal>
      )}

      {findings && (
        <Modal
          title="Descriptor findings"
          subtitle={findings.name}
          width={640}
          onClose={() => setFindings(null)}
          footer={<button className="btn btn-ghost" onClick={() => setFindings(null)}>Close</button>}
        >
          <p className="muted" style={{ fontSize: 16, marginBottom: 14 }}>
            What the static evaluation found in the text this server is asking the
            model to trust. The grade is the highest severity here, so one critical
            finding is not averaged away by a list of benign ones.
          </p>

          <div className="cluster cluster-6" style={{ marginBottom: 16 }}>
            <Badge tone={riskTone(findings.evaluation.risk)}>{findings.evaluation.risk}</Badge>
            <Badge tone="neutral" size="sm">{findings.evaluation.category}</Badge>
            <span className="meta">exposure score {findings.evaluation.score}/100</span>
            {findings.evaluation.checks_run != null && (
              <span className="meta">{findings.evaluation.checks_run} checks run</span>
            )}
          </div>

          {findings.runtime_policy && (
            <>
              <div className="field-label">What the gate will do at dispatch</div>
              <div className="result-box" style={{ marginBottom: 16 }}>
                {findings.runtime_policy.blocked ? (
                  <div style={{ color: 'var(--red)' }}>
                    Refused outright. A tool graded critical is never dispatched,
                    however trusted the agent.
                  </div>
                ) : (
                  <div className="meta">
                    Needs trust <strong>{findings.runtime_policy.min_trust}</strong>
                    {' · '}at most <strong>{findings.runtime_policy.max_calls_per_minute}</strong> calls/min
                    {findings.runtime_policy.required_capabilities?.length > 0 && (
                      <> · capabilities <code>{findings.runtime_policy.required_capabilities.join(', ')}</code></>
                    )}
                  </div>
                )}
                <div className="meta faint" style={{ marginTop: 4 }}>
                  {findings.runtime_policy.derived_from}
                </div>
              </div>
            </>
          )}

          {findings.evaluation.escalated_by === 'agt_descriptor_scan' && (
            <div className="result-box" style={{ marginBottom: 16,
              borderColor: 'var(--red-line)' }}>
              <div style={{ color: 'var(--red)' }}>
                Graded <strong>{findings.evaluation.risk}</strong>, raised from{' '}
                <strong>{findings.evaluation.escalated_from}</strong> by the
                toolkit's descriptor scan.
              </div>
              <div className="meta faint" style={{ marginTop: 4 }}>
                The tier is what the import ceiling and the dispatch gate both
                read, so this is not only a note — it changes what the tool is
                allowed to do.
              </div>
            </div>
          )}

          {findings.mcp?.security_scan?.length > 0 && (
            <>
              <div className="field-label">
                Agent Governance Toolkit descriptor scan
              </div>
              <p className="meta" style={{ marginBottom: 8 }}>
                AGT's own scanner, running the rule set in{' '}
                <code>backend/config/</code>. It runs beside the evaluation
                below rather than instead of it — the two catch different
                things, and this is the one that sees across servers, so
                impersonation and typosquatting show up here.
              </p>
              <table className="table" style={{ marginBottom: 16 }}>
                <thead><tr><th>Severity</th><th>Threat</th><th>What it found</th></tr></thead>
                <tbody>
                  {findings.mcp.security_scan.map((f, i) => (
                    <tr key={i}>
                      <td><Badge tone={riskTone(f.risk)} size="sm">{f.severity}</Badge></td>
                      <td><code className="muted">{f.threat}</code></td>
                      <td className="meta">{f.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <div className="field-label">
            {findings.evaluation.findings.length} descriptor finding
            {findings.evaluation.findings.length === 1 ? '' : 's'}
          </div>
          <table className="table">
            <thead><tr><th>Severity</th><th>Check</th><th>What it found</th></tr></thead>
            <tbody>
              {findings.evaluation.findings.length === 0 && (
                <tr><td colSpan={3} className="meta">
                  Nothing — this tool's grade comes from the toolkit scan above.
                </td></tr>
              )}
              {findings.evaluation.findings.map((f, i) => (
                <tr key={f.id || i}>
                  <td><Badge tone={riskTone(f.severity)} size="sm">{f.severity}</Badge></td>
                  <td><code className="muted">{f.id}</code></td>
                  <td className="meta">{f.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {findings.mcp?.descriptor?.description && (
            <>
              <div className="field-label" style={{ marginTop: 16 }}>
                The descriptor as advertised at import
              </div>
              <div className="code-block">{findings.mcp.descriptor.description}</div>
              <p className="meta" style={{ marginTop: 6 }}>
                This exact text is the rug-pull baseline. If the server changes it,
                re-verifying the server quarantines the tool until an operator
                imports it again.
              </p>
            </>
          )}
        </Modal>
      )}

      {showMcp && (
        <MCPConnector
          allowPrivate={allowPrivate}
          onClose={() => setShowMcp(false)}
          onImported={refreshTools}
        />
      )}

      {/* Onboarding */}
      {showOnboard && (
        <Modal
          title="Onboard a tool"
          subtitle="Add an HTTP(S) endpoint to have allowed calls actually invoked (SSRF-guarded), or leave it blank for a governance-decision-only tool."
          onClose={() => setShowOnboard(false)}
          footer={
            <>
              <button className="btn btn-ghost" onClick={() => setShowOnboard(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={onboard} disabled={!onb.name.trim()}>
                <Plus size={14} /> Onboard tool
              </button>
            </>
          }
        >
          <div className="grid-form">
            <Field label="Name">
              <input className="mono" value={onb.name} onChange={e => setOnb(o => ({ ...o, name: e.target.value }))}
                placeholder="payments_api" />
            </Field>
            <Field label="Risk">
              <select value={onb.risk} onChange={e => setOnb(o => ({ ...o, risk: e.target.value }))}>
                {['low', 'medium', 'high', 'critical'].map(r => <option key={r}>{r}</option>)}
              </select>
            </Field>
          </div>

          <Field label="Description">
            <input value={onb.description} onChange={e => setOnb(o => ({ ...o, description: e.target.value }))}
              placeholder="What the tool does" />
          </Field>

          <Field label="Category" hint="Policies can target this with tool.category">
            <select value={onb.category} onChange={e => setOnb(o => ({ ...o, category: e.target.value }))}>
              {(tools.categories || []).map(c => <option key={c}>{c}</option>)}
            </select>
          </Field>

          <Field label="Actions" hint="Comma-separated">
            <input className="mono" value={onb.actions} onChange={e => setOnb(o => ({ ...o, actions: e.target.value }))}
              placeholder="read, write, refund" />
          </Field>

          <div className="grid-form">
            <Field label="Endpoint URL" hint="Optional — a real webhook">
              <input className="mono" value={onb.endpoint_url} onChange={e => setOnb(o => ({ ...o, endpoint_url: e.target.value }))}
                placeholder="https://example.com/hook" />
            </Field>
            <Field label="Timeout (ms)">
              <input type="number" value={onb.timeout_ms} onChange={e => setOnb(o => ({ ...o, timeout_ms: e.target.value }))} />
            </Field>
          </div>

          {!allowPrivate && (
            <div className="meta" style={{ display: 'flex', alignItems: 'flex-start', gap: 7 }}>
              <ShieldOff size={12} color="var(--yellow)" style={{ flexShrink: 0, marginTop: 3 }} />
              <span>Private and loopback endpoints are blocked. Set <code className="inline-code">AGT_TOOL_ALLOW_PRIVATE=1</code> for local testing.</span>
            </div>
          )}

          {onbMsg && (
            <div style={{ marginTop: 12, fontSize: 16, color: onbMsg.ok ? 'var(--green)' : 'var(--red)' }}>
              {onbMsg.text}
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}

// Anything after the denying gate never ran. A gate name this build does not
// know is treated as last, so the strip under-claims rather than inventing a
// skip — but GATE_ORDER is meant to be complete, and a denial landing in that
// fallback means a gate was added to the backend and not to this table.
function reached(deniedBy, gate) {
  if (!deniedBy) return false;
  const at = GATE_ORDER.indexOf(deniedBy);
  return GATE_ORDER.indexOf(gate) > (at === -1 ? GATE_ORDER.length : at);
}
