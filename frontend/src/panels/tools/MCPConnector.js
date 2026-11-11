import { useState } from 'react';
import { Plug, Search, Download, ShieldAlert, ShieldOff, CheckCircle, AlertTriangle } from '../../icons';
import { api } from '../../api';
import { Modal, Badge, Field, Empty, Notice, riskTone } from '../../ui';

const RISK_ORDER = ['low', 'medium', 'high', 'critical'];

const TRANSPORTS = [
  { id: 'auto', label: 'Auto — HTTP, fall back to SSE' },
  { id: 'http', label: 'Streamable HTTP (2025-03-26+)' },
  { id: 'sse', label: 'HTTP + SSE (legacy 2024-11-05)' },
  { id: 'stdio', label: 'Local — stdio (this machine)' },
];

/* The runtimes AGT's command allowlist accepts. Shown so the field can say what
   will work before the server refuses it; the list that decides is the
   toolkit's, applied on the backend at spawn time. */
const LOCAL_RUNTIMES = 'python, python3, node, npx, uv, uvx, pipx, docker, podman, deno, bun, java, dotnet, go, cargo';

/** Split a command line into argv without pretending to be a shell.
 *  Quoted runs stay together; nothing is expanded, because nothing is a shell
 *  here — the backend passes argv straight to the process. */
function splitArgs(line) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line)) !== null) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/** Mirrors MCP_AUTH_ENV_RE in backend/tool_registry.py — only these are readable at call time. */
const AUTH_ENV_RE = /^AGT_MCP_[A-Z0-9_]{1,48}$/;

const CATEGORY_LABEL = {
  code_execution: 'code execution',
  data_write: 'data write',
  data_read: 'data read',
};
const categoryLabel = (c) => CATEGORY_LABEL[c] || c;

/**
 * Connect an MCP server, read what it is asking the model to trust, then decide.
 *
 * Discovery is deliberately a separate step from import: the whole point is that
 * an operator sees the descriptor findings — instructions aimed at the model,
 * characters hiding them, destructive capability, open schemas — before any of
 * those tools become callable. The risk ceiling is enforced by the backend, not
 * here; this only chooses what to ask for.
 */
export default function MCPConnector({ allowPrivate, onClose, onImported }) {
  const [conn, setConn] = useState({
    server_url: '', auth_token: '', auth_env: '', transport: 'auto',
    command: '', argline: '', cwd: '',
  });
  const [discovery, setDiscovery] = useState(null);
  const [selected, setSelected] = useState(() => new Set());
  const [maxRisk, setMaxRisk] = useState('');
  const [categories, setCategories] = useState(() => new Set());
  const [open, setOpen] = useState(() => new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const toggle = (set, key) => {
    const next = new Set(set);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  };

  const isLocal = conn.transport === 'stdio';

  /* A local server is launched, a remote one dialled. Sending both addressing
     forms would leave the backend guessing which one was meant. */
  const connectionBody = () => (isLocal
    ? {
        transport: 'stdio',
        command: conn.command.trim(),
        args: splitArgs(conn.argline),
        cwd: conn.cwd.trim() || null,
        // Discovery has to start the server to ask what it offers, and a first
        // npx/uvx run may fetch the package first.
        timeout_ms: 30000,
        call_timeout_ms: 30000,
      }
    : {
        transport: conn.transport,
        server_url: conn.server_url.trim(),
        auth_token: conn.auth_token.trim() || null,
      });

  const canConnect = isLocal ? !!conn.command.trim() : !!conn.server_url.trim();

  const discover = async () => {
    setBusy(true); setError(null); setResult(null);
    try {
      const d = await api.mcp.discover(connectionBody());
      setDiscovery(d);
      setSelected(new Set(d.tools.map(t => t.name)));
      setCategories(new Set());
    } catch (e) {
      setDiscovery(null);
      setError(typeof e.message === 'string' ? e.message : 'Discovery failed');
    }
    setBusy(false);
  };

  const runImport = async () => {
    setBusy(true); setError(null);
    try {
      const r = await api.mcp.import({
        ...connectionBody(),
        auth_env: conn.auth_env.trim() || null,
        tools: [...selected],
        categories: [...categories],
        max_risk: maxRisk || null,
      });
      setResult(r);
      onImported?.();
    } catch (e) {
      setError(typeof e.message === 'string' ? e.message : 'Import failed');
    }
    setBusy(false);
  };

  const authEnv = conn.auth_env.trim();
  const authEnvError = authEnv && !AUTH_ENV_RE.test(authEnv)
    ? 'Must be named AGT_MCP_… — only those variables are readable at call time'
    : null;

  const summary = discovery?.summary;
  const presentCategories = Object.keys(summary?.categories || {});

  return (
    <Modal
      title="Connect an MCP server"
      subtitle="Discover the tools a Model Context Protocol server offers, evaluate every descriptor, then onboard the ones you accept. Imported tools are governed by the same four gates as any other, plus AGT's MCP trust proxy at dispatch — which scans the call arguments the descriptor evaluation never sees."
      width={720}
      busy={busy}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-ghost" onClick={onClose}>Close</button>
          <button className="btn btn-ghost" onClick={discover}
            disabled={busy || !canConnect}>
            <Search size={14} /> {busy && !discovery ? 'Connecting' : 'Discover'}
          </button>
          <button className="btn btn-primary" onClick={runImport}
            disabled={busy || !discovery || selected.size === 0 || !!authEnvError}>
            <Download size={14} /> Import {selected.size || ''}
          </button>
        </>
      }
    >
      <div className="grid-form">
        {isLocal ? (
          <Field label="Command" hint={`Launched on this machine. One of: ${LOCAL_RUNTIMES}`}>
            <input className="mono" value={conn.command} placeholder="python"
              onChange={e => setConn(c => ({ ...c, command: e.target.value }))} />
          </Field>
        ) : (
          <Field label="Server URL" hint="Remote MCP endpoint">
            <input className="mono" value={conn.server_url} placeholder="https://mcp.example.com/mcp"
              onChange={e => setConn(c => ({ ...c, server_url: e.target.value }))} />
          </Field>
        )}
        <Field label="Transport"
          hint={isLocal ? 'This platform starts the server itself' : 'How a remote server is reached'}>
          <select value={conn.transport} onChange={e => setConn(c => ({ ...c, transport: e.target.value }))}>
            {TRANSPORTS.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
        </Field>
      </div>

      {isLocal ? (
        <div className="grid-form">
          <Field label="Arguments"
            hint="Split on spaces; quote anything containing one. Not a shell — no expansion.">
            <input className="mono" value={conn.argline}
              placeholder="-y @modelcontextprotocol/server-filesystem /tmp"
              onChange={e => setConn(c => ({ ...c, argline: e.target.value }))} />
          </Field>
          <Field label="Working directory" hint="Optional. Where the command runs.">
            <input className="mono" value={conn.cwd} placeholder="(the server's own default)"
              onChange={e => setConn(c => ({ ...c, cwd: e.target.value }))} />
          </Field>
        </div>
      ) : (
        <div className="grid-form">
          <Field label="Bearer token" hint="Used for this request only — never stored">
            <input className="mono" type="password" value={conn.auth_token}
              onChange={e => setConn(c => ({ ...c, auth_token: e.target.value }))} />
          </Field>
          <Field label="Token variable" error={authEnvError}
            hint="Env var read at call time, e.g. AGT_MCP_NOTES. Leave blank for an unauthenticated server.">
            <input className="mono" value={conn.auth_env} placeholder="AGT_MCP_…"
              onChange={e => setConn(c => ({ ...c, auth_env: e.target.value.toUpperCase() }))} />
          </Field>
        </div>
      )}

      <Field label="Import ceiling" hint="Refuse to onboard anything graded above this">
        <select value={maxRisk} onChange={e => setMaxRisk(e.target.value)}>
          <option value="">No ceiling — import everything</option>
          {RISK_ORDER.map(r => <option key={r} value={r}>{r} and below</option>)}
        </select>
      </Field>

      {isLocal ? (
        <div className="meta" style={{ display: 'flex', alignItems: 'flex-start', gap: 7 }}>
          <ShieldAlert size={12} color="var(--yellow)" style={{ flexShrink: 0, marginTop: 3 }} />
          <span>
            Discovering a local server <strong>starts it</strong> — that is how stdio
            works, and it runs as this backend process. The command must be one of
            the runtimes on the Agent Governance Toolkit's allowlist, the child gets
            a sanitised environment, and it is launched without a shell. Every tool
            from a local server is graded at least <code className="inline-code">medium</code>,
            so dispatching one needs more trust than a remote tool of the same
            description.
          </span>
        </div>
      ) : !allowPrivate && (
        <div className="meta" style={{ display: 'flex', alignItems: 'flex-start', gap: 7 }}>
          <ShieldOff size={12} color="var(--yellow)" style={{ flexShrink: 0, marginTop: 3 }} />
          <span>Private and loopback servers are blocked. Set <code className="inline-code">AGT_TOOL_ALLOW_PRIVATE=1</code> to reach an MCP server on this host over HTTP.</span>
        </div>
      )}

      {error && (
        <Notice tone="danger" icon={<AlertTriangle size={14} />} style={{ marginTop: 14 }}>
          {error}
        </Notice>
      )}

      {discovery && !result && (
        <div style={{ marginTop: 18 }}>
          <div className="cluster cluster-6" style={{ marginBottom: 10 }}>
            <Plug size={14} color="var(--text-3)" />
            <code style={{ color: 'var(--text)' }}>{discovery.server_info?.name || 'unnamed server'}</code>
            <Badge tone="info" size="sm">{
              discovery.transport === 'stdio' ? 'Local · stdio'
                : discovery.transport === 'sse' ? 'HTTP + SSE' : 'Streamable HTTP'
            }</Badge>
            <span className="meta mono">MCP {discovery.protocol_version}</span>
            <Badge tone={riskTone(summary.risk)} size="sm">{summary.risk}</Badge>
            <span className="meta spacer">{summary.flagged} of {summary.tools} flagged</span>
          </div>

          {presentCategories.length > 1 && (
            <Field label="Only import these categories" hint="None selected imports every category">
              <div className="cluster cluster-6">
                {presentCategories.map(c => (
                  <button key={c}
                    className={`btn btn-xs ${categories.has(c) ? 'btn-primary' : 'btn-ghost'}`}
                    onClick={() => setCategories(s => toggle(s, c))}>
                    {categoryLabel(c)} · {summary.categories[c]}
                  </button>
                ))}
              </div>
            </Field>
          )}

          {discovery.tools.length === 0
            ? <Empty>This server advertises no tools.</Empty>
            : discovery.tools.map(t => {
              const ev = t.evaluation;
              const expanded = open.has(t.name);
              return (
                <div key={t.name} className="row" style={{ alignItems: 'flex-start' }}>
                  <input type="checkbox" checked={selected.has(t.name)} style={{ marginTop: 4 }}
                    onChange={() => setSelected(s => toggle(s, t.name))} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="cluster cluster-6">
                      <code style={{ color: 'var(--text)', fontSize: 16 }}>{t.name}</code>
                      <Badge tone={riskTone(ev.risk)} size="sm">{ev.risk}</Badge>
                      <Badge tone="neutral" size="sm">{categoryLabel(ev.category)}</Badge>
                      {ev.findings.length > 0 && (
                        <button className="btn btn-quiet btn-xs" onClick={() => setOpen(o => toggle(o, t.name))}>
                          <ShieldAlert size={12} color="var(--yellow)" />
                          {ev.findings.length} finding{ev.findings.length > 1 ? 's' : ''}
                        </button>
                      )}
                    </div>
                    {t.description && (
                      <div className="meta" style={{ marginTop: 3, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                        {t.description.slice(0, 240)}{t.description.length > 240 ? '…' : ''}
                      </div>
                    )}
                    {expanded && ev.findings.map(f => (
                      <div key={f.id} className="meta" style={{ marginTop: 6, display: 'flex', gap: 7 }}>
                        <Badge tone={riskTone(f.severity)} size="sm">{f.severity}</Badge>
                        <span style={{ overflowWrap: 'anywhere' }}><code className="inline-code">{f.id}</code> — {f.detail}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 18 }}>
          <Notice tone={result.skipped.length ? 'warn' : 'success'}
            icon={result.skipped.length ? <ShieldAlert size={14} /> : <CheckCircle size={14} />}>
            Imported {result.imported.length} tool{result.imported.length === 1 ? '' : 's'} from
            {' '}<code className="inline-code">{result.server}</code>
            {' '}over {result.transport === 'sse' ? 'HTTP + SSE' : 'Streamable HTTP'}
            {result.skipped.length > 0 && <> · {result.skipped.length} refused</>}
          </Notice>
          {result.imported.map(t => (
            <div key={t.name} className="row" style={{ alignItems: 'flex-start' }}>
              <CheckCircle size={14} color="var(--green)" style={{ marginTop: 3 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="cluster cluster-6">
                  <code style={{ color: 'var(--text)' }}>{t.name}</code>
                  <Badge tone={riskTone(t.risk)} size="sm">{t.risk}</Badge>
                  <Badge tone="neutral" size="sm">{categoryLabel(t.category)}</Badge>
                </div>
                {/* What AGT's trust proxy will enforce at dispatch, derived
                    from this tool's own grade. Shown at import so a tool that
                    is onboarded but can never run says so up front. */}
                {t.runtime_policy && (
                  <div className="meta" style={{ marginTop: 3 }}>
                    {t.runtime_policy.blocked
                      ? <span style={{ color: 'var(--red)' }}>
                          Blocked at dispatch — a critical grade is refused outright
                        </span>
                      : <>
                          At dispatch: needs trust ≥ {t.runtime_policy.min_trust}
                          {' · '}{t.runtime_policy.max_calls_per_minute}/min
                          {t.runtime_policy.required_capabilities.length > 0 && <>
                            {' · '}needs {t.runtime_policy.required_capabilities.join(', ')}
                          </>}
                          {' · '}arguments scanned
                        </>}
                  </div>
                )}
              </div>
            </div>
          ))}
          {result.skipped.map(s => (
            <div key={s.tool} className="row" style={{ alignItems: 'flex-start' }}>
              <ShieldAlert size={14} color="var(--red)" style={{ marginTop: 3 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <code style={{ color: 'var(--text)' }}>{s.tool}</code>
                <div className="meta" style={{ marginTop: 3 }}>{s.reason}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}
