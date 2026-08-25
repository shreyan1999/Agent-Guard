import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Cpu, Users, Activity, BookOpen, FileText,
  Zap, AlertTriangle, CheckCircle, XCircle, RefreshCw,
  ChevronRight, Terminal, Lock
} from 'lucide-react';
import { api } from './api';
import PolicyPanel from './panels/PolicyPanel';
import ToolPanel from './panels/ToolPanel';
import TrustPanel from './panels/TrustPanel';
import AuditPanel from './panels/AuditPanel';
import SREPanel from './panels/SREPanel';
import CompliancePanel from './panels/CompliancePanel';
import AgentsPanel from './panels/AgentsPanel';

const NAV = [
  { id: 'overview',    label: 'Overview',        icon: Activity },
  { id: 'policy',      label: 'Policy Engine',   icon: Shield },
  { id: 'tools',       label: 'Tool Playground',  icon: Terminal },
  { id: 'trust',       label: 'Trust & Identity', icon: Lock },
  { id: 'agents',      label: 'Agents',           icon: Users },
  { id: 'sre',         label: 'Agent SRE',        icon: Zap },
  { id: 'compliance',  label: 'Compliance',       icon: BookOpen },
  { id: 'audit',       label: 'Audit Log',        icon: FileText },
];

export default function App() {
  const [tab, setTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [healthy, setHealthy] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [s, h] = await Promise.all([api.stats(), api.health()]);
      setStats(s);
      setHealthy(h.status === 'ok');
    } catch {
      setHealthy(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar */}
      <aside style={{
        width: 220, background: 'var(--bg-2)', borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 16px 16px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: 'linear-gradient(135deg, var(--accent), var(--purple))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Cpu size={18} color="#000" />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, lineHeight: 1.2 }}>AGT</div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
                Governance
              </div>
            </div>
          </div>
          {/* health dot */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 12 }}>
            <div style={{
              width: 7, height: 7, borderRadius: '50%',
              background: healthy === null ? 'var(--yellow)' : healthy ? 'var(--green)' : 'var(--red)',
              boxShadow: healthy ? '0 0 6px var(--green)' : 'none',
            }} />
            <span style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
              {healthy === null ? 'connecting…' : healthy ? 'API online' : 'API offline'}
            </span>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }}>
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 10px', borderRadius: 7, marginBottom: 2,
                background: tab === id ? 'var(--accent-dim)' : 'transparent',
                color: tab === id ? 'var(--accent)' : 'var(--text-2)',
                border: tab === id ? '1px solid var(--accent)33' : '1px solid transparent',
                fontSize: 13, fontWeight: tab === id ? 600 : 400,
                transition: 'all .15s',
              }}
            >
              <Icon size={15} />
              {label}
              {tab === id && <ChevronRight size={12} style={{ marginLeft: 'auto' }} />}
            </button>
          ))}
        </nav>

        {/* Version */}
        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 10, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
            agent-governance-toolkit v4.1.0
          </div>
        </div>
      </aside>

      {/* Main */}
      <main style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
        {tab === 'overview' && <Overview stats={stats} onRefresh={refresh} onNav={setTab} />}
        {tab === 'policy'     && <PolicyPanel />}
        {tab === 'tools'      && <ToolPanel />}
        {tab === 'trust'      && <TrustPanel />}
        {tab === 'agents'     && <AgentsPanel />}
        {tab === 'sre'        && <SREPanel />}
        {tab === 'compliance' && <CompliancePanel />}
        {tab === 'audit'      && <AuditPanel />}
      </main>
    </div>
  );
}

function Stat({ label, value, accent, sub }) {
  return (
    <div className="card" style={{ flex: 1, minWidth: 140 }}>
      <div className="card-title">{label}</div>
      <div style={{ fontSize: 32, fontWeight: 700, color: accent || 'var(--text)', fontFamily: 'var(--mono)' }}>
        {value ?? '—'}
      </div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function Overview({ stats, onRefresh, onNav }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>Agent Governance Dashboard</h1>
          <p style={{ color: 'var(--text-2)', marginTop: 4, fontSize: 13 }}>
            Live view of your agent governance posture — powered by Microsoft Agent Governance Toolkit
          </p>
        </div>
        <button className="btn btn-ghost" onClick={onRefresh} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Stat row */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
        <Stat label="Agents" value={stats?.total_agents} accent="var(--accent)" sub={`${stats?.active_agents ?? 0} active`} />
        <Stat label="Policies" value={stats?.total_policies} accent="var(--purple)" />
        <Stat label="Governed Tools" value={stats?.total_governed_tools} accent="var(--yellow)" />
        <Stat label="Audit Events" value={stats?.audit_events} sub={`${stats?.denials ?? 0} denials`} />
        <Stat label="Allow Rate" value={stats ? stats.allow_rate + '%' : null} accent="var(--green)" />
      </div>

      {/* Agent status table */}
      {stats?.agents?.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-title">Agent Status</div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Agent', 'Status', 'Trust', 'Policy', 'Calls', 'Denials'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '6px 10px', fontSize: 11, color: 'var(--text-3)', fontWeight: 600, letterSpacing: '.5px' }}>{h.toUpperCase()}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {stats.agents.map(a => (
                <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '9px 10px', fontFamily: 'var(--mono)', fontSize: 12 }}>{a.id}</td>
                  <td style={{ padding: '9px 10px' }}>
                    <span className={`tag ${a.status === 'active' ? 'allow' : 'deny'}`}>
                      {a.status}
                    </span>
                  </td>
                  <td style={{ padding: '9px 10px' }}>
                    <TrustBar score={a.trust_score} />
                  </td>
                  <td style={{ padding: '9px 10px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-2)' }}>{a.policy}</td>
                  <td style={{ padding: '9px 10px', fontFamily: 'var(--mono)', fontSize: 12 }}>{a.calls}</td>
                  <td style={{ padding: '9px 10px', fontFamily: 'var(--mono)', fontSize: 12, color: a.denials > 0 ? 'var(--red)' : 'var(--text-3)' }}>{a.denials}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Quick nav cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(220px,1fr))', gap: 14 }}>
        {[
          { id: 'policy', title: 'Policy Engine', desc: 'Create & evaluate YAML governance policies', icon: Shield, color: 'var(--accent)' },
          { id: 'tools', title: 'Tool Playground', desc: 'Test governed tool calls and see decisions', icon: Terminal, color: 'var(--yellow)' },
          { id: 'trust', title: 'Trust & Identity', desc: 'Evaluate agent trust scores and delegation', icon: Lock, color: 'var(--purple)' },
          { id: 'compliance', title: 'Compliance', desc: 'Prompt injection scan + OWASP coverage', icon: BookOpen, color: 'var(--green)' },
          { id: 'sre', title: 'Agent SRE', desc: 'SLOs, kill switch, error budgets', icon: Zap, color: 'var(--red)' },
          { id: 'audit', title: 'Audit Log', desc: 'Hash-chained governance event stream with integrity verification', icon: FileText, color: 'var(--text-2)' },
        ].map(({ id, title, desc, icon: Icon, color }) => (
          <button
            key={id}
            onClick={() => onNav(id)}
            className="card"
            style={{ textAlign: 'left', cursor: 'pointer', transition: 'border-color .15s', width: '100%' }}
            onMouseEnter={e => e.currentTarget.style.borderColor = color}
            onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <Icon size={20} color={color} style={{ marginBottom: 10 }} />
            <div style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{desc}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function TrustBar({ score }) {
  const pct = Math.round((score || 0) * 100);
  const color = pct >= 80 ? 'var(--green)' : pct >= 50 ? 'var(--yellow)' : 'var(--red)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 60, height: 5, background: 'var(--bg-4)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color }}>{pct}%</span>
    </div>
  );
}
