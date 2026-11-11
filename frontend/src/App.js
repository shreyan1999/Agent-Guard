import { useState, useEffect, useCallback } from 'react';
import { api } from './api';
import GlassNav from './GlassNav';
import Landing from './Landing';
import GlassSurface, { refreshGlass } from './GlassSurface';
import './vendor/liquid-glass/glass.css';
import ThemeToggle from './ThemeToggle';
import PolicyPanel from './panels/PolicyPanel';
import ToolPanel from './panels/ToolPanel';
import TrustPanel from './panels/TrustPanel';
import AuditPanel from './panels/AuditPanel';
import SREPanel from './panels/SREPanel';
import CompliancePanel from './panels/CompliancePanel';
import AgentsPanel from './panels/AgentsPanel';
import OverviewPanel from './panels/OverviewPanel';

const NAV = [
  { id: 'overview',    label: 'Overview' },
  { id: 'policy',      label: 'Policy Engine' },
  { id: 'tools',       label: 'Tool Playground' },
  { id: 'trust',       label: 'Trust & Identity' },
  { id: 'agents',      label: 'Agents' },
  { id: 'sre',         label: 'Agent SRE' },
  { id: 'compliance',  label: 'Compliance' },
  { id: 'audit',       label: 'Audit Log' },
];

const THEME_KEY = 'agt.theme';

export default function App() {
  const [tab, setTab] = useState('overview');
  // The hero is the entry point; Get started hands over to the dashboard.
  const [entered, setEntered] = useState(false);
  const [healthy, setHealthy] = useState(null);
  // Fluent is a light-first system, so light is the default; only an explicit
  // choice moves it.
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light'; } catch { return 'light'; }
  });

  useEffect(() => {
    // Everything behind the glass is repainted, so the snapshot it refracts is
    // stale until it is re-taken.
    refreshGlass();
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* private mode */ }
  }, [theme]);

  // Only the health probe. This used to poll /stats alongside it and drop the
  // result on the floor: OverviewPanel takes no props and loads what it needs
  // itself, so the reply was never read. /stats walks the whole audit chain to
  // build its counters, which made the discarded call the most expensive
  // request the dashboard made, every eight seconds, per open tab.
  const refresh = useCallback(async () => {
    try {
      const h = await api.health();
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

  const health = healthy === null ? 'Connecting' : healthy ? 'API online' : 'API offline';

  if (!entered) {
    return <Landing onEnter={() => { setTab('overview'); setEntered(true); }} />;
  }

  return (
    <>
      {/* Both themes are matte now — white and black — so nothing is painted
          over the body background. */}

    <div className="app">
      {/* The brand bar is gone; the pivot is the only chrome. Its two live
          controls moved here rather than being deleted with it — the theme
          switch is the sole way to change theme, and the health dot is the
          only signal that the API is reachable. */}
      {/* The nav is the one surface that is always on screen, so it is the one
          that carries the real WebGL glass. */}
      <GlassSurface className="pivotbar" type="pill" radius={999} tintOpacity={0.18}>
        <GlassNav items={NAV} active={tab} onSelect={setTab} />

        <div className="pivot-actions">
          <span className="pivot-status" title={health}>
            <span className={`status-dot ${healthy === null ? 'idle' : healthy ? 'ok' : 'bad'}`} />
            {health}
          </span>
          <ThemeToggle theme={theme} onChange={setTheme} />
        </div>
      </GlassSurface>

      <main className="main">
        <div className="container">
          {/* Keyed on the tab so each destination remounts and plays the
              top-level fade. Destinations are large, so Fluent fades between
              them rather than sliding — sliding would imply a spatial
              relationship the tabs don't have. */}
          <div className="page-swap" key={tab}>
            {tab === 'overview'   && <OverviewPanel />}
            {tab === 'policy'     && <PolicyPanel />}
            {tab === 'tools'      && <ToolPanel />}
            {tab === 'trust'      && <TrustPanel />}
            {tab === 'agents'     && <AgentsPanel />}
            {tab === 'sre'        && <SREPanel />}
            {tab === 'compliance' && <CompliancePanel />}
            {tab === 'audit'      && <AuditPanel />}
          </div>
        </div>
      </main>
    </div>
    </>
  );
}
