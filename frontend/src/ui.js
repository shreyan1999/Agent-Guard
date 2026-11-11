/**
 * Shared presentation primitives.
 *
 * Purely visual — no state, no data access. They exist so every page spells
 * the same idea (a page header, a grouping panel, a status badge, a labelled
 * field, a score meter) exactly one way.
 */

import { X } from './icons';

/* ── page header ─────────────────────────────────────────────────────────── */

export function PageHeader({ title, subtitle, actions }) {
  return (
    <header className="page-head">
      <div className="page-head-text">
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

/* ── panel (a card, used only for meaningful grouping) ───────────────────── */

export function Panel({
  title, desc, actions, children,
  scroll = false, bodyClass = '', className = '', style, bodyStyle,
}) {
  return (
    <section className={`panel ${scroll ? 'panel-scroll' : ''} ${className}`} style={style}>
      {(title || actions) && (
        <div className="panel-head">
          <div className="panel-head-text">
            {title && <h2 className="panel-title">{title}</h2>}
            {desc && <p className="panel-desc">{desc}</p>}
          </div>
          {actions && <div className="cluster">{actions}</div>}
        </div>
      )}
      <div className={`panel-body ${bodyClass}`} style={bodyStyle}>{children}</div>
    </section>
  );
}

/* ── modal ───────────────────────────────────────────────────────────────── */

/**
 * A dialog for a form that would otherwise push the page past one screen.
 * Same fields, same handlers — only the surface they sit on differs.
 */
export function Modal({ title, subtitle, onClose, children, footer, width, busy = false }) {
  return (
    <div className="overlay" onClick={() => !busy && onClose()}>
      <div className="modal animate-in" style={width ? { width } : undefined}
        onClick={e => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="panel-head">
          <div className="panel-head-text">
            <h2 className="panel-title">{title}</h2>
            {subtitle && <p className="panel-desc">{subtitle}</p>}
          </div>
          <button className="btn btn-quiet btn-icon" onClick={() => !busy && onClose()} aria-label="Close">
            <X size={17} />
          </button>
        </div>
        <div className="panel-body">{children}</div>
        {footer && <div className="panel-foot cluster" style={{ justifyContent: 'flex-end' }}>{footer}</div>}
      </div>
    </div>
  );
}

/* ── badges ──────────────────────────────────────────────────────────────── */

const TONE_CLASS = {
  success: 'badge-success',
  danger: 'badge-danger',
  warn: 'badge-warn',
  info: 'badge-info',
  purple: 'badge-purple',
  neutral: 'badge-neutral',
};

export function Badge({ tone = 'neutral', dot = false, size, children, className = '', style, title }) {
  return (
    <span
      className={`badge ${TONE_CLASS[tone] || TONE_CLASS.neutral} ${size === 'sm' ? 'badge-sm' : ''} ${className}`}
      style={style}
      title={title}
    >
      {dot && <span className="badge-dot" />}
      {children}
    </span>
  );
}

/** allow / deny / warn wording used across the governance panels */
export const decisionTone = (allowed) => (allowed ? 'success' : 'danger');

export const actionTone = (action) =>
  action === 'allow' ? 'success' : action === 'deny' ? 'danger' : 'warn';

export const statusTone = (status) => (status === 'active' ? 'success' : 'danger');

export const riskTone = (risk) =>
  risk === 'low' ? 'success' : risk === 'medium' ? 'warn' : 'danger';

/** shared trust thresholds: >=80% healthy, >=50% caution, below that at risk */
export const scoreColor = (score) =>
  score >= 0.8 ? 'var(--green)' : score >= 0.5 ? 'var(--yellow)' : 'var(--red)';

export const scoreTone = (score) =>
  score >= 0.8 ? 'success' : score >= 0.5 ? 'warn' : 'danger';

/* ── form field ──────────────────────────────────────────────────────────── */

export function Field({ label, hint, error, children, className = '', style }) {
  return (
    <label className={`field ${className}`} style={style}>
      {label && <span className="field-label">{label}</span>}
      {children}
      {error ? <span className="field-hint error">{error}</span>
        : hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

/* ── stats ───────────────────────────────────────────────────────────────── */

export function StatStrip({ children, className = '' }) {
  return <div className={`stat-strip ${className}`}>{children}</div>;
}

export function Stat({ label, value, sub, color }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={color ? { color } : undefined}>{value ?? '—'}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

/* ── meter ───────────────────────────────────────────────────────────────── */

/** `value` is a 0–100 percentage. */
export function Meter({ value, color, width, className = '' }) {
  const pct = Math.max(0, Math.min(100, value || 0));
  return (
    <div className={`meter ${className}`} style={width ? { width } : undefined}>
      <div className="meter-fill" style={{ width: `${pct}%`, background: color || 'var(--accent)' }} />
    </div>
  );
}

/** meter + numeric readout, the standard way a trust score is shown */
export function ScoreMeter({ score, width = 72 }) {
  const pct = Math.round((score || 0) * 100);
  const color = scoreColor(score || 0);
  return (
    <div className="meter-row">
      <Meter value={pct} color={color} width={width} />
      <span className="meter-value" style={{ color }}>{pct}%</span>
    </div>
  );
}

/* ── notice ──────────────────────────────────────────────────────────────── */

export function Notice({ tone = 'info', icon, children, onClose, className = '', style }) {
  return (
    <div className={`notice notice-${tone} ${className}`} style={style}>
      {icon}
      <div className="notice-body">{children}</div>
      {onClose && (
        <button className="notice-close" onClick={onClose} aria-label="Dismiss">
          <X size={14} />
        </button>
      )}
    </div>
  );
}

/* ── empty state ─────────────────────────────────────────────────────────── */

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

/* ── tilt ────────────────────────────────────────────────────────────────── */

/**
 * Wraps a card so it tips toward the pointer in 3D and lights a glare where
 * the cursor is. The wrapper carries the grid placement (spans, hue) because
 * it — not the card inside it — is the grid item.
 */
