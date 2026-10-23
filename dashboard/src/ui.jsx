// Small shared building blocks: badges, panels, tabs, formatting helpers.

export const SEVERITIES = ['critical', 'high', 'medium', 'low']

export function fmt(ts) {
  if (!ts) return '-'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  })
}

export function SeverityBadge({ level }) {
  const l = String(level || 'low').toLowerCase()
  return <span className={`badge sev-${l}`}>{l}</span>
}

const STATUS_LABEL = {
  proposed: 'Awaiting approval',
  executed: 'Executed',
  failed: 'Failed',
  rejected: 'Rejected',
  rejected_by_validation: 'Refused by validation',
  simulated: 'Simulated',
  recorded: 'Recorded',
}

export function StatusBadge({ status }) {
  return <span className={`badge st-${status}`}>{STATUS_LABEL[status] || status}</span>
}

export function Chip({ children, mono }) {
  return <span className={mono ? 'chip mono' : 'chip'}>{children}</span>
}

export function Panel({ title, right, flush, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || right) && (
        <header className="panel-head">
          <h3>{title}</h3>
          <div>{right}</div>
        </header>
      )}
      <div className={flush ? 'panel-body flush' : 'panel-body'}>{children}</div>
    </section>
  )
}

export function Stat({ label, value, hint, tone }) {
  return (
    <div className="panel stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${tone || ''}`}>{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  )
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <nav className="tabs">
      {tabs.map((t) => (
        <button
          key={t.key}
          className={t.key === active ? 'tab active' : 'tab'}
          onClick={() => onChange(t.key)}
        >
          {t.label}
          {t.count !== undefined && t.count !== null && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </nav>
  )
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>
}

export function Notice({ kind = 'info', children }) {
  return <div className={`notice ${kind}`}>{children}</div>
}

export function PageHeader({ crumbs, title, children }) {
  return (
    <div className="page-head">
      {crumbs && <div className="crumbs">{crumbs}</div>}
      <div className="page-title-row">
        <h1>{title}</h1>
        <div>{children}</div>
      </div>
    </div>
  )
}

export function Loading({ error }) {
  if (error) return <Notice kind="error">Could not load data: {error}</Notice>
  return <div className="empty">Loading...</div>
}
