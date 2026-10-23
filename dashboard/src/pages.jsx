import { useState } from 'react'
import { api, useData } from './api.js'
import Graph from './Graph.jsx'
import {
  Chip, Empty, Loading, Notice, PageHeader, Panel, SEVERITIES, SeverityBadge, Stat, StatusBadge, Tabs, fmt,
} from './ui.jsx'

const POLL = 15000

// ---------------------------------------------------------------- Overview
export function Overview({ go }) {
  const summary = useData(api.summary, [], POLL)
  const incidents = useData(api.incidents, [], POLL)
  const actions = useData(() => api.actions(), [], POLL)

  if (!summary.data || !incidents.data) return <Loading error={summary.error || incidents.error} />
  const s = summary.data
  const cov = s.coverage.expected ? Math.round((100 * s.coverage.detected) / s.coverage.expected) : 0
  const maxSev = Math.max(1, ...SEVERITIES.map((k) => s.by_severity[k] || 0))
  const pending = (actions.data || []).filter((a) => a.status === 'proposed')

  return (
    <>
      <PageHeader title="Overview">
        <span className="muted">Refreshes every 15 seconds</span>
      </PageHeader>

      <div className="stat-grid">
        <Stat label="Incidents" value={s.incidents} hint="correlated from detection alerts" />
        <Stat label="Critical" value={s.by_severity.critical || 0} tone={s.by_severity.critical ? 'danger' : ''} hint="highest severity" />
        <Stat label="Analysed by AI" value={`${s.analysed} / ${s.incidents}`} hint="incidents with a stored analysis" />
        <Stat label="Awaiting approval" value={s.pending_actions} tone={s.pending_actions ? 'warn' : ''} hint="response actions" />
        <Stat label="Events collected" value={s.events} hint="telemetry in Elasticsearch" />
        <Stat label="Detection coverage" value={`${cov}%`} hint={`${s.coverage.detected} of ${s.coverage.expected} simulated techniques`} />
      </div>

      <div className="grid-2">
        <Panel title="Incidents by severity">
          <div className="bars">
            {SEVERITIES.map((k) => (
              <div key={k} className="bar-row">
                <span className="bar-label"><SeverityBadge level={k} /></span>
                <span className="bar-track">
                  <span className={`bar-fill sev-fill-${k}`} style={{ width: `${((s.by_severity[k] || 0) / maxSev) * 100}%` }} />
                </span>
                <span className="bar-value">{s.by_severity[k] || 0}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel
          title="Awaiting approval"
          right={<button className="link-btn" onClick={() => go('/queue')}>Open response queue</button>}
          flush
        >
          {pending.length === 0 ? (
            <Empty>No response action is waiting for a decision.</Empty>
          ) : (
            <table className="table">
              <thead>
                <tr><th>Action</th><th>Target</th><th>Incident</th></tr>
              </thead>
              <tbody>
                {pending.slice(0, 6).map((a) => (
                  <tr key={a.action_id} className="clickable" onClick={() => go(`/incidents/${a.incident_id}`)}>
                    <td className="mono">{a.action}</td>
                    <td>{a.target}</td>
                    <td className="mono">{a.incident_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <Panel
        title="Latest incidents"
        right={<button className="link-btn" onClick={() => go('/incidents')}>View all incidents</button>}
        flush
      >
        <IncidentTable rows={incidents.data.slice(0, 5)} go={go} />
      </Panel>
    </>
  )
}

// --------------------------------------------------------------- Incidents
function IncidentTable({ rows, go }) {
  if (rows.length === 0) return <Empty>No incidents match.</Empty>
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Incident</th>
          <th>Source IP</th>
          <th>Identity</th>
          <th>Tactics</th>
          <th className="num">Alerts</th>
          <th>Last alert</th>
          <th>AI analysis</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((i) => (
          <tr key={i.incident_id} className="clickable" onClick={() => go(`/incidents/${i.incident_id}`)}>
            <td><SeverityBadge level={i.severity} /></td>
            <td>
              <div className="cell-title">{i.title}</div>
              <div className="cell-sub mono">{i.incident_id}</div>
            </td>
            <td className="mono">{i.source_ip}</td>
            <td>{(i.users || []).join(', ')}</td>
            <td>{(i.tactics || []).map((t) => <Chip key={t}>{t}</Chip>)}</td>
            <td className="num">{i.alerts}</td>
            <td className="nowrap">{fmt(i.last_alert)}</td>
            <td>{i.analysed ? <span className="ok-text">Available</span> : <span className="muted">Not yet</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function Incidents({ go }) {
  const { data, error, reload } = useData(api.incidents, [], POLL)
  const [text, setText] = useState('')
  const [sev, setSev] = useState('all')
  if (!data) return <Loading error={error} />

  const q = text.trim().toLowerCase()
  const rows = data.filter((i) => {
    if (sev !== 'all' && i.severity !== sev) return false
    if (!q) return true
    return [i.incident_id, i.title, i.source_ip, ...(i.users || []), ...(i.techniques || [])]
      .join(' ').toLowerCase().includes(q)
  })

  return (
    <>
      <PageHeader title="Incidents">
        <button className="btn btn-ghost" onClick={reload}>Refresh</button>
      </PageHeader>
      <div className="toolbar">
        <input
          className="input grow"
          placeholder="Search by incident, IP, identity or technique"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <select className="input" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">All severities</option>
          {SEVERITIES.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <span className="muted">{rows.length} of {data.length}</span>
      </div>
      <Panel flush><IncidentTable rows={rows} go={go} /></Panel>
    </>
  )
}

// ------------------------------------------------------- Incident details
function severityOf(a) {
  const s = a.severity_assessment
  if (!s) return { level: null, reason: '' }
  if (typeof s === 'string') return { level: s.split(/[\s:-]/)[0].toLowerCase(), reason: s }
  return { level: s.level || s.severity, reason: s.reason || '' }
}

function AnalysisTab({ inc }) {
  const ai = inc.ai_analysis
  if (!ai) {
    return (
      <Panel>
        <Empty>No AI analysis is stored for this incident. Run <code>python analyst.py --incident {inc.incident_id}</code> in the incident-engine folder.</Empty>
      </Panel>
    )
  }
  const a = ai.analysis || {}
  const sev = severityOf(a)
  const techInfo = Object.fromEntries((inc.techniques || []).map((t) => [t.id, t]))
  const notes = ai.problems || ai.guardrail_issues || []

  return (
    <div className="grid-main-side">
      <div className="stack">
        <Panel title="Summary">
          <p className="prose">{a.summary || '-'}</p>
        </Panel>

        <Panel title="Attack story">
          {(a.attack_story || []).length === 0 ? <Empty>No story was produced.</Empty> : (
            <ol className="story">
              {a.attack_story.map((step, i) => <li key={i}>{step}</li>)}
            </ol>
          )}
        </Panel>

        <Panel title="API calls mapped to MITRE ATT&CK" flush>
          {(a.action_technique_map || []).length === 0 ? <Empty>No mapping was produced.</Empty> : (
            <table className="table">
              <thead><tr><th>API call</th><th>Technique</th><th>Name</th></tr></thead>
              <tbody>
                {a.action_technique_map.map((m, i) => (
                  <tr key={i}>
                    <td className="mono">{m.action}</td>
                    <td className="mono">{m.technique}</td>
                    <td>{(techInfo[m.technique] || {}).name || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Why these techniques apply" flush>
          {(a.mitre_techniques_explained || []).length === 0 ? <Empty>No explanation was produced.</Empty> : (
            <table className="table">
              <thead><tr><th>Technique</th><th>Evidence</th></tr></thead>
              <tbody>
                {a.mitre_techniques_explained.map((t, i) => (
                  <tr key={i}>
                    <td className="mono nowrap">
                      {techInfo[t.id] && techInfo[t.id].url
                        ? <a href={techInfo[t.id].url} target="_blank" rel="noreferrer">{t.id}</a>
                        : t.id}
                    </td>
                    <td>{t.why}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <div className="stack">
        <Panel title="Assessment">
          <dl className="kv">
            <div className="kv-row"><dt>Severity (AI)</dt><dd><SeverityBadge level={sev.level} /></dd></div>
            <div className="kv-row"><dt>Severity (stored)</dt><dd><SeverityBadge level={inc.severity} /></dd></div>
            <div className="kv-row"><dt>Confidence</dt><dd><span className={`badge conf-${a.confidence}`}>{a.confidence || '-'}</span></dd></div>
          </dl>
          {sev.reason && <p className="prose small">{sev.reason}</p>}
        </Panel>

        <Panel title="Open questions">
          {(a.uncertainties || []).length === 0 ? <Empty>None reported.</Empty> : (
            <ul className="plain-list">
              {a.uncertainties.map((u, i) => <li key={i}>{u}</li>)}
            </ul>
          )}
        </Panel>

        <Panel title="Knowledge used">
          {(a.playbooks_used || []).length === 0 ? <Empty>No playbook was cited.</Empty> : (
            <ul className="plain-list">
              {a.playbooks_used.map((p, i) => <li key={i}>{p}</li>)}
            </ul>
          )}
        </Panel>

        <Panel title="Analysis details">
          <dl className="kv">
            <div className="kv-row"><dt>Model</dt><dd>{ai.model || '-'}</dd></div>
            <div className="kv-row"><dt>Retrieval (RAG)</dt><dd>{ai.rag ? 'Enabled' : 'Disabled'}</dd></div>
            <div className="kv-row"><dt>Generated</dt><dd>{fmt(ai.generated_at)}</dd></div>
          </dl>
          {notes.length > 0 && (
            <Notice kind="warn">
              Guardrail notes: {notes.join(' ')}
            </Notice>
          )}
        </Panel>
      </div>
    </div>
  )
}

function EvidenceTab({ inc }) {
  const map = {}
  const pairs = ((inc.ai_analysis || {}).analysis || {}).action_technique_map || []
  pairs.forEach((m) => { map[m.action] = m.technique })
  const cov = inc.detection_coverage || {}
  const events = [...(inc.evidence || [])].sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)))

  return (
    <div className="stack">
      <Panel title="Detection alerts" flush>
        <table className="table">
          <thead><tr><th>Time</th><th>Rule</th><th>Severity</th></tr></thead>
          <tbody>
            {(inc.alerts || []).map((a) => (
              <tr key={a.alert_uuid}>
                <td className="nowrap">{fmt(a.time)}</td>
                <td>{a.rule}</td>
                <td><SeverityBadge level={a.severity} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="Cloud API calls" flush>
        <table className="table">
          <thead>
            <tr><th>Time</th><th>Identity</th><th>API call</th><th>Resource</th><th>Result</th><th>Technique (AI)</th></tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i}>
                <td className="nowrap">{fmt(e.timestamp)}</td>
                <td>{e.user}</td>
                <td className="mono">{e.api_action}</td>
                <td className="mono">{e.resource}</td>
                <td>{e.result}</td>
                <td className="mono">{map[e.api_action] || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="Detection coverage (lab ground truth)">
        <p className="prose small">
          The attack simulator labels every call with the technique it represents. These labels are never shown to the AI;
          they only measure how much of the simulated attack the detection rules saw.
        </p>
        <div className="cov-grid">
          <div>
            <div className="cov-title">Expected</div>
            {(cov.expected || []).map((t) => <Chip key={t} mono>{t}</Chip>)}
          </div>
          <div>
            <div className="cov-title">Detected by rules</div>
            {(cov.detected || []).map((t) => <Chip key={t} mono>{t}</Chip>)}
          </div>
          <div>
            <div className="cov-title">Missed</div>
            {(cov.missed || []).length === 0 ? <span className="muted">None</span> : cov.missed.map((t) => <Chip key={t} mono>{t}</Chip>)}
          </div>
        </div>
      </Panel>
    </div>
  )
}

// ------------------------------------------------------------ Response UI
function ActionRow({ a, analyst, onChanged, showIncident, go }) {
  const [mode, setMode] = useState(null) // null | 'approve' | 'reject'
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const run = async () => {
    setBusy(true)
    setError(null)
    try {
      if (mode === 'approve') await api.approve(a.action_id, analyst || 'analyst')
      else await api.reject(a.action_id, analyst || 'analyst', reason)
      setMode(null)
      onChanged()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const result = a.result || {}
  return (
    <tr>
      {showIncident && (
        <td className="mono nowrap">
          <button className="link-btn mono" onClick={() => go(`/incidents/${a.incident_id}`)}>{a.incident_id}</button>
        </td>
      )}
      <td><StatusBadge status={a.status} /></td>
      <td className="mono">{a.action}</td>
      <td>{a.target}</td>
      <td className="wrap">
        {a.reason}
        {a.status === 'rejected_by_validation' && <div className="cell-sub danger-text">{a.validation}</div>}
        {a.status === 'rejected' && a.reject_reason && <div className="cell-sub">Reason: {a.reject_reason}</div>}
        {result.verified !== undefined && (
          <div className="cell-sub">{result.verified ? 'Verified by configuration read-back' : 'Not verified'}</div>
        )}
        {result.note && <div className="cell-sub">{result.note}</div>}
        {result.error && <div className="cell-sub danger-text">{result.error}</div>}
        {a.decided_by && <div className="cell-sub">Decision by {a.decided_by}, {fmt(a.decided_at)}</div>}
        {error && <div className="cell-sub danger-text">{error}</div>}
      </td>
      <td className="actions-cell">
        {a.status === 'proposed' && mode === null && (
          <>
            <button className="btn btn-primary" onClick={() => setMode('approve')}>Approve</button>
            <button className="btn btn-danger" onClick={() => setMode('reject')}>Reject</button>
          </>
        )}
        {a.status === 'proposed' && mode === 'approve' && (
          <div className="confirm">
            <div className="confirm-text">Run <b>{a.action}</b> on <b>{a.target}</b> now?</div>
            <button className="btn btn-primary" disabled={busy} onClick={run}>{busy ? 'Running...' : 'Confirm'}</button>
            <button className="btn btn-ghost" disabled={busy} onClick={() => setMode(null)}>Cancel</button>
          </div>
        )}
        {a.status === 'proposed' && mode === 'reject' && (
          <div className="confirm">
            <input className="input" placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
            <button className="btn btn-danger" disabled={busy} onClick={run}>{busy ? 'Saving...' : 'Confirm reject'}</button>
            <button className="btn btn-ghost" disabled={busy} onClick={() => setMode(null)}>Cancel</button>
          </div>
        )}
      </td>
    </tr>
  )
}

function ActionsTable({ rows, analyst, onChanged, showIncident, go }) {
  if (rows.length === 0) return <Empty>No response actions.</Empty>
  return (
    <table className="table">
      <thead>
        <tr>
          {showIncident && <th>Incident</th>}
          <th>Status</th>
          <th>Action</th>
          <th>Target</th>
          <th>Details</th>
          <th>Decision</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((a) => (
          <ActionRow key={a.action_id} a={a} analyst={analyst} onChanged={onChanged} showIncident={showIncident} go={go} />
        ))}
      </tbody>
    </table>
  )
}

const ENFORCEMENT_NOTE =
  'The free LocalStack edition does not enforce IAM. Execution makes the real API calls and is verified by reading the configuration back; it does not prove that an attacker is blocked.'

function ResponseTab({ actions, analyst, onChanged, go }) {
  if (!actions.data) return <Loading error={actions.error} />
  return (
    <div className="stack">
      <Notice kind="info">
        The AI only proposes actions. Nothing runs until an analyst approves it, and every decision is written to the audit log.
      </Notice>
      <Panel title="Proposed response actions" flush>
        <ActionsTable rows={actions.data} analyst={analyst} onChanged={onChanged} go={go} />
      </Panel>
      <p className="footnote">{ENFORCEMENT_NOTE}</p>
    </div>
  )
}

export function IncidentDetail({ id, go, analyst }) {
  const inc = useData(() => api.incident(id), [id], POLL)
  const actions = useData(() => api.actions(id), [id], 10000)
  const [tab, setTab] = useState('analysis')

  if (!inc.data) return <Loading error={inc.error} />
  const i = inc.data
  const pending = (actions.data || []).filter((a) => a.status === 'proposed').length

  return (
    <>
      <PageHeader
        crumbs={<><button className="link-btn" onClick={() => go('/incidents')}>Incidents</button><span className="sep">/</span><span className="mono">{i.incident_id}</span></>}
        title={i.title}
      >
        <SeverityBadge level={i.severity} />
      </PageHeader>

      <Panel>
        <dl className="meta-grid">
          <div><dt>Source IP</dt><dd className="mono">{i.source_ip}</dd></div>
          <div><dt>Identity</dt><dd>{(i.users || []).join(', ') || '-'}</dd></div>
          <div><dt>Risk score</dt><dd>{i.risk_score}</dd></div>
          <div><dt>Status</dt><dd>{i.status}</dd></div>
          <div><dt>First alert</dt><dd>{fmt(i.first_alert)}</dd></div>
          <div><dt>Last alert</dt><dd>{fmt(i.last_alert)}</dd></div>
          <div><dt>Tactics</dt><dd>{(i.tactics || []).map((t) => <Chip key={t}>{t}</Chip>)}</dd></div>
          <div><dt>Techniques</dt><dd>{(i.techniques || []).map((t) => <Chip key={t.id} mono>{t.id}</Chip>)}</dd></div>
        </dl>
      </Panel>

      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { key: 'analysis', label: 'AI analysis' },
          { key: 'evidence', label: 'Evidence', count: (i.evidence || []).length },
          { key: 'graph', label: 'Attack graph' },
          { key: 'response', label: 'Response', count: pending || null },
        ]}
      />

      {tab === 'analysis' && <AnalysisTab inc={i} />}
      {tab === 'evidence' && <EvidenceTab inc={i} />}
      {tab === 'graph' && <Graph incidentId={id} actions={actions.data || []} />}
      {tab === 'response' && <ResponseTab actions={actions} analyst={analyst} onChanged={actions.reload} go={go} />}
    </>
  )
}

// ---------------------------------------------------------- Response queue
export function Queue({ go, analyst }) {
  const actions = useData(() => api.actions(), [], 10000)
  const [status, setStatus] = useState('all')
  if (!actions.data) return <Loading error={actions.error} />
  const statuses = [...new Set(actions.data.map((a) => a.status))]
  const rows = actions.data.filter((a) => status === 'all' || a.status === status)
  return (
    <>
      <PageHeader title="Response queue">
        <button className="btn btn-ghost" onClick={actions.reload}>Refresh</button>
      </PageHeader>
      <div className="toolbar">
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">All statuses</option>
          {statuses.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
        </select>
        <span className="muted">{rows.length} of {actions.data.length}</span>
      </div>
      <Panel flush>
        <ActionsTable rows={rows} analyst={analyst} onChanged={actions.reload} showIncident go={go} />
      </Panel>
      <p className="footnote">{ENFORCEMENT_NOTE}</p>
    </>
  )
}

// --------------------------------------------------------------- Audit log
export function Audit() {
  const audit = useData(api.audit, [], 10000)
  if (!audit.data) return <Loading error={audit.error} />
  return (
    <>
      <PageHeader title="Audit log">
        <button className="btn btn-ghost" onClick={audit.reload}>Refresh</button>
      </PageHeader>
      <Panel flush>
        {audit.data.length === 0 ? <Empty>No audit entries yet.</Empty> : (
          <table className="table">
            <thead><tr><th>Time</th><th>Action</th><th>Event</th><th>By</th><th>Detail</th></tr></thead>
            <tbody>
              {audit.data.map((a, i) => (
                <tr key={i}>
                  <td className="nowrap">{fmt(a.time)}</td>
                  <td className="mono">{a.action_id}</td>
                  <td>{a.event}</td>
                  <td>{a.by}</td>
                  <td className="mono wrap small">{JSON.stringify(a.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  )
}
