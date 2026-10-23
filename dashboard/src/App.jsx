import { useEffect, useState } from 'react'
import { Audit, IncidentDetail, Incidents, Overview, Queue } from './pages.jsx'

// Tiny hash router: #/incidents/INC-1234 -> { page: 'incident', id: 'INC-1234' }
function parse(hash) {
  const path = hash.replace(/^#/, '') || '/'
  if (path.startsWith('/incidents/')) return { page: 'incident', id: decodeURIComponent(path.slice('/incidents/'.length)) }
  if (path === '/incidents') return { page: 'incidents' }
  if (path === '/queue') return { page: 'queue' }
  if (path === '/audit') return { page: 'audit' }
  return { page: 'overview' }
}

function useRoute() {
  const [route, setRoute] = useState(() => parse(window.location.hash))
  useEffect(() => {
    const onChange = () => setRoute(parse(window.location.hash))
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  const go = (path) => { window.location.hash = path }
  return [route, go]
}

function readName() {
  try {
    return window.localStorage.getItem('kestrel-analyst') || 'analyst'
  } catch {
    return 'analyst'
  }
}

const NAV = [
  { key: 'overview', label: 'Overview', path: '/' },
  { key: 'incidents', label: 'Incidents', path: '/incidents' },
  { key: 'queue', label: 'Response queue', path: '/queue' },
  { key: 'audit', label: 'Audit log', path: '/audit' },
]

export default function App() {
  const [route, go] = useRoute()
  const [analyst, setAnalyst] = useState(readName)

  const rename = (value) => {
    setAnalyst(value)
    try {
      window.localStorage.setItem('kestrel-analyst', value)
    } catch {
      /* storage not available: the name simply is not remembered */
    }
  }

  const active = route.page === 'incident' ? 'incidents' : route.page

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">Kestrel</div>
        <div className="brand-sub">Cloud security operations</div>
        <div className="spacer" />
        <label className="who">
          <span>Analyst</span>
          <input className="input" value={analyst} onChange={(e) => rename(e.target.value)} aria-label="Analyst name" />
        </label>
      </header>

      <div className="body">
        <nav className="sidebar">
          {NAV.map((n) => (
            <button key={n.key} className={n.key === active ? 'nav-item active' : 'nav-item'} onClick={() => go(n.path)}>
              {n.label}
            </button>
          ))}
          <div className="nav-foot">Lab environment</div>
        </nav>

        <main className="content">
          {route.page === 'overview' && <Overview go={go} />}
          {route.page === 'incidents' && <Incidents go={go} />}
          {route.page === 'incident' && <IncidentDetail id={route.id} go={go} analyst={analyst} />}
          {route.page === 'queue' && <Queue go={go} analyst={analyst} />}
          {route.page === 'audit' && <Audit />}
        </main>
      </div>
    </div>
  )
}
