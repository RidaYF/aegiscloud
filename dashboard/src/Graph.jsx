import { useMemo, useState } from 'react'
import { api, useData } from './api.js'
import { Empty, Loading, Panel } from './ui.jsx'

// Attack path drawn as columns, left to right:
// source -> identity -> API calls -> service / target -> technique -> tactic
const COLUMNS = ['Source', 'Identity', 'API calls', 'Service / target', 'MITRE technique', 'Tactic']
const TYPE_COLOR = {
  SourceIP: '#6092C0',
  Identity: '#54B399',
  APICall: '#D6BF57',
  Service: '#9170B8',
  Resource: '#CA8EAE',
  Technique: '#D36086',
  Tactic: '#AA6556',
}
const TYPE_NAME = {
  SourceIP: 'Source IP',
  Identity: 'Identity',
  APICall: 'API call',
  Service: 'Service',
  Resource: 'Resource',
  Technique: 'Technique',
  Tactic: 'Tactic',
}

const NODE_W = 164
const NODE_H = 46
const COL_W = 196
const ROW = 62
const TOP = 48
const LEFT = 16

function trunc(text, n) {
  const s = String(text ?? '')
  return s.length > n ? s.slice(0, n - 1) + '...' : s
}

function columnOf(node, performed, targeted) {
  switch (node.type) {
    case 'SourceIP': return 0
    case 'Identity': return targeted.has(node.id) && !performed.has(node.id) ? 3 : 1
    case 'APICall': return 2
    case 'Tactic': return 5
    case 'Technique': return 4
    default: return 3 // Service, Resource
  }
}

function layout(graph, actions) {
  const nodes = graph.nodes
    .filter((n) => n.type !== 'Incident' && n.type !== 'ProposedAction')
    .map((n) => ({ ...n }))
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const edges = graph.edges.filter((e) => byId.has(e.source) && byId.has(e.target))

  const performed = new Set(edges.filter((e) => e.type === 'PERFORMED').map((e) => e.source))
  const targeted = new Set(edges.filter((e) => e.type === 'TARGETED').map((e) => e.target))
  nodes.forEach((n) => { n.col = columnOf(n, performed, targeted) })

  // Proposed response actions are shown as a small note on the node they target.
  nodes.forEach((n) => {
    const hit = (actions || []).filter((a) => a.target && a.target === n.label && a.status === 'proposed')
    n.proposed = hit.map((a) => a.action)
  })

  const neighbours = (id) =>
    edges.filter((e) => e.source === id || e.target === id).map((e) => (e.source === id ? e.target : e.source))

  // API calls are placed first, in the order they happened.
  const calls = nodes.filter((n) => n.col === 2).sort((a, b) => (a.props.order || 0) - (b.props.order || 0))
  calls.forEach((n, i) => { n.y = i * ROW })
  const placed = new Set(calls.map((n) => n.id))

  // Every other column sits next to the nodes it is connected to.
  for (const col of [1, 3, 4, 5, 0]) {
    const members = nodes.filter((n) => n.col === col)
    members.forEach((n) => {
      const ys = neighbours(n.id).filter((id) => placed.has(id)).map((id) => byId.get(id).y)
      n.want = ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Infinity
    })
    members.sort((a, b) => a.want - b.want || String(a.label).localeCompare(String(b.label)))
    let floor = -ROW
    members.forEach((n) => {
      n.y = Math.max(Number.isFinite(n.want) ? n.want : floor + ROW, floor + ROW)
      floor = n.y
      placed.add(n.id)
    })
  }

  nodes.forEach((n) => {
    n.px = LEFT + n.col * COL_W
    n.py = TOP + n.y
  })
  const used = [...new Set(nodes.map((n) => n.col))]
  const height = Math.max(...nodes.map((n) => n.py + NODE_H), TOP + NODE_H) + 24
  return { nodes, edges, byId, height, width: LEFT * 2 + COLUMNS.length * COL_W - (COL_W - NODE_W), used }
}

function edgePath(a, b) {
  if (a.col === b.col) {
    const upper = a.py <= b.py ? a : b
    const lower = a.py <= b.py ? b : a
    const gap = lower.py - (upper.py + NODE_H)
    if (gap <= ROW - NODE_H + 1) {
      const x = upper.px + NODE_W / 2
      const d = a === upper ? `M ${x} ${upper.py + NODE_H} L ${x} ${lower.py}` : `M ${x} ${lower.py} L ${x} ${upper.py + NODE_H}`
      return { d, mx: x + 6, my: (upper.py + NODE_H + lower.py) / 2 }
    }
    const x1 = a.px + NODE_W
    const y1 = a.py + NODE_H / 2
    const y2 = b.py + NODE_H / 2
    return { d: `M ${x1} ${y1} C ${x1 + 46} ${y1}, ${x1 + 46} ${y2}, ${x1} ${y2}`, mx: x1 + 36, my: (y1 + y2) / 2 }
  }
  const forward = a.col < b.col
  const x1 = forward ? a.px + NODE_W : a.px
  const x2 = forward ? b.px : b.px + NODE_W
  const y1 = a.py + NODE_H / 2
  const y2 = b.py + NODE_H / 2
  const k = (x2 - x1) / 2
  return { d: `M ${x1} ${y1} C ${x1 + k} ${y1}, ${x2 - k} ${y2}, ${x2} ${y2}`, mx: (x1 + x2) / 2, my: (y1 + y2) / 2 }
}

function subline(n) {
  if (n.proposed && n.proposed.length) return 'Proposed: ' + n.proposed.join(', ')
  if (n.type === 'APICall') return n.props.result || 'API call'
  if (n.type === 'Technique') return n.props.name || 'Technique'
  if (n.type === 'Resource') return n.props.kind || 'Resource'
  return TYPE_NAME[n.type] || n.type
}

function Details({ node }) {
  if (!node) {
    return <Empty>Select a node to see its details.</Empty>
  }
  const rows = Object.entries(node.props).filter(([, v]) => v !== null && v !== undefined && v !== '')
  return (
    <div>
      <div className="detail-type" style={{ borderColor: TYPE_COLOR[node.type] }}>{TYPE_NAME[node.type] || node.type}</div>
      <div className="detail-label">{node.label}</div>
      {node.proposed && node.proposed.length > 0 && (
        <div className="detail-proposed">Proposed response: {node.proposed.join(', ')}</div>
      )}
      <dl className="kv">
        {rows.map(([k, v]) => (
          <div key={k} className="kv-row">
            <dt>{k}</dt>
            <dd>{String(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

export default function Graph({ incidentId, actions }) {
  const { data, error, loading } = useData(() => api.graph(incidentId), [incidentId], 20000)
  const [hover, setHover] = useState(null)
  const [selected, setSelected] = useState(null)
  const lay = useMemo(() => (data && data.nodes.length ? layout(data, actions) : null), [data, actions])

  if (!data) return <Loading error={error} />
  if (!lay) {
    return (
      <Panel title="Attack graph">
        <Empty>
          {loading ? 'Loading...' : 'No graph data for this incident yet. Run graph.py in the incident-engine folder.'}
        </Empty>
      </Panel>
    )
  }

  const focus = hover || (selected && selected.id)
  const linked = new Set()
  if (focus) {
    linked.add(focus)
    lay.edges.forEach((e) => {
      if (e.source === focus || e.target === focus) {
        linked.add(e.source)
        linked.add(e.target)
      }
    })
  }
  const selectedNode = selected ? lay.byId.get(selected.id) : null

  return (
    <div className="graph-layout">
      <Panel title="Attack path" flush className="graph-panel">
        <div className="graph-scroll">
          <svg width={lay.width} height={lay.height} role="img" aria-label="Attack path graph">
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#98A2B3" />
              </marker>
              <marker id="arrow-on" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#006BB4" />
              </marker>
            </defs>

            {COLUMNS.map((title, i) => (
              <g key={title}>
                <text x={LEFT + i * COL_W} y={22} className="col-title">{title}</text>
                <line x1={LEFT + i * COL_W} x2={LEFT + i * COL_W + NODE_W} y1={30} y2={30} className="col-rule" />
              </g>
            ))}

            {lay.edges.map((e, i) => {
              const a = lay.byId.get(e.source)
              const b = lay.byId.get(e.target)
              const p = edgePath(a, b)
              const on = focus && (e.source === focus || e.target === focus)
              const dim = focus && !on
              return (
                <g key={i} opacity={dim ? 0.12 : 1}>
                  <path d={p.d} className={on ? 'edge on' : 'edge'} markerEnd={on ? 'url(#arrow-on)' : 'url(#arrow)'} />
                  {on && <text x={p.mx} y={p.my - 4} className="edge-label" textAnchor="middle">{e.type.toLowerCase().replace('_', ' ')}</text>}
                </g>
              )
            })}

            {lay.nodes.map((n) => {
              const dim = focus && !linked.has(n.id)
              const isSel = selected && selected.id === n.id
              return (
                <g
                  key={n.id}
                  transform={`translate(${n.px}, ${n.py})`}
                  opacity={dim ? 0.25 : 1}
                  className="node"
                  onMouseEnter={() => setHover(n.id)}
                  onMouseLeave={() => setHover(null)}
                  onClick={() => setSelected({ id: n.id })}
                >
                  <rect width={NODE_W} height={NODE_H} rx={4} className={isSel ? 'node-box sel' : 'node-box'} />
                  <rect width={5} height={NODE_H} rx={2} fill={TYPE_COLOR[n.type] || '#98A2B3'} />
                  <text x={16} y={19} className="node-label">{trunc(n.label, 20)}</text>
                  <text x={16} y={35} className={n.proposed && n.proposed.length ? 'node-sub proposed' : 'node-sub'}>
                    {trunc(subline(n), 24)}
                  </text>
                </g>
              )
            })}
          </svg>
        </div>
        <div className="legend">
          {Object.keys(TYPE_COLOR).map((t) => (
            <span key={t} className="legend-item">
              <i style={{ background: TYPE_COLOR[t] }} />
              {TYPE_NAME[t]}
            </span>
          ))}
        </div>
      </Panel>
      <Panel title="Details">
        <Details node={selectedNode} />
      </Panel>
    </div>
  )
}
