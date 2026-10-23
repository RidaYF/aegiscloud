import { useCallback, useEffect, useState } from 'react'

const BASE = '/dash'

async function request(path, options) {
  const res = await fetch(BASE + path, options)
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch {
      /* the body was not JSON */
    }
    throw new Error(detail)
  }
  return res.json()
}

const post = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const api = {
  summary: () => request('/summary'),
  incidents: () => request('/incidents'),
  incident: (id) => request(`/incidents/${encodeURIComponent(id)}`),
  graph: (id) => request(`/graph/${encodeURIComponent(id)}`),
  actions: (incidentId) =>
    request('/actions' + (incidentId ? `?incident_id=${encodeURIComponent(incidentId)}` : '')),
  audit: () => request('/audit'),
  approve: (actionId, by) =>
    request(`/actions/${encodeURIComponent(actionId)}/approve`, post({ by })),
  reject: (actionId, by, reason) =>
    request(`/actions/${encodeURIComponent(actionId)}/reject`, post({ by, reason })),
}

/**
 * Load data from the API, and reload it every `intervalMs` milliseconds.
 * Returns { data, error, loading, reload }.
 */
export function useData(loader, deps = [], intervalMs = 0) {
  const [state, setState] = useState({ data: null, error: null, loading: true })
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let alive = true
    const load = () =>
      loader()
        .then((data) => alive && setState({ data, error: null, loading: false }))
        .catch((err) => alive && setState((s) => ({ ...s, error: err.message, loading: false })))
    load()
    const timer = intervalMs ? setInterval(load, intervalMs) : null
    return () => {
      alive = false
      if (timer) clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { ...state, reload }
}
