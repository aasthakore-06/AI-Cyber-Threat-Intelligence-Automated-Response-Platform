import React, { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, Tooltip, Legend } from 'chart.js'
import { Bar, Line, Doughnut } from 'react-chartjs-2'
import api from '../services/api'
import { Tier, Mode, fmt } from '../components/Tier'

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, Tooltip, Legend)

const COLORS = ['#e65100', '#2b5797', '#d32f2f', '#2e9e4f', '#7b3fa0', '#0f9d8a']

export default function Dashboard() {
  const [s, setS] = useState(null)
  const [live, setLive] = useState([])
  const [wsOn, setWsOn] = useState(false)
  const timer = useRef(null)

  const load = () => api.stats().then(setS).catch(() => {})

  useEffect(() => { load(); timer.current = setInterval(load, 8000); return () => clearInterval(timer.current) }, [])

  // live feed over websocket: new alerts show up without refreshing
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/api/ws/alerts?token=${localStorage.getItem('token')}`)
    ws.onopen = () => setWsOn(true)
    ws.onclose = () => setWsOn(false)
    ws.onmessage = (m) => {
      const d = JSON.parse(m.data)
      if (d.type === 'alert') { setLive((l) => [d.alert, ...l].slice(0, 12)); load() }
    }
    return () => ws.close()
  }, [])

  if (!s) return <p>Loading...</p>

  const types = Object.keys(s.alerts_by_type)
  const status = s.incident_status

  return (
    <div>
      <div className="flex items-center justify-between"><h1>Dashboard</h1><button className="btn" onClick={load}>Refresh</button></div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-4">
        {[['Events processed', s.total_events, 'c-blue'], ['Alerts', s.total_alerts, 'c-teal'], ['Open incidents', s.open_incidents, 'c-amber'],
          ['Resolved incidents', s.resolved_incidents, 'c-green'], ['Malicious incidents', s.malicious_incidents, 'c-red'], ['Blocked IPs / URLs', s.blocked_entries, 'c-blue']].map(([k, v, c]) => (
          <div className={`box stat ${c}`} key={k}><div className="num">{v}</div><div className="lab">{k}</div></div>
        ))}
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <div className="box">
          <h2>Alerts by type</h2>
          {types.length ? (
            <>
              <div style={{ height: 200 }}><Doughnut data={{ labels: types, datasets: [{ data: types.map((t) => s.alerts_by_type[t].count), backgroundColor: COLORS }] }}
                options={{ maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }} /></div>
              <table className="t mt-2">
                <tbody>{types.map((t) => <tr key={t}><td>{t}</td><td>{s.alerts_by_type[t].count}</td><td>{s.alerts_by_type[t].percent}%</td></tr>)}</tbody>
              </table>
            </>
          ) : <p className="muted">no alerts</p>}
        </div>
        <div className="box">
          <h2>Incident status</h2>
          <Bar data={{ labels: Object.keys(status), datasets: [{ label: 'incidents', data: Object.values(status), backgroundColor: ['#f0a30a', '#e65100', '#2e9e4f', '#6b7a8c', '#2b5797'] }] }}
            options={{ plugins: { legend: { display: false } }, scales: { y: { ticks: { precision: 0 } } } }} />
          <p className="muted mt-2">Risk tiers: Safe {s.risk_tier_distribution.Safe} / Suspicious {s.risk_tier_distribution.Suspicious} / Malicious {s.risk_tier_distribution.Malicious}</p>
        </div>
        <div className="box">
          <h2>Risk score per incident</h2>
          <Line data={{ labels: s.risk_trend.map((_, i) => i + 1),
            datasets: [{ label: 'current score', data: s.risk_trend.map((r) => r.score), borderColor: '#c62828' },
                       { label: 'before decay', data: s.risk_trend.map((r) => r.base), borderColor: '#999', borderDash: [4, 4] }] }}
            options={{ scales: { y: { min: 0, max: 100 } } }} />
          <p className="muted mt-2">x axis = incidents in the order they started</p>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="box">
          <h2>Live alert feed {wsOn ? <span className="ok text-xs">(connected)</span> : <span className="err text-xs">(not connected)</span>}</h2>
          {live.length === 0 && <p className="muted">New alerts appear here as soon as a log is uploaded. Latest saved alerts:</p>}
          <table className="t">
            <tbody>
              {(live.length ? live : s.recent_alerts).map((a) => (
                <tr key={a.id}><td>{fmt(a.timestamp)}</td><td>{a.detector}</td><td>{a.severity}</td><td>{a.source_ip || '-'}</td><td>{a.title}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="box">
          <h2>Recent incidents</h2>
          <table className="t">
            <thead><tr><th>Title</th><th>Tier</th><th>Score</th><th>Status</th><th>Response</th></tr></thead>
            <tbody>
              {s.recent_incidents.map((i) => (
                <tr key={i.id} className={`row-${i.risk_tier}`}>
                  <td><Link to={`/incidents/${i.id}`}>{i.title.slice(0, 55)}</Link></td>
                  <td><Tier tier={i.risk_tier} /></td><td>{i.risk_score}</td><td>{i.status}</td><td><Mode mode={i.response_mode} /></td>
                </tr>
              ))}
              {!s.recent_incidents.length && <tr><td colSpan="5" className="muted">no incidents</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="box">
        <h2>Log source health</h2>
        <table className="t">
          <thead><tr><th>Source</th><th>Files</th><th>Lines parsed</th><th>Events</th><th>Last upload</th></tr></thead>
          <tbody>
            {s.log_sources.map((l) => (
              <tr key={l.source}><td>{l.source}</td><td>{l.files}</td>
                <td>{l.lines_total ? `${l.lines_parsed}/${l.lines_total}` : '-'}</td><td>{l.events}</td>
                <td>{l.last_upload ? fmt(l.last_upload) : <span className="muted">never</span>}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
