import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { fmt } from '../components/Tier'

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [detector, setDetector] = useState('')
  const [severity, setSeverity] = useState('')
  const [open, setOpen] = useState(null)

  useEffect(() => {
    const p = { limit: 200 }
    if (detector) p.detector = detector
    if (severity) p.severity = severity
    api.alerts(p).then(setAlerts)
  }, [detector, severity])

  return (
    <div>
      <h1>Alerts</h1>
      <div className="box">
        Module:{' '}
        <select value={detector} onChange={(e) => setDetector(e.target.value)}>
          <option value="">all</option>
          {['login', 'phishing', 'port_scan', 'web_attack', 'honeytoken'].map((d) => <option key={d}>{d}</option>)}
        </select>
        <span className="ml-4">Severity:{' '}</span>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">all</option>
          {['low', 'medium', 'high', 'critical'].map((d) => <option key={d}>{d}</option>)}
        </select>
        <span className="muted ml-4">{alerts.length} alerts</span>
      </div>
      <table className="t">
        <thead><tr><th>Time</th><th>Module</th><th>Severity</th><th>Conf.</th><th>IP</th><th>User</th><th>Title</th><th>Incident</th></tr></thead>
        <tbody>
          {alerts.map((a) => (
            <React.Fragment key={a.alert_id}>
              <tr onClick={() => setOpen(open === a.alert_id ? null : a.alert_id)} style={{ cursor: 'pointer' }}>
                <td>{fmt(a.timestamp)}</td><td>{a.detector}</td><td>{a.severity}</td><td>{a.confidence}</td>
                <td>{a.source_ip || '-'}</td><td>{a.user_id || '-'}</td><td>{a.title}</td>
                <td>{a.incident_id ? <Link to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()}>open</Link> : '-'}</td>
              </tr>
              {open === a.alert_id && (
                <tr><td colSpan="8">
                  <b>Recommended action:</b> {a.recommended_action}
                  <pre>{JSON.stringify(a.evidence, null, 2)}</pre>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
