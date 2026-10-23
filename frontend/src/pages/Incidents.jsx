import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { Tier, Mode, fmt } from '../components/Tier'

export default function Incidents() {
  const [list, setList] = useState([])
  const [status, setStatus] = useState('')
  const [tier, setTier] = useState('')

  const load = () => {
    const p = { limit: 100 }
    if (status) p.status = status
    if (tier) p.risk_tier = tier
    api.incidents(p).then(setList)
  }
  useEffect(load, [status, tier])

  const blockIps = async (i) => {
    if (!window.confirm('Block these IPs?\n' + i.related_entities.ips.join('\n'))) return
    await api.respond(i.incident_id, 'BLOCK_IP', 'blocked from incident list')
    load()
  }

  return (
    <div>
      <h1>Incidents</h1>
      <p className="muted mb-3">Related alerts are grouped into one incident when they share an IP or user within 30 minutes. Incidents from the same attacker using different IPs are merged by the Graph page.</p>
      <div className="box">
        Status:{' '}
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">all</option>
          {['open', 'escalated', 'contained', 'false_positive'].map((x) => <option key={x}>{x}</option>)}
        </select>
        <span className="ml-4">Tier:{' '}</span>
        <select value={tier} onChange={(e) => setTier(e.target.value)}>
          <option value="">all</option>
          {['Safe', 'Suspicious', 'Malicious'].map((x) => <option key={x}>{x}</option>)}
        </select>
      </div>
      <table className="t">
        <thead><tr><th>ID</th><th>Title</th><th>Tier</th><th>Score</th><th>Status</th><th>Response</th><th>Alerts</th><th>Correlated by</th><th>Last seen</th><th>Action</th></tr></thead>
        <tbody>
          {list.map((i) => (
            <tr key={i.incident_id} className={`row-${i.risk_tier}`}>
              <td><Link to={`/incidents/${i.incident_id}`}>{i.incident_id}</Link></td>
              <td>{i.title.slice(0, 70)}</td>
              <td><Tier tier={i.risk_tier} /></td>
              <td>{i.risk_score}{i.base_risk_score > i.risk_score ? <span className="muted"> (was {i.base_risk_score})</span> : null}</td>
              <td>{i.status}</td><td><Mode mode={i.response_mode} /></td><td>{i.alert_ids.length}</td>
              <td>{i.correlation_method === 'networkx_batch' ? 'NetworkX' : 'time window'}</td>
              <td>{fmt(i.last_seen)}</td>
              <td>{(i.related_entities.ips || []).length > 0 && ['open', 'escalated'].includes(i.status)
                ? <button className="btn btn-danger" onClick={() => blockIps(i)}>Block IP</button> : <span className="muted">-</span>}</td>
            </tr>
          ))}
          {!list.length && <tr><td colSpan="10" className="muted">no incidents</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
