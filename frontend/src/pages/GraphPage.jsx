import React, { useEffect, useState } from 'react'
import api from '../services/api'
import GraphView from '../components/GraphView'

export default function GraphPage() {
  const [g, setG] = useState(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  useEffect(() => { api.globalGraph().then(setG) }, [])
  const blockComponent = async (c) => {
    if (!window.confirm('Block these IPs (same actor)?\n' + c.ips.join('\n'))) return
    await api.respond(c.incident_ids[0], 'BLOCK_IP', 'blocked from graph: one actor across several IPs', { ips: c.ips })
    setMsg('Blocked: ' + c.ips.join(', '))
    run()
  }
  const run = async () => { setBusy(true); try { setG(await api.runGraph()) } finally { setBusy(false) } }

  return (
    <div>
      <h1>IP relationship graph (batch)</h1>
      <p className="muted mb-3">
        This graph shows how IPs, users, user agents and honeytokens are connected. Two items are joined when they appeared in the same alert. It updates automatically every few minutes, or click the button to update it now.
      </p>
      <div className="box">
        <button className="btn btn-main" onClick={run} disabled={busy}>{busy ? 'Running...' : 'Run NetworkX correlation now'}</button>
        {msg && <span className="ok ml-3">{msg}</span>}
        {g && g.merged !== undefined && <span className="ml-3">Incidents merged in the last run: <b>{g.merged}</b></span>}
      </div>

      {g && g.components && g.components.length > 0 ? (
        <>
          <div className="box">
            <h2>Connected components</h2>
            <table className="t">
              <thead><tr><th>#</th><th>IPs</th><th>Users</th><th>IP rotation?</th><th>Multi-hop path</th><th>Merged</th><th>Action</th></tr></thead>
              <tbody>
                {g.components.map((c) => (
                  <tr key={c.component}>
                    <td>{c.component}</td><td>{c.ips.join(', ') || '-'}</td><td>{c.users.join(', ') || '-'}</td>
                    <td>{c.ip_rotation ? 'yes' : 'no'}</td><td>{c.multi_hop_path || '-'}</td><td>{c.merged ? 'yes' : 'no'}</td>
                    <td>{c.ips.length > 0 && c.incident_ids.length > 0
                      ? <button className="btn btn-danger" onClick={() => blockComponent(c)}>Block {c.ips.length > 1 ? 'all ' + c.ips.length + ' IPs' : 'IP'}</button>
                      : <span className="muted">-</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="box"><GraphView nodes={g.nodes} edges={g.edges} height={460} /></div>
        </>
      ) : <p className="muted">No graph yet. Upload logs and press the button.</p>}
    </div>
  )
}
