import React, { useEffect, useState } from 'react'
import api from '../services/api'
import { fmt } from '../components/Tier'

export default function Settings() {
  const [auto, setAuto] = useState(false)
  const [block, setBlock] = useState([])
  const [hours, setHours] = useState(24)
  const [msg, setMsg] = useState('')
  const [tokens, setTokens] = useState([])

  const load = () => {
    api.settings().then((s) => setAuto(s.auto_response_enabled))
    api.blocklist().then(setBlock)
    api.honeytokens().then(setTokens)
  }
  useEffect(load, [])

  const toggle = async () => { const r = await api.setAutoResponse(!auto); setAuto(r.auto_response_enabled) }
  const decay = async () => { const r = await api.runDecay(hours); setMsg(`${r.incidents_changed} incident(s) changed`) }

  return (
    <div>
      <h1>Settings</h1>

      <div className="box">
        <h2>Response mode</h2>
        <p className="mb-2">
          Currently: <b>{auto ? 'AUTOMATIC' : 'manual'}</b>.{' '}
          {auto
            ? 'When an incident reaches Malicious (71+) the system blocks the IP / URL by itself.'
            : 'Malicious incidents wait until the admin clicks a button on the incident page.'}
        </p>
        <button className={'btn ' + (auto ? '' : 'btn-danger')} onClick={toggle}>{auto ? 'Switch to manual' : 'Turn on automatic response'}</button>
      </div>

      <div className="box">
        <h2>Risk decay</h2>
        <p className="mb-2">An incident that gets no new alerts loses 10% of its score every 6 hours, but never drops below half of its original score. This runs automatically. To see the effect now, enter a number of hours and click Run decay job.</p>
        Pretend <input type="number" className="w-20 mx-1" value={hours} onChange={(e) => setHours(Number(e.target.value))} /> hours have passed
        <button className="btn ml-2" onClick={decay}>Run decay job</button>
        {msg && <span className="ml-3">{msg}</span>}
      </div>

      <div className="box">
        <h2>Data</h2>
        <p className="mb-2">Remove all uploaded events, alerts, incidents, feedback and the blocklist. Users and honeytoken settings stay.</p>
        <button className="btn btn-danger" onClick={async () => { if (window.confirm('Delete all events, alerts, incidents and the blocklist?')) { await api.reset(); load(); setMsg('All data cleared') } }}>Clear all data</button>
      </div>

      <div className="box">
        <h2>Blocklist</h2>
        <table className="t">
          <thead><tr><th>Type</th><th>Value</th><th>Incident</th><th>Mode</th><th>Added</th><th></th></tr></thead>
          <tbody>
            {block.map((b) => (
              <tr key={b.id}><td>{b.kind}</td><td>{b.value}</td><td>{b.incident_id}</td><td>{b.mode}</td><td>{fmt(b.created_at)}</td>
                <td><button className="btn" onClick={() => api.unblock(b.id).then(load)}>remove</button></td></tr>
            ))}
            {!block.length && <tr><td colSpan="6" className="muted">empty</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="box">
        <h2>Planted honeytokens</h2>
        <table className="t">
          <thead><tr><th>Type</th><th>Decoy (masked)</th><th>Path</th><th>Last triggered</th></tr></thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}><td>{t.type}</td><td>{t.decoy}</td><td>{t.resource_path || '-'}</td><td>{t.last_triggered_at ? fmt(t.last_triggered_at) : 'never'}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
