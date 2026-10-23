import React, { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import api, { errorText } from '../services/api'
import { Tier, Mode, fmt, dec } from '../components/Tier'
import GraphView from '../components/GraphView'

export default function IncidentDetail() {
  const { id } = useParams()
  const [inc, setInc] = useState(null)
  const [graph, setGraph] = useState(null)
  const [msg, setMsg] = useState('')
  const [notes, setNotes] = useState('')

  const load = () => {
    api.incident(id).then(setInc).catch((e) => setMsg(errorText(e)))
    api.incidentGraph(id).then(setGraph).catch(() => {})
  }
  useEffect(load, [id])

  if (!inc) return <p>{msg || 'Loading...'}</p>

  const act = async (type) => {
    try { await api.respond(id, type); setMsg(type === 'BLOCK_IP' ? 'IP(s) added to the blocklist, incident is now contained.' : type === 'BLOCK_URL' ? 'URL(s) added to the blocklist, incident is now contained.' : 'Done: ' + type); load() } catch (e) { setMsg(errorText(e)) }
  }
  const feedback = async (verdict) => {
    try { await api.feedback(id, verdict, notes); setMsg('Feedback saved'); load() } catch (e) { setMsg(errorText(e)) }
  }

  const hasUrls = (inc.related_entities.urls || []).length > 0
  const hasIps = (inc.related_entities.ips || []).length > 0
  const decayed = inc.base_risk_score > inc.risk_score
  const done = ['contained', 'false_positive', 'closed'].includes(inc.status)

  return (
    <div>
      <p className="mb-2"><Link to="/incidents">&laquo; all incidents</Link></p>
      <h1>{inc.title}</h1>
      <p className="muted mb-3">{inc.incident_id} | first seen {fmt(inc.first_seen)} | last seen {fmt(inc.last_seen)}</p>

      <div className="grid md:grid-cols-3 gap-4">
        <div className="box">
          <div className="muted">Risk score</div>
          <div className="text-3xl font-bold">{inc.risk_score}<span className="text-base font-normal"> / 100</span></div>
          <Tier tier={inc.risk_tier} />
          {decayed && (
            <p className="mt-2 text-sm">Score went down from {inc.base_risk_score} because no new evidence arrived (last evidence {fmt(inc.last_evidence_at)}).</p>
          )}
        </div>
        <div className="box">
          <div className="muted">Status</div>
          <div className="text-lg font-bold">{inc.status}</div>
          <div className="mt-1">Handled: <Mode mode={inc.response_mode} /></div>
          <div className="mt-1 text-sm">Correlated by: {inc.correlation_method === 'networkx_batch' ? 'NetworkX batch job' : 'time window (IP / user)'}</div>
        </div>
        <div className="box">
          <div className="muted mb-1">Entities</div>
          {Object.entries(inc.related_entities).filter(([, v]) => v.length).map(([k, v]) => (
            <div key={k} className="text-sm"><b>{k}:</b> {dec(v.join(', '))}</div>
          ))}
        </div>
      </div>

      <div className="box">
        <h2>What happened</h2>
        <p style={{ lineHeight: 1.5 }}>{inc.incident_narrative}</p>
      </div>

      <div className="box">
        <h2>Response</h2>
        {done && <p className="mb-2">This incident is already {inc.status}. {inc.response_mode === 'auto' && 'It was handled automatically.'}</p>}
        <button className="btn btn-danger mr-2" disabled={!hasIps} title={hasIps ? '' : 'No IP address in this incident'} onClick={() => act('BLOCK_IP')}>Block IP</button>
        <button className="btn btn-danger mr-2" disabled={!hasUrls} title={hasUrls ? '' : 'No URL in this incident'} onClick={() => act('BLOCK_URL')}>Block URL</button>
        <button className="btn btn-warn mr-2" onClick={() => act('ESCALATE')}>Escalate</button>
        <button className="btn btn-grey mr-2" onClick={() => act('MARK_FALSE_POSITIVE')}>Mark false positive</button>
        <button className="btn" disabled={inc.status === 'closed'} onClick={() => act('CLOSE_INCIDENT')}>Close incident</button>
        {!hasIps && hasUrls && <div className="hint mt-2">This incident only has a URL (no IP address), so the block option is Block URL.</div>}
        {hasIps && !hasUrls && <div className="muted mt-2">Block IP will add: {inc.related_entities.ips.join(', ')}</div>}
        {msg && <div className="ok mt-2 font-bold">{msg}</div>}
        {inc.response_actions.some((a) => a.action_type.startsWith('BLOCK')) && (
          <div className="mt-2">Blocked so far: {inc.response_actions.filter((a) => a.action_type.startsWith('BLOCK'))
            .map((a) => (a.parameters.blocked_ips || a.parameters.blocked_urls || []).join(', ')).join(', ')}
            {' '}(see <Link to="/settings">Settings &raquo; Blocklist</Link>)</div>
        )}
        {inc.response_actions.length > 0 && (
          <table className="t mt-3">
            <thead><tr><th>Time</th><th>Action</th><th>Mode</th><th>By</th><th>Outcome</th></tr></thead>
            <tbody>
              {inc.response_actions.map((a) => (
                <tr key={a.action_id}><td>{fmt(a.timestamp)}</td><td>{a.action_type}</td><td><Mode mode={a.mode} /></td><td>{a.performed_by}</td><td>{a.outcome}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="box">
          <h2>Why was this flagged?</h2>
          <ul className="list-disc ml-5 text-sm">{inc.explanation.map((e, i) => <li key={i}>{dec(e)}</li>)}</ul>
        </div>
        <div className="box">
          <h2>Score breakdown</h2>
          <table className="t">
            <thead><tr><th>Step</th><th>Reason</th><th>Points</th></tr></thead>
            <tbody>{inc.risk_score_explanation.map((r, i) => <tr key={i}><td>{r.category}</td><td>{r.reason}</td><td>{r.points}</td></tr>)}</tbody>
          </table>
          {inc.decay_history.length > 0 && (
            <>
              <h3 className="mt-3">Decay history</h3>
              <table className="t">
                <thead><tr><th>When</th><th>From</th><th>To</th><th>Idle (h)</th><th>Note</th></tr></thead>
                <tbody>{inc.decay_history.map((d, i) => <tr key={i}><td>{fmt(d.at)}</td><td>{d.from}</td><td>{d.to}</td><td>{d.idle_hours}</td><td>{d.note}</td></tr>)}</tbody>
              </table>
            </>
          )}
        </div>
      </div>

      <div className="box">
        <h2>Timeline</h2>
        <table className="t">
          <thead><tr><th>Time</th><th>Module</th><th>Severity</th><th>Event</th><th>Linked because</th></tr></thead>
          <tbody>
            {inc.timeline.map((t, i) => (
              <tr key={i}><td>{fmt(t.timestamp)}</td><td>{t.detector}</td><td>{t.severity}</td><td>{t.title}</td><td>{t.reason}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="box">
        <h2>Graph of this incident <span className="muted">(live, built from its alerts)</span></h2>
        {graph && <GraphView nodes={graph.nodes} edges={graph.edges} />}
        {graph && graph.key_hubs.length > 0 && <p className="muted mt-1">Most connected: {graph.key_hubs.join(', ')}</p>}
      </div>

      <div className="box">
        <h2>Analyst feedback</h2>
        {inc.analyst_feedback && <p className="mb-2">Saved verdict: <b>{inc.analyst_feedback.verdict}</b> {inc.analyst_feedback.notes && `(${inc.analyst_feedback.notes})`}</p>}
        <input type="text" className="w-1/2" placeholder="note (optional)" value={notes} onChange={(e) => setNotes(e.target.value)} />
        <button className="btn ml-2" onClick={() => feedback('true_positive')}>True positive</button>
        <button className="btn ml-2" onClick={() => feedback('false_positive')}>False positive</button>
        <button className="btn ml-2" onClick={() => feedback('benign')}>Benign</button>
      </div>
    </div>
  )
}
