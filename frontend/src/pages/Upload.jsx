import React, { useEffect, useState } from 'react'
import api, { errorText } from '../services/api'
import { fmt } from '../components/Tier'

const SOURCES = [
  { kind: 'auth-log', label: 'Authentication log', hint: 'Linux auth.log (OpenSSH "Failed password" / "Accepted password" lines). Used by the login threat module.' },
  { kind: 'web-log', label: 'Web server log', hint: 'Apache or Nginx access.log in combined format. Used by the web attack and honeytoken modules.' },
  { kind: 'network-log', label: 'Network log (CSV)', hint: 'Columns: timestamp, src_ip, dst_ip, dst_port, protocol. Used by the port scan module.' },
  { kind: 'url-list', label: 'URL list', hint: 'Plain text, one URL per line. Used by the phishing URL module.' },
]

export default function Upload() {
  const [files, setFiles] = useState({})
  const [msgs, setMsgs] = useState({})
  const [history, setHistory] = useState([])
  const [busy, setBusy] = useState(false)
  const [url, setUrl] = useState('')
  const [urlRes, setUrlRes] = useState(null)
  const [tokens, setTokens] = useState([])
  const [tokenId, setTokenId] = useState('')
  const [hitIp, setHitIp] = useState('')
  const [hitMsg, setHitMsg] = useState('')

  const loadHistory = () => api.uploads().then(setHistory).catch(() => {})
  useEffect(() => { loadHistory(); api.honeytokens().then((t) => { setTokens(t); if (t.length) setTokenId(String(t[0].id)) }).catch(() => {}) }, [])

  const show = (kind, text, bad) => setMsgs((m) => ({ ...m, [kind]: { text, bad } }))

  const doUpload = async (kind) => {
    if (!files[kind]) return show(kind, 'Choose a file first.', true)
    setBusy(true)
    try {
      const r = await api.upload(kind, files[kind])
      show(kind, `${r.filename}: ${r.lines_parsed} of ${r.lines_total} lines parsed, ${r.events_created} events stored, ${r.alerts_created} alerts raised.`)
    } catch (e) { show(kind, errorText(e), true) }
    setBusy(false)
    loadHistory()
  }

  const checkUrl = async () => {
    if (!url.trim()) return
    try { setUrlRes(await api.checkUrl(url.trim())) } catch (e) { setUrlRes({ error: errorText(e) }) }
  }

  const touch = async () => {
    try {
      const r = await api.honeytoken({ token_id: Number(tokenId), source_ip: hitIp.trim() || null })
      setHitMsg(`Honeytoken access recorded, ${r.alerts} alert raised.`)
    } catch (e) { setHitMsg(errorText(e)) }
  }

  return (
    <div>
      <h1>Upload Logs</h1>

      <div className="grid md:grid-cols-2 gap-4">
        {SOURCES.map((s) => (
          <div className="box" key={s.kind}>
            <h2>{s.label}</h2>
            <p className="muted mb-3">{s.hint}</p>
            <input type="file" onChange={(e) => setFiles({ ...files, [s.kind]: e.target.files[0] })} />
            <button className="btn btn-main ml-2" disabled={busy} onClick={() => doUpload(s.kind)}>Upload</button>
            {msgs[s.kind] && <div className={(msgs[s.kind].bad ? 'err' : 'ok') + ' mt-2 text-sm'}>{msgs[s.kind].text}</div>}
          </div>
        ))}
      </div>

      <div className="box">
        <h2>Check a single URL</h2>
        <input type="text" style={{ width: '55%' }} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Paste a URL to test" />
        <button className="btn ml-2" onClick={checkUrl}>Check</button>
        {urlRes && (urlRes.error ? <p className="err mt-2">{urlRes.error}</p> :
          <p className="mt-2">{urlRes.is_phishing ? <b className="err">Phishing</b> : <b className="ok">No phishing indicators</b>} (model confidence {urlRes.confidence})</p>)}
      </div>

      <div className="box">
        <h2>Honeytoken access</h2>
        <p className="muted mb-3">Honeytokens are fake keys, passwords or pages that no real user should ever touch. Choose one, enter the IP address that used it, and click Record access. The system raises a high-risk alert because only an attacker would use a fake item.</p>
        <select value={tokenId} onChange={(e) => setTokenId(e.target.value)}>
          {tokens.map((t) => <option key={t.id} value={t.id}>{t.type}: {t.decoy}</option>)}
        </select>
        <input type="text" className="ml-2" placeholder="Source IP" value={hitIp} onChange={(e) => setHitIp(e.target.value)} />
        <button className="btn ml-2" disabled={!tokenId} onClick={touch}>Record access</button>
        {hitMsg && <p className="mt-2">{hitMsg}</p>}
      </div>

      <div className="box">
        <h2>Upload history</h2>
        <table className="t">
          <thead><tr><th>Time</th><th>File</th><th>Type</th><th>Lines parsed</th><th>Events</th><th>Alerts</th></tr></thead>
          <tbody>
            {history.map((h) => (
              <tr key={h.id}><td>{fmt(h.uploaded_at)}</td><td>{h.filename}</td><td>{h.source_type}</td>
                <td>{h.lines_parsed} / {h.lines_total}</td><td>{h.events_created}</td><td>{h.alerts_created}</td></tr>
            ))}
            {!history.length && <tr><td colSpan="6" className="muted">No files uploaded yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
