import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api, { errorText } from '../services/api'

export default function Login() {
  const nav = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    try {
      const r = await api.login(username, password)
      localStorage.setItem('token', r.access_token)
      nav('/')
    } catch (err) {
      setError(errorText(err))
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-24 box" style={{ borderTop: "4px solid var(--blue)" }}>
      <h1>Sign in</h1>
      <p className="muted mb-3">AI Cyber Threat Intelligence &amp; Automated Response Platform</p>
      <form onSubmit={submit}>
        <div className="mb-2">Username<br /><input type="text" className="w-full" value={username} onChange={(e) => setUsername(e.target.value)} /></div>
        <div className="mb-3">Password<br /><input type="password" className="w-full" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        <button className="btn btn-main" type="submit">Login</button>
        {error && <p className="err mt-2">{error}</p>}
      </form>
    </div>
  )
}
