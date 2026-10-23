import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, NavLink, useNavigate, useLocation } from 'react-router-dom'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Upload from './pages/Upload'
import Alerts from './pages/Alerts'
import Incidents from './pages/Incidents'
import IncidentDetail from './pages/IncidentDetail'
import GraphPage from './pages/GraphPage'
import Settings from './pages/Settings'
import api from './services/api'

const TITLES = { '/': 'Dashboard', '/upload': 'Upload Logs', '/alerts': 'Alerts', '/incidents': 'Incidents', '/graph': 'Graph', '/settings': 'Settings' }

function Layout({ children }) {
  const nav = useNavigate()
  const loc = useLocation()
  const [dark, setDark] = useState(localStorage.getItem('dark') === '1')
  const [auto, setAuto] = useState(false)
  const [counts, setCounts] = useState({ alerts: 0, open: 0, malicious: 0 })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('dark', dark ? '1' : '0')
  }, [dark])

  // response mode + small counters shown in the sidebar
  useEffect(() => {
    const load = () => {
      api.settings().then((s) => setAuto(s.auto_response_enabled)).catch(() => {})
      api.stats().then((s) => setCounts({ alerts: s.total_alerts, open: s.open_incidents, malicious: s.malicious_incidents })).catch(() => {})
    }
    load()
    const t = setInterval(load, 6000)
    return () => clearInterval(t)
  }, [])

  const logout = () => { localStorage.removeItem('token'); nav('/login') }
  const item = (to, label, count, hot) => (
    <NavLink to={to} end={to === '/'} className={({ isActive }) => 'navitem' + (isActive ? ' active' : '')}>
      <span>{label}</span>
      {count > 0 && <span className={'count' + (hot ? ' hot' : '')}>{count}</span>}
    </NavLink>
  )
  const page = loc.pathname.startsWith('/incidents/') ? 'Incidents / Detail' : TITLES[loc.pathname] || ''

  return (
    <div className="app">
      <aside className="side">
        <div className="brand">
          <span className="mark">CTI</span>
          <div className="name">AI Cyber Threat Intelligence &amp; Automated Response Platform</div>
        </div>
        <div className="navgroup">Monitor</div>
        {item('/', 'Dashboard')}
        {item('/alerts', 'Alerts', counts.alerts)}
        {item('/incidents', 'Incidents', counts.open, counts.malicious > 0)}
        {item('/graph', 'Graph')}
        <div className="navgroup">Data</div>
        {item('/upload', 'Upload Logs')}
        <div className="navgroup">System</div>
        {item('/settings', 'Settings')}
        <div className="sidefoot">
          <NavLink to="/settings" className={'modebox' + (auto ? ' auto' : '')}>
            Response mode<br /><b>{auto ? 'AUTOMATIC' : 'Manual'}</b>
          </NavLink>
          <button onClick={() => setDark(!dark)}>{dark ? 'Light mode' : 'Dark mode'}</button>
          <button onClick={logout}>Logout</button>
        </div>
      </aside>
      <div className="main">
        <div className="topstrip"><span>Home / {page}</span><span>Signed in as admin</span></div>
        <div className="content">{children}</div>
      </div>
    </div>
  )
}

function Private({ children }) {
  if (!localStorage.getItem('token')) return <Navigate to="/login" replace />
  return <Layout>{children}</Layout>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Private><Dashboard /></Private>} />
        <Route path="/upload" element={<Private><Upload /></Private>} />
        <Route path="/alerts" element={<Private><Alerts /></Private>} />
        <Route path="/incidents" element={<Private><Incidents /></Private>} />
        <Route path="/incidents/:id" element={<Private><IncidentDetail /></Private>} />
        <Route path="/graph" element={<Private><GraphPage /></Private>} />
        <Route path="/settings" element={<Private><Settings /></Private>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
