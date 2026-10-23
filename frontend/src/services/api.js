import axios from 'axios'

// every request goes to /api (proxied by vite in dev, by nginx in docker)
const http = axios.create({ baseURL: import.meta.env.VITE_API_URL || '/api', timeout: 30000 })

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// token expired / wrong -> back to login
http.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response && err.response.status === 401 && !err.config.url.includes('/auth/login')) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export const errorText = (e) => e?.response?.data?.detail
  ? (typeof e.response.data.detail === 'string' ? e.response.data.detail : JSON.stringify(e.response.data.detail))
  : e.message

export const api = {
  login: (username, password) => http.post('/auth/login', { username, password }).then((r) => r.data),
  stats: () => http.get('/stats/dashboard').then((r) => r.data),
  alerts: (params) => http.get('/alerts', { params }).then((r) => r.data),
  incidents: (params) => http.get('/incidents', { params }).then((r) => r.data),
  incident: (id) => http.get(`/incidents/${id}`).then((r) => r.data),
  incidentGraph: (id) => http.get(`/incidents/${id}/graph`).then((r) => r.data),
  respond: (id, action_type, reason = '', parameters = {}) => http.post(`/incidents/${id}/respond`, { action_type, reason, parameters }).then((r) => r.data),
  feedback: (id, verdict, notes) => http.post(`/incidents/${id}/feedback`, { verdict, notes }).then((r) => r.data),

  upload: (kind, file) => {
    const fd = new FormData()
    fd.append('file', file)
    return http.post(`/upload/${kind}`, fd).then((r) => r.data)
  },
  uploads: () => http.get('/uploads').then((r) => r.data),
  reset: () => http.delete('/admin/reset').then((r) => r.data),
  checkUrl: (url) => http.post('/detect/phishing-url', { url }).then((r) => r.data),
  honeytoken: (body) => http.post('/detect/honeytoken', body).then((r) => r.data),
  honeytokens: () => http.get('/honeytokens').then((r) => r.data),

  settings: () => http.get('/settings').then((r) => r.data),
  setAutoResponse: (enabled) => http.put('/settings/auto-response', { enabled }).then((r) => r.data),
  blocklist: () => http.get('/blocklist').then((r) => r.data),
  unblock: (id) => http.delete(`/blocklist/${id}`).then((r) => r.data),
  runDecay: (hours) => http.post('/jobs/decay', null, { params: { hours_ahead: hours } }).then((r) => r.data),
  runGraph: () => http.post('/jobs/graph').then((r) => r.data),
  globalGraph: () => http.get('/graph/global').then((r) => r.data),
}

export default api
