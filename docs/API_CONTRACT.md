# API (under /api; JWT needed except health, login and the honeytoken webhook)

| Method | Path | Purpose |
|---|---|---|
| POST | /auth/login | `{username,password}` -> `{access_token}` |
| POST | /upload/{auth-log, web-log, network-log, url-list} | multipart file upload |
| DELETE | /admin/reset | clear events, alerts, incidents, blocklist |
| POST | /events/ingest | one JSON event (not login events) |
| POST | /detect/phishing-url | check one URL |
| POST | /detect/honeytoken | honeytoken webhook (open) |
| GET | /alerts, /alerts/{id} | module alerts |
| GET | /incidents, /incidents/{id}, /incidents/{id}/graph | incidents |
| POST | /incidents/{id}/respond | BLOCK_IP, BLOCK_URL, ESCALATE, MARK_FALSE_POSITIVE |
| POST | /incidents/{id}/feedback | true_positive, false_positive, benign |
| GET/PUT | /settings, /settings/auto-response | response mode toggle |
| GET/DELETE | /blocklist | blocked IPs / URLs |
| POST | /jobs/decay?hours_ahead=24 | run decay now |
| POST | /jobs/graph, GET /graph/global | NetworkX batch correlation |
| GET | /stats/dashboard | dashboard numbers |
| WS | /ws/alerts?token=... | live alert push |
