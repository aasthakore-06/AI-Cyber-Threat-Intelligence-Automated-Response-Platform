# AI Cyber Threat Intelligence & Automated Response Platform

IDEA Lab project, Ramdeobaba University, School of Computer Science and Engineering (2026-27, Sem V)
Team: Swanandi Zade, Nidhi Ashtankar, Radhika Joshi, Aastha Kore. Guide: Prof. Anshul Pande.

A small SOC (security operations centre) prototype. You upload log files, five detection modules look for
attacks, related alerts are joined into one incident, the incident gets a 0-100 risk score and a plain-language
story, and the admin can block the attacker manually or let the system do it automatically.

Main idea (from the synopsis): **Deception-Guided Graph Correlation**. Honeytokens give near-certain evidence, and
NetworkX links IPs, users and user agents, so an attacker who changes IP is still caught.

## What it does

| Step | What happens | Where |
|---|---|---|
| Ingest | auth.log, web access.log, network CSV and URL list are **uploaded as files**; honeytoken hits come by webhook | `api/upload.py`, `ingest/parsers.py` |
| Detect | Login (rules + Isolation Forest), Phishing URL (Random Forest), Port scan, Web attack (regex), Honeytoken | `detectors/` |
| Correlate (primary) | same IP or same user inside 30 min = one incident | `services/correlation.py` |
| Correlate (NetworkX) | batch job over recent incidents, joins incidents that share a user agent / user / decoy (IP rotation, multi-hop) | `services/graph_correlation.py` |
| Score | 0-100: 0-30 Safe, 31-70 Suspicious, 71-100 Malicious | `services/risk_scoring.py` |
| Decay | -10% every 6 h without new evidence, never below 50% | `services/risk_decay.py` |
| Narrative | ordered readable story + "why was this flagged" lines | `services/narrative.py` |
| Respond | Block IP / Block URL / Escalate / Mark false positive. **Manual** (button) or **Automatic** (toggle in Settings), both call the same function | `services/response.py` |
| Dashboard | React: live alert feed (websocket), charts, incidents, graph, settings, dark mode | `frontend/` |

### Login module (log upload based)
Upload a Linux `auth.log`. The parser reads the `Failed password` / `Accepted password` lines, then:
1. **Brute force**: more than 5 failed logins from one IP (or against one user) inside 120 s
2. **Failed/success ratio**: users with a high ratio over the last 7 days, plus "many failures then a success"
3. **Isolation Forest**: per-user features (hour vs the user's usual hour, weekend, new IP, failures right before) flag unusual logins

## Run it

```bash
cd backend
pip install -r requirements.txt
# plant decoys first (PowerShell: $env:HONEYTOKENS="..."), otherwise no honeytoken can trigger
export HONEYTOKENS="HONEYTOKEN_AWS_DEV_KEY_9921,decoy_admin_token_alpha,/admin/backup-keys"
python -m uvicorn app.main:app --reload --port 8000     # sqlite is used if DATABASE_URL is not set

cd frontend          # second terminal
npm install
npm run dev          # http://localhost:5173
```

### Tests
```bash
python -m pytest -v        # from the project root, 27 tests
```

## Trying it with the test logs
`test_logs/` has four small log files (auth.log, access.log, network.csv, urls.txt). They are only test input: they go through
the same upload page and parsers as any other log, nothing is pre-loaded. `generate_samples.py` in that folder shows how they were made.

1. Login, open **Upload Logs** and upload the four files (the page says which module each box feeds).
2. **Dashboard**: events, alerts, charts and incident counts fill from the uploaded data.
3. **Graph**, *Run NetworkX correlation now*: incidents that the 30-minute window kept apart are joined through a shared user agent / user / decoy.
4. **Graph** also has a *Block all N IPs* button for an actor that used several IPs (same user, different IPs).
5. **Incidents**: open one to see the narrative, score breakdown, timeline and graph, or use the **Block IP** button on the incident row. On the incident page use **Block IP** / **Block URL** / **Escalate** / **Mark false positive** (manual mode).
5. **Settings**: switch to automatic response, clear data, upload again; Malicious incidents get an "Auto" tag and are blocked without a click. Switch back to manual afterwards.
6. **Settings**, *Run decay job* with a number of hours to see scores drop (decay history appears on the incident).
7. `/docs` shows the generated API documentation.

You can also upload your own logs as long as they match the formats listed on the Upload page.

## Layout
```
backend/app/  api/ detectors/ ingest/ services/ db/ tests/
test_logs/    four small log files used for testing
frontend/src/ pages/ components/ services/api.js
docs/         ARCHITECTURE.md, API_CONTRACT.md
```

## Limits 
- "Blocking" writes to a `blocklist` table; no real firewall is touched.
- Honeytokens are fake strings/routes you list in the `HONEYTOKENS` setting (`.env` / `compose.yaml`). They are copied into the `honeytokens` table at startup and the detector reads that table. Nothing is pre-planted if the setting is empty.
- Only SSH-style auth logs are parsed; syslog has no year so the current year is assumed.
- Isolation Forest is fitted on the uploaded log plus a small synthetic baseline; thresholds were tuned on our synthetic data only.
- Adaptive scoring (refitting weights) and SHAP are **not** built. Analyst feedback is stored with the alert features so they can be added later future scope.
- Single admin account, no roles.
