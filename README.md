# AI Cyber Threat Intelligence & Automated Response Platform

A cybersecurity prototype that detects suspicious activity, groups related
alerts into incidents, assigns risk scores and displays results on a dashboard.

## Features

- Phishing URL detection using Random Forest
- Unusual login detection using Isolation Forest
- Rule-based detection of brute-force attempts, port scanning and web attacks
- Honeytoken detection
- Incident correlation using NetworkX
- Risk scoring, risk decay and incident explanations
- Manual and automatic response workflows
- IP and URL blocklist records

## Technologies

- Frontend: React, Tailwind CSS, Chart.js
- Backend: Python, FastAPI
- Database: SQLite
- Machine Learning: scikit-learn
- Graph Analysis: NetworkX

## Run the Backend

Open PowerShell in the project root:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:HONEYTOKENS="HONEYTOKEN_AWS_DEV_KEY_9921,decoy_admin_token_alpha,/admin/backup-keys"
python -m uvicorn app.main:app --reload --port 8000
```

API documentation: http://localhost:8000/docs

## Run the Frontend

Open another PowerShell window in the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open the URL shown in the terminal, normally http://localhost:5173.

## Demo Login

- Username: `admin`
- Password: `admin123`

For local demonstration only.

## Usage

1. Start the backend and frontend.
2. Log in and open Upload Logs.
3. Upload sample files from `test_logs/`.
4. Review alerts, incidents, risk scores and graphs.
5. Use response controls to record actions.

## Testing

From the project root:

```powershell
python -m pytest -v
```

## Limitations

- Blocking stores database records; it does not change a real firewall.
- ML models use small demonstration datasets.
- Most logs are analysed through file uploads.
