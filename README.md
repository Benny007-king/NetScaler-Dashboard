# NetScaler Dashboard — Dual-Stack (NITRO + Next-Gen)

A modern Flask dashboard for NetScaler with **parallel support** for both **NITRO API** and the **Next-Gen API**.  
The app automatically detects which API is supported per node and **falls back to NITRO** when Next-Gen is unavailable.

Tabs included: **Overview**, **Applications / Services**, **Failover History**, **User Sessions**, and **Unlock Users**.

---

## Key Features

- **Dual-Stack** runtime: auto-detect Next-Gen per node; fallback to NITRO when needed.
- **Applications / Services**:
  - In **Next-Gen** mode: shows Applications.
  - In **NITRO** mode: shows LB vservers plus Services / Service Groups.
- **Failover History & User Sessions**:
  - Date-range filters with a pop-up **date picker** that stays open until **Apply/Cancel**.
  - **Search** buttons trigger fresh API calls; **Export CSV** available.
- **Unlock Users**: unlock a locked AAA user (NITRO, with automatic `?action=unlock` fallback).
- **HTTPS** support for local secure runs.
- Lightweight, responsive, dark UI.

---

## Project Structure

netscaler-dashboard/
├── app.py
├── requirements.txt
├── .env
├── auth_config.json
├── netscaler_complete.log
├── templates/
│ ├── dashboard.html
│ ├── login.html
│ └── change_password.html
└── README.md

makefile
Copy
Edit

---

## Configuration

### 1) `.env` (do NOT commit)

All sensitive settings live here. Example:

```env
# Flask
SECRET_KEY=REPLACE_WITH_LONG_RANDOM_STRING

# Primary node (example)
PRIMARY_NODE_IP=10.0.0.90
PRIMARY_NODE_USER=nsroot
PRIMARY_NODE_PASS=nsroot
PRIMARY_NODE_PROTOCOL=http
PRIMARY_NODE_PORT=80

# Secondary node (example)
SECONDARY_NODE_IP=10.0.0.92
SECONDARY_NODE_USER=nsroot
SECONDARY_NODE_PASS=nsroot
SECONDARY_NODE_PROTOCOL=http
SECONDARY_NODE_PORT=80

# NITRO
NITRO_VERIFY_SSL=0
NITRO_TIMEOUT_SECS=15

# Next-Gen
NEXTGEN_VERIFY_SSL=0
NEXTGEN_TIMEOUT_SECS=15

# HTTPS (optional)
ENABLE_HTTPS=0
SSL_CERT_FILE=cert.pem
SSL_KEY_FILE=key.pem
SECRET_KEY must be long and random. Generate with one of:

python -c "import secrets; print(secrets.token_urlsafe(64))"

openssl rand -hex 64

2) auth_config.json
Runtime config for nodes and default API mode hints (the app still auto-detects capabilities):

json
Copy
Edit
{
  "api_mode": {
    "primary": "nitro",
    "secondary": "nitro"
  },
  "nodes": {
    "primary": { "ip": "10.0.0.90", "port": 80, "protocol": "http" },
    "secondary": { "ip": "10.0.0.92", "port": 80, "protocol": "http" }
  }
}
If this file is missing, it is created on first run.

To reset the dashboard’s admin password/policy, delete auth_config.json, start the app, log in, and set a new password from Change Password.

Install & Run
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Create/adjust .env and auth_config.json per the examples above.

Start:

bash
Copy
Edit
python app.py
If ENABLE_HTTPS=1 and SSL_CERT_FILE/SSL_KEY_FILE are valid, the server starts over HTTPS.

Open http://127.0.0.1:5000 (or https://... accordingly).

Windows console note:
If you ever see Unicode logging issues in classic cmd.exe, set:

bat
Copy
Edit
set PYTHONIOENCODING=utf-8
(Or use PowerShell.)

Using the Dashboard
Overview
System stats, versions, HA roles, CPU/Mem, HTTP rates.

HA table with status, sync, and route monitor state.

The capability bar shows the active API mode per node (nextgen / nitro).

Applications & Services
Next-Gen mode: Applications from the Next-Gen API.

NITRO mode: LB vservers and Services / Service Groups from NITRO.

Failover History
Two date pickers (From/To). The pop-up stays open until you click Apply or Cancel.

Filter by Type (Automatic / Manual / Failure / Role change).

Search refreshes the table; Export CSV downloads results (when enabled server-side).

User Sessions
Date range, User, Type (Web/VPN/Workspace), and Status (Active/Terminated).

Search and Export CSV.

Unlock Users
Select node (primary/secondary), enter username, click Unlock.

Uses NITRO /nitro/v1/config/aaauser, with automatic fallback to ?action=unlock.

REST Endpoints (summary)
Capabilities & system

GET /api/caps — Next-Gen/NITRO capability report per node.

GET /api/system-stats

GET /api/ha-status

Apps/Services

GET /api/applications?node=primary|secondary (Next-Gen)

GET /api/lb-vservers?node=... (NITRO)

GET /api/services?node=... (NITRO)

Failover

GET /api/failover-history?from=ISO&to=ISO&type=&node=...

GET /api/export/failover-history (CSV)

User Sessions

GET /api/user-sessions?from=ISO&to=ISO&user=&type=&status=&node=...

GET /api/export/user-sessions (CSV)

Actions

POST /api/unlock-user

json
Copy
Edit
{ "node": "primary", "username": "user1" }
Security
Keep secrets in .env; do not hard-code credentials.

Optional local HTTPS via ENABLE_HTTPS=1 and certificate/key files.

Restrict access to NetScaler management networks (firewall/allowlist).

Troubleshooting
Applications tab empty / disabled look: The node likely does not support Next-Gen (cap bar shows nitro). In NITRO mode you’ll see LB vservers/Services instead.

No Failover / Sessions listed: Check the selected date range. Empty results can be normal if there were no events or sessions in that window.

SSL verification errors in lab: Set NITRO_VERIFY_SSL=0 / NEXTGEN_VERIFY_SSL=0 for testing.

Secondary name shows as node-2: The UI displays names as provided by the API; if the device doesn’t return a human-friendly label, a fallback like node-2 is shown. Adjust naming in your environment if desired.

Logging
Runtime logs go to stdout and to netscaler_complete.log by default.

For production, prefer running behind a process manager (e.g., gunicorn, supervisor) and reverse proxy.

Production Recommendations
Run behind Nginx/Apache with a real certificate.

Use Gunicorn/uWSGI instead of Flask’s dev server.

Persist historical data (failover/sessions) in a proper datastore if you need long-term reports.

Add CI/CD and basic tests as needed.

License
Private / Internal. All rights reserved by the repository owner.

makefile
Copy
Edit

::contentReference[oaicite:0]{index=0}






Sources

Ask ChatGPT
