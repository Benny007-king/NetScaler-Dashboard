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

```
netscaler-dashboard/
├── app.py
├── requirements.txt
├── .env
├── auth_config.json
├── netscaler_complete.log
├── templates/
│   ├── dashboard.html
│   ├── login.html
│   └── change_password.html
└── README.md
```

---

## Configuration

> Environment variables are expected to be provided via a `.env` file, but the exact keys and values are **omitted here** per your request.  
> Keep secrets in `.env` and never commit that file.

### `auth_config.json`

Runtime config for nodes and default API mode hints (the app also auto-detects capabilities at runtime):

```json
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
```

- If this file is missing, it is created on first run.
- To reset the dashboard’s admin password/policy, delete `auth_config.json`, start the app, log in, and set a new password from **Change Password**.

---

## Install & Run

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Provide your environment variables in `.env` (not documented here) and adjust `auth_config.json` as needed.

3. Start:
   ```bash
   python app.py
   ```
   - If HTTPS is enabled via your environment (certificate + key), the server starts over HTTPS.
   - Open `http://127.0.0.1:5000` (or `https://...` accordingly).

**Windows console note:**  
If you ever see Unicode logging issues in classic `cmd.exe`, set:
```bat
set PYTHONIOENCODING=utf-8
```
(Or use PowerShell.)

---

## Using the Dashboard

### Overview
- System stats, versions, HA roles, CPU/Mem, HTTP rates.
- HA table with status, sync, and route monitor state.
- The capability bar shows the active API mode per node (`nextgen` / `nitro`).

### Applications & Services
- **Next-Gen** mode: Applications from the Next-Gen API.
- **NITRO** mode: LB vservers and Services / Service Groups from NITRO.

### Failover History
- Two date pickers (From/To). The pop-up stays open until you click **Apply** or **Cancel**.
- Filter by Type (Automatic / Manual / Failure / Role change).
- **Search** refreshes the table; **Export CSV** downloads results (when enabled server-side).

### User Sessions
- Date range, User, Type (Web/VPN/Workspace), and Status (Active/Terminated).
- **Search** and **Export CSV**.

### Unlock Users
- Select node (primary/secondary), enter username, click **Unlock**.
- Uses NITRO `/nitro/v1/config/aaauser`, with automatic fallback to `?action=unlock`.

---

## REST Endpoints (summary)

**Capabilities & system**
- `GET /api/caps` — Next-Gen/NITRO capability report per node.
- `GET /api/system-stats`
- `GET /api/ha-status`

**Apps/Services**
- `GET /api/applications?node=primary|secondary`  _(Next-Gen)_
- `GET /api/lb-vservers?node=...`                   _(NITRO)_
- `GET /api/services?node=...`                      _(NITRO)_

**Failover**
- `GET /api/failover-history?from=ISO&to=ISO&type=&node=...`
- `GET /api/export/failover-history`  _(CSV)_

**User Sessions**
- `GET /api/user-sessions?from=ISO&to=ISO&user=&type=&status=&node=...`
- `GET /api/export/user-sessions`      _(CSV)_

**Actions**
- `POST /api/unlock-user`
  ```json
  { "node": "primary", "username": "user1" }
  ```

---

## Security

- Keep secrets in `.env`; do not hard-code credentials.
- Optional local HTTPS (certificate + key).
- Restrict access to NetScaler management networks (firewall/allowlist).

---

## Troubleshooting

- **Applications tab empty / disabled look:** The node likely does not support Next-Gen (cap bar shows `nitro`). In NITRO mode you’ll see LB vservers/Services instead.
- **No Failover / Sessions listed:** Verify the selected date range. Empty results can be normal if there were no events or sessions in that window.
- **SSL verification errors in lab:** Temporarily disable verification via env (not documented here).
- **Secondary name shows as `node-2`:** The UI displays names as provided by the API; if the device doesn’t return a friendly label, a fallback like `node-2` is shown.

---

## Logging

- Runtime logs go to stdout and to `netscaler_complete.log` by default.
- For production, prefer running behind a process manager (e.g., `gunicorn`, `supervisor`) and reverse proxy.

---

## Production Recommendations

- Reverse proxy (Nginx/Apache) with a real certificate.
- Gunicorn/uWSGI instead of Flask dev server.
- Persist historical data (failover/sessions) in a proper datastore if you need long-term reports.
- CI/CD and basic tests as needed.

---

## License

Private / Internal. All rights reserved by the repository owner.
