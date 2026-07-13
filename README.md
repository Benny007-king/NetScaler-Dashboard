# NetScaler Dashboard — Dual-Stack (NITRO + Next-Gen)

A modern Flask dashboard for NetScaler with **parallel support** for both the **NITRO API** and the **Next-Gen API** (14.1+). The app auto-detects which API a node supports and **falls back to NITRO** when Next-Gen is unavailable.

Works for **standalone**, **HA-pair**, and **cluster (CLIP)** deployments. Serves **HTTPS on 443** with a self-signed certificate out of the box (replaceable from Settings), and supports **local** and **LDAP/AD** login.

Tabs: **Overview**, **Applications / Services**, **Failover History**, **User Sessions**, **Unlock Users**.

---

## Key Features

- **Deployment modes**: `standalone` (single node), `ha` (primary + secondary), `cluster` (primary points at the Cluster IP / CLIP; members read from `/config/clusternode`). Selectable in **Settings**.
- **Dual-Stack** runtime: auto-detect Next-Gen per node, fall back to NITRO.
- **HTTPS on 443** with a self-signed cert generated on first boot; upload your own PEM cert/key from **Settings → TLS Certificate** and restart to apply.
- **Authentication**: local admin account and/or **LDAP/Active Directory** (`AUTH_BACKENDS=local,ldap`), with optional allowed-group enforcement.
- **Applications / Services**: Next-Gen mode shows Applications; NITRO mode shows LB vServers plus Services / Service Groups.
- **Failover History & User Sessions**: date-range filters with a pop-up picker; **Excel/PDF** export (client-side).
- **Unlock Users**: unlock a locked AAA user (NITRO, with automatic `?action=unlock` fallback).

---

## Project Structure

```
netscaler-dashboard/
├── app.py                     # Flask app + NITRO/Next-Gen clients + API routes
├── cert_utils.py              # Self-signed cert generation / PEM validation
├── gunicorn.conf.py           # Binds 0.0.0.0:443 with TLS; generates cert on boot
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── nodes_config.example.json  # Copy to nodes_config.json (gitignored)
├── .env.example               # Copy to .env (gitignored)
├── templates/                 # dashboard.html, login.html, change_password.html
└── static/
```

Runtime files that are **gitignored** (contain secrets/state, created at runtime):
`nodes_config.json`, `auth_config.json`, `ha_last_state.json`, `failover_history.json`,
`.env`, `.app_secret`, `certs/`, `*.log`.

---

## Configuration

### Nodes — `nodes_config.json`

Copy `nodes_config.example.json` → `nodes_config.json` (or configure it live from **Settings**):

```json
{
  "mode": "ha",
  "primary":   { "ip": "10.0.0.100", "port": 443, "protocol": "https", "username": "nsroot", "password": "" },
  "secondary": { "ip": "10.0.0.200", "port": 443, "protocol": "https", "username": "nsroot", "password": "" }
}
```

- `mode`: `standalone` | `ha` | `cluster`. In `cluster`, set `primary` to the **Cluster IP (CLIP)**; members are discovered automatically.
- Passwords are stored in this gitignored file. Leaving the password blank in the Settings form keeps the currently stored value.

### Environment — `.env`

Copy `.env.example` → `.env`. Notable keys: `APP_PORT` (default `443`), `APP_SSL`, `TLS_CERT_FILE` / `TLS_KEY_FILE`, `AUTH_BACKENDS`, the `LDAP_*` block, and `NITRO_VERIFY_SSL`. See `.env.example` for the full list.

### Dashboard login

- Default local admin is `admin` / `admin`; you are forced to change it on first login.
- Reset it by deleting `auth_config.json` and restarting.

---

## Install & Run

### Docker (recommended)

```bash
docker compose up -d --build
```

Then open **https://<host>/** (self-signed cert — accept the browser warning, or upload your own from Settings). The compose project is named `netscaler-dashboard`.

### Python (dev)

```bash
pip install -r requirements.txt
python app.py            # serves HTTPS on :443 by default
```

> Binding to 443 may require elevated privileges. Set `APP_PORT` to a high port for local dev.

---

## REST Endpoints (summary)

- `GET  /api/caps` — per-node API capability + deployment mode
- `GET  /api/system-stats?node=primary|secondary`
- `GET  /api/ha-status` — HA nodes (or cluster members in cluster mode)
- `GET  /api/lb-vservers?node=...` / `GET /api/services?node=...` (NITRO)
- `GET  /api/failover-history` · `GET /api/user-sessions?node=...`
- `POST /api/unlock-user` — `{ "node": "primary", "username": "user1" }`
- `GET/POST /api/settings` — read/update nodes + mode
- `POST /api/tls-cert` — replace the TLS cert (`{ "cert": "...PEM...", "key": "...PEM..." }`)

---

## Security

- HTTPS-only on 443; replace the self-signed cert with your own from Settings.
- Secrets live in gitignored files (`nodes_config.json`, `.env`, `.app_secret`); never commit them.
- Session cookies are HttpOnly + SameSite=Lax + Secure. The session secret is random and persisted to `.app_secret`.
- Restrict access to NetScaler management networks (firewall / allowlist).

---

## Troubleshooting

- **Applications tab empty:** node doesn't support Next-Gen (cap bar shows `nitro`) — you'll see LB vServers/Services instead.
- **No failover/sessions:** check the selected date range; empty windows are normal.
- **TLS warning in browser:** expected with the default self-signed cert; upload a trusted cert from Settings.
- **Cluster shows no nodes:** confirm `primary` points at the CLIP and NITRO is reachable there.

---

## License

Private / Internal. All rights reserved by the repository owner.
