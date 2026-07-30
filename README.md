# NetScaler Dashboard — Dual-Stack (NITRO + Next-Gen)

A modern Flask dashboard for NetScaler with **parallel support** for both the **NITRO API** and the **Next-Gen API** (14.1+). The app auto-detects which API a node supports and **falls back to NITRO** when Next-Gen is unavailable.

Works for **standalone**, **HA-pair**, and **cluster (CLIP)** deployments. Serves **HTTPS on 443** with a self-signed certificate out of the box (replaceable from Settings), and supports **local** and **LDAP/AD** login.

Tabs: **Overview**, **Applications / Services**, **Failover History**, **User Sessions**, **Unlock Users**.

---

## Key Features

- **Deployment modes**: `standalone` (single node), `ha` (primary + secondary), `cluster` (primary points at the Cluster IP / CLIP; members read from `/config/clusternode`). Selectable in **Settings**.
- **Dual-Stack** runtime: auto-detect Next-Gen per node, fall back to NITRO.
- **HTTPS on 443** with a cert signed by a **local CA** generated on first boot. Install the CA for warning-free HTTPS, upload your own PEM cert/key, or generate a CSR for your corporate CA — all from **Settings → TLS Certificate**.
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
- **LDAP/AD is configured in the UI** — open **Settings → LDAP / Active Directory**, enable it, fill in server / base DN / bind account / user attribute (and optional allowed-group DN), and use **Test Connection** before saving. Settings persist to `ldap_config.json` (gitignored). The `LDAP_*` env vars in `.env` act as initial defaults. The local admin account always works regardless.

### Session timeout

Idle users are logged out automatically. Default **15 minutes**; change it in **Settings → Session Timeout** (1–1440 min). It's a sliding, server-enforced inactivity timeout — background auto-refresh polls don't keep the session alive, and an expired session returns to the login page.

### Data persistence (survives updates)

All runtime state — node config, LDAP config, the local database, TLS certs, and the session secret — lives under **`DATA_DIR`** (default `data/`), which the compose files back with a Docker **named volume** (`ns_data`). So `git pull` and image rebuilds **never touch your configuration** — you set it up once. On first start after upgrading, any legacy root-level files are migrated into the volume automatically, and loaders fall back to the old location so nothing is lost. Back up the volume with:

```bash
docker run --rm -v netscaler-dashboard_ns_data:/data -v "$PWD":/backup alpine tar czf /backup/ns_data_backup.tgz -C /data .
```

### Local history database & retention

`dashboard.db` (SQLite — no external service) stores **failover events** and **session history**, so the Failover and Sessions tabs show real history rather than only what's live on the appliance.

A **retention pass runs at startup and hourly**, deleting anything older than **`RETENTION_DAYS` (default 7)** — you always keep at least a week, and the file can't grow unbounded. Sessions are de-duplicated per **(node, stable session id)** — so repeated polls of the same session refresh **one row** instead of piling up — and marked `Active` while still being seen, `Terminated` afterwards.

Inspect it any time:

```bash
curl -k https://<host>/api/history-stats     # size, row counts, oldest data, retention window
```

Tune with `RETENTION_DAYS`, `RETENTION_INTERVAL_SECS`, `DASHBOARD_DB_FILE` (see `.env.example`). The DB is gitignored.

---

## Install & Run

### Docker (recommended)

```bash
docker compose up -d --build
```

Then open **https://<host>/** (self-signed cert — accept the browser warning, or upload your own from Settings). The compose project is named `netscaler-dashboard`.

#### Version-tagged images

Pass `APP_VERSION` to tag the built image with the release (it's also stamped into
the image as an OCI `org.opencontainers.image.version` label). Without it the
image is tagged `:latest`.

```bash
APP_VERSION=$(cat VERSION) docker compose -f docker-compose.yml -f deploy/docker-compose.proxy.yml up -d --build
```

That produces `netscaler-dashboard:<version>` — verify with
`docker images netscaler-dashboard` or
`docker inspect netscaler-dashboard --format '{{index .Config.Labels "org.opencontainers.image.version"}}'`.

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
- `POST /api/tls-cert` — replace the TLS cert (`{ "cert": "...PEM...", "key": "...PEM..." }`; key optional after a CSR)
- `GET  /api/tls-ca` — download the local CA certificate
- `POST /api/tls-csr` — generate a CSR (`{ "common_name": "..." }`)

---

## TLS certificates

On first boot the app generates a **local CA** (`certs/ca.crt` / `certs/ca.key`) and issues a server cert signed by it. Three ways to get trusted HTTPS, all under **Settings → TLS Certificate**:

1. **Install the local CA** — click *Download CA Certificate* and add it to each client's trust store (Windows: *Trusted Root Certification Authorities*; browsers may have their own store). The default server cert then validates cleanly. Add extra hostnames/IPs to the cert via `TLS_SAN`.
2. **Upload your own** cert + key (PEM), then restart.
3. **Generate a CSR** — click *Generate CSR*, have it signed by your corporate CA, then upload the signed certificate (leave the key field blank — the matching key stays on disk). Restart to apply.

## Running behind a reverse proxy

`deploy/nginx.conf` + `deploy/docker-compose.proxy.yml` terminate TLS at nginx and proxy to the app over internal HTTP:

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.proxy.yml up -d --build
```

This runs the app with `APP_SSL=0`, `APP_PORT=8080`, `TRUST_PROXY=1` (so it honors `X-Forwarded-Proto` for secure cookies/redirects) and publishes 443/80 from nginx. `gunicorn.conf.py` binds plain HTTP when `APP_SSL=0`, so nginx alone terminates TLS. Put a cert/key in `./certs` (a prior default run generates one, or drop your own).

## Versioning

`major.minor.patch`, starting at `1.0.0`. A small change/fix bumps the patch (`1.0.0 → 1.0.1`); a significant change/feature bumps the minor and resets patch (`1.0.0 → 1.1.0`). Each release is tagged `vX.Y.Z`; see [CHANGELOG.md](CHANGELOG.md).

## Security

- HTTPS-only on 443; CA-signed cert out of the box, replaceable from Settings.
- Response headers: HSTS (on HTTPS), CSP (scoped to the CDNs used), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- Secrets live in gitignored files (`nodes_config.json`, `.env`, `.app_secret`, `certs/`); never commit them.
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
