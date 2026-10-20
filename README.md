# NetScaler Dashboard — Dual-Stack (NITRO + Next-Gen)

A modern Flask dashboard for NetScaler with **parallel support** for both the **NITRO API** and the **Next-Gen API** (14.1+). The app auto-detects which API a node supports and **falls back to NITRO** when Next-Gen is unavailable.

Manage **multiple NetScaler deployments** from one dashboard — any mix of **standalone**, **HA-pair**, and **cluster (CLIP)** instances (e.g. two HA pairs plus three standalones). An **Instance switcher** in the header scopes every tab to the selected deployment. Serves **HTTPS on 443** with a self-signed certificate out of the box (replaceable from Settings), and supports **local** and **LDAP/AD** login.

Tabs: **All Instances** (fleet health wall), **Overview**, **Applications / Services**, **Failover History**, **User Sessions**, **Certificates**, **Unlock Users**.

---

## Get it — the virtual appliance

The dashboard ships as a **virtual appliance**: a minimal Linux VM with Docker and the dashboard pre-installed and tested together. There is nothing to install on a host.

| | File | What to do with it |
|---|---|---|
| **First-time install** | `netscaler-dashboard-appliance-<version>.ova` | Import into VMware ESXi / Workstation / Fusion or VirtualBox and power on. The console shows the address to browse to. |
| **Upgrade** | `netscaler-dashboard-upgrade-<version>.nsu` | Upload in **Settings → Software & Upgrade**. Configuration is kept; a version that fails to start is rolled back automatically. |

Both are attached to every [GitHub Release](https://github.com/Benny007-king/NetScaler-Dashboard/releases/latest), with a `SHA256SUMS` file. Full guide: **https://net-scaler-dashboard-web.vercel.app/docs.html**

- VM defaults: 2 vCPU · 2 GB RAM · 16 GB thin disk · DHCP (a static address is set from the console menu).
- Neither the appliance nor the browser needs internet access: the pages load everything from the appliance itself.
- Times are shown in the appliance's time zone - Asia/Jerusalem until you choose another under **Time zone** on the console menu.
- Web sign-in `admin` / `admin`, console sign-in `nsadmin` / `nsadmin` — both must be changed at first use. SSH is off until enabled from the console.

---

## Key Features

- **All-instances health wall**: the **All Instances** tab shows every deployment as a card — Operational / Degraded / Unreachable, nodes up, and per node the hostname, IP, HA role + status and live CPU/memory, with warnings for unreachable nodes and forced HA modes. Click a card to drill into that instance. Powered by `GET /api/instances-health` (all instances and nodes probed in parallel).
- **Multiple instances**: manage many deployments at once. Add / rename / remove them in **Settings → NetScaler Instances** and pick the active one from the header **Instance** switcher; every tab, plus session and failover history, is scoped to it.
- **Deployment modes** (per instance): `standalone` (single node), `ha` (primary + secondary), `cluster` (primary points at the Cluster IP / CLIP; members read from `/config/clusternode`), `sdx` (the node is an SDX Management Service - see below). Selectable in **Settings**.
- **HA status at a glance**: the HA panel shows each node's role *and* its NITRO `hastatus` — including the forced **STAYPRIMARY / STAYSECONDARY** modes (flagged amber, since they suppress failover), `Up`, and failure states like route-monitor/partial/complete failure.
- **HA resilience**: if one node of an HA pair is down, the dashboard keeps polling — HA status fails over to whichever node answers, the dead node is shown offline, the role change is logged as a failover, and the dead node fails fast (~3s connect timeout) instead of hanging.
- **Dual-Stack** runtime: auto-detect Next-Gen per node, fall back to NITRO. Detection is explainable — the capability line shows *why* a node is on NITRO — and **re-runs automatically** every `API_DETECT_INTERVAL_SECS` (default 600s), so enabling Next-Gen on an appliance, or a node that was unreachable at boot, is picked up without a restart. `GET /api/nextgen-debug` reports the version, which management paths answer and the real login error; `NEXTGEN_BASE_PATH` overrides the path.
- **Honest health colours**: service/application states render `UP` green, `DOWN` red, and `OUT OF SERVICE` / `PARTIAL-UP` / `DISABLED` / `UNKNOWN` amber.
- **HTTPS on 443** with a cert signed by a **local CA** generated on first boot. Install the CA for warning-free HTTPS, upload your own PEM cert/key, or generate a CSR for your corporate CA — all from **Settings → TLS Certificate**.
- **Authentication**: local admin account and/or **LDAP/Active Directory** (`AUTH_BACKENDS=local,ldap`), with optional allowed-group enforcement.
- **Applications / Services**: one search box over both tables (name, IP, port, type, state) and a state filter; shows Next-Gen Applications when a node has them, and falls back to classic **LB vServers** otherwise; **Services and Service Groups** are listed with their real runtime state (`UP` / `DOWN` / `OUT OF SERVICE` / `PARTIAL-UP`) and bound-member counts.
- **Tabs follow the live primary**: Applications, Failover, Sessions, Security, Certificates and Unlock User open on the node currently holding the PRIMARY role, so they track a failover automatically.
- **Failover History & User Sessions**: date-range filters with a pop-up picker (a session is shown when it overlaps the range); **Excel/PDF** export (client-side). The Sessions tab is about **Gateway / AAA end users** only - management logins and system accounts never appear. Live sessions come from NITRO `aaasession` (one row per user, address and virtual server; the Gateway named from its virtual server address; group, intranet IP, destinations) and the live ICA connections (application server by name, TCP or EDT). The Gateway's own log lines - received by [syslog](#security-tab) or read from the audit log - add the real **login and logout time**, duration and **why it ended** (logoff, idle timeout, forced logoff), the Gateway and AAA **session ids**, the **client type** (ICA proxy, clientless, full VPN), **OS** and **Workspace app or browser** (from the login audit policy on the Security tab), the Gateway FQDN, user agent, bytes, and each **published application** with its server, start and end. Sessions that ended before the dashboard saw them appear from their log lines. **Failed sign-ins** (status `Failed`, attempt time, source IP, failure reason) and **locked accounts** (`Locked`) are kept for the retention period. `GET /api/session-debug` dumps per-node reachability and the raw (redacted) NITRO session and audit fields.
- **SDX**: an instance in `sdx` mode points at the SDX **Management Service** (NITRO v2, read-only) and shows the platform, its hardware health (power supplies, fans, temperatures, voltages, interfaces, disks), the platform license, and every NetScaler (VPX) instance on it with state, role, version, load and allocation. An instance that is also added to the dashboard opens from there, and its own overview says which SDX it runs on.
- **License & Capacity**: edition, license type (LAS fixed bandwidth, LAS online, pooled, local file, vCPU), capacity, expiry date and grace period - amber within 30 days or in grace, red within 7 days - also flagged on the All Instances card.
- **Security tab**: a hardening checklist for the Gateway (36 items) - login audit logging, brute-force rate limiter, session cookie hijack prevention, IP reputation, EPA Referer check, SAML hardening, built-in WAF protection for Auth/VPN/Portal, CSP header, HttpOnly cookies, cookie version 1, enhanced TCP ISN generation, secure-only management, syslog to the dashboard - each detected on the node, markable **Done** / **Not relevant**, with an explanation and the commands for the node's version, exportable to Excel or PDF with the marks. Below it, the **activity**: WAF violations and policy hits over time, the hit counters of the checklist's policies, top source addresses and URLs, and every event with all its fields. See [Security tab](#security-tab).
- **Unlock Users**: unlock a locked AAA user (NITRO, with automatic `?action=unlock` fallback).
- **External database (optional)**: keep session and failover history, plus a copy of the settings, in your own **PostgreSQL, MySQL / MariaDB or Microsoft SQL Server** — set up in **Settings → Database**. The dashboard keeps working when that database is unreachable and catches up by itself when it returns.

---

## Project Structure

```
netscaler-dashboard/
├── app.py                     # Flask app + NITRO/Next-Gen clients + API routes
├── appliance.py               # Version/health endpoints + upgrade-bundle upload
├── db.py                      # History + settings store: built-in SQLite or an external database
├── security.py                # Security tab: checklist detection, log-line parsing, syslog receiver
├── security_catalog.py        # The checklist entries: explanation, commands, how each is detected
├── tests/test_security.py     # Checklist, log lines, syslog, sessions - against tests/fake_netscaler.py
├── tests/test_platform.py     # License & Capacity, SDX - against the same stand-ins
├── tests/test_storage.py      # Storage tests, run against real database servers
├── tests/test_auth.py         # Login tests: default admin, forced change, hashes from earlier releases
├── tests/test_offline.py      # No page loads from another host; bundled files match their checksums; time zone
├── static/vendor/             # Browser libraries and fonts served by the dashboard itself (see its README)
├── appliance/                 # Everything that turns the image into a virtual appliance
│   ├── build.sh               #   builds the OVA and the .nsu (needs only Docker)
│   ├── build-image.sh         #   Debian image -> customised disk -> OVA
│   ├── make-upgrade.sh        #   packs the upgrade bundle
│   ├── host-install.sh        #   installs rootfs/ (at build time and at upgrade time)
│   ├── rootfs/                #   host files: systemd units, ns-dashboard, ns-upgrade, ns-console
│   ├── appliance.ovf.in       #   OVF descriptor template
│   ├── smoke-test.sh          #   boots the OVA in QEMU: install, upgrade, rollback, console
│   └── console-test.py        #   drives the console menu over the VM's serial port
├── .github/workflows/release.yml  # tag -> build -> boot-test -> GitHub Release
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
`nodes_config.json`, `auth_config.json`, `ldap_config.json`, `db_config.json`, `ha_last_state.json`,
`failover_history.json`, `dashboard.db`, `.env`, `.app_secret`, `certs/`, `*.log`.

---

## Configuration

### Nodes — `nodes_config.json`

Configure it live from **Settings → NetScaler Instances** (recommended), or edit `nodes_config.json` directly. It holds a list of **instances**, each with its own mode and nodes:

```json
{
  "instances": [
    {
      "id": "default", "name": "DC1 HA pair", "mode": "ha",
      "primary":   { "ip": "192.0.2.10", "port": 443, "protocol": "https", "username": "nsroot", "password": "" },
      "secondary": { "ip": "192.0.2.11", "port": 443, "protocol": "https", "username": "nsroot", "password": "" }
    },
    {
      "id": "lab", "name": "Lab standalone", "mode": "standalone",
      "primary": { "ip": "192.0.2.50", "port": 443, "protocol": "https", "username": "nsroot", "password": "" }
    }
  ],
  "session_timeout_minutes": 15
}
```

- `mode` (per instance): `standalone` | `ha` | `cluster` | `sdx`. In `cluster`, set `primary` to the **Cluster IP (CLIP)**; members are discovered automatically. In `sdx`, `primary` is the SDX Management Service address with its `nsroot` (or a read-only Management Service user); add the NetScaler instances on it as instances of their own to see their traffic, sessions and security.
- Passwords are stored in this gitignored file. Leaving a password blank in the Settings form keeps the currently stored value for that node.
- **Backward compatible:** a legacy single-deployment file (top-level `mode`/`primary`/`secondary`) is migrated automatically into one `"Default"` instance on first start.

### A dedicated NetScaler user for the dashboard (optional)

The dashboard talks to the NetScaler only through the API (NITRO, over the protocol and port set for the node). It never uses the CLI, SSH or the shell, and the only thing it changes is *unlock AAA user* on the Unlock User tab. Instead of `nsroot`, it can sign in with an account that has exactly that. Create it as `nsroot` - only a superuser may set `-allowedManagementInterface`:

```
add system cmdPolicy Dashboard_Read_Policy ALLOW "(^show\\s+audit\\s+messages)|(^show\\s+audit\\s+messages\\s+.*)|(^show\\s+system\\s+(user|parameter))|(^show\\s+system\\s+(user|parameter)\\s+.*)"
add system cmdPolicy Unlock_Users_Policy ALLOW "(^unlock\\s+aaa\\s+user)|(^unlock\\s+aaa\\s+user\\s+.*)"
add system user Dashboard <password> -externalAuth DISABLED -timeout 900 -logging ENABLED -maxsession 20 -allowedManagementInterface API
bind system user Dashboard read-only 100
bind system user Dashboard Unlock_Users_Policy 110
bind system user Dashboard Dashboard_Read_Policy 120
save ns config
```

Everything the dashboard runs, and the policy that allows it:

| The dashboard runs | Allowed by | For |
|---|---|---|
| `show ...` (all but the next two rows) | `read-only` | HA / cluster state, virtual servers, services, certificates, license and capacity, AAA sessions, ICA connections, AAA users, and almost every checklist item |
| `stat ...` | `read-only` | CPU, memory, throughput, counters |
| `show audit messages` | `Dashboard_Read_Policy` | the appliance's audit log: WAF violations, policy hits, failed logins, and the Gateway login / logout lines behind the Sessions tab's times and end reasons - whenever no syslog from the NetScaler reaches the dashboard |
| `show system user`, `show system parameter` | `Dashboard_Read_Policy` | three checklist items: *Named administrator accounts*, *Strong passwords for management accounts*, *Management sessions time out* |
| `unlock aaa user` | `Unlock_Users_Policy` | the Unlock User tab |
| `add`, `set`, `rm`, `save`, `kill`, the shell, ... | - | never run |

**Is `read-only` plus the Unlock policy enough? No.** The built-in `read-only` policy allows every `show` and `stat` command except `show system ...`, `show audit messages`, `show ns runningConfig` / `ns.conf` / `savedconfig`, `show configstatus`, `show techsupport` and `show shell`. The dashboard needs the first two, so with only `read-only` and the Unlock policy the audit log is refused (no WAF events, policy-hit details, failed logins or session end reasons from the appliance unless it sends syslog to the dashboard) and the three checklist items above show *Could not check*. The Security tab says when a read is refused, with the appliance's own answer.

- `-allowedManagementInterface API` - the API (NITRO, which the GUI also uses) only; the account cannot open the CLI, SSH or the console.
- `-externalAuth DISABLED` - the local password always works, also when LDAP/RADIUS is down.
- `-timeout 900` - idle sessions end after 15 minutes; `-maxsession 20` - at most 20 connections at once.
- `-logging ENABLED` - optional; it does not affect what the dashboard can read.
- Use a long random password and enter it in **Settings → NetScaler Instances** for every node. On an HA pair, create the user and policies on the primary - they are synchronised to the secondary, which the dashboard reads with the same account; in a cluster, on the Cluster IP.
- Without the Unlock policy the dashboard still works; only unlocking users is refused.
- An `sdx` instance signs in to the SDX Management Service, which has users of its own; the dashboard only reads there.

### Environment — `.env`

Copy `.env.example` → `.env`. Notable keys: `APP_PORT` (default `443`), `APP_SSL`, `TLS_CERT_FILE` / `TLS_KEY_FILE`, `AUTH_BACKENDS`, the `LDAP_*` block, and `NITRO_VERIFY_SSL`. See `.env.example` for the full list.

### Dashboard login

- Default local admin is `admin` / `admin`; you are forced to change it on first login.
- Reset it by deleting `auth_config.json` and restarting (on the appliance: console menu → *Reset the web admin password*).
- The password is stored in `auth_config.json` only as a salted scrypt hash. A hash written by 1.16.0 or earlier (unsalted SHA-256) still signs in and is replaced on the first successful sign-in.
- **LDAP/AD is configured in the UI** — open **Settings → LDAP / Active Directory**, enable it, fill in server / base DN / bind account / user attribute (and optional allowed-group DN), and use **Test Connection** before saving. Settings persist to `ldap_config.json` (gitignored). The `LDAP_*` env vars in `.env` act as initial defaults. The local admin account always works regardless.

### Session timeout

Idle users are logged out automatically. Default **15 minutes**; change it in **Settings → Session Timeout** (1–1440 min). It's a sliding, server-enforced inactivity timeout — background auto-refresh polls don't keep the session alive, and an expired session returns to the login page.

### Data persistence (survives updates)

All runtime state — node config, LDAP config, the local database, TLS certs, and the session secret — lives under **`DATA_DIR`** (default `data/`), which the compose files back with a Docker **named volume** (`ns_data`). So `git pull` and image rebuilds **never touch your configuration** — you set it up once. On first start after upgrading, any legacy root-level files are migrated into the volume automatically, and loaders fall back to the old location so nothing is lost. Back up the volume with:

```bash
docker run --rm -v netscaler-dashboard_ns_data:/data -v "$PWD":/backup alpine tar czf /backup/ns_data_backup.tgz -C /data .
```

### Upgrading

Run the one-command upgrade script from the repo folder — it pulls the latest
release and rebuilds the version-tagged image:

```bash
./upgrade.sh          # Linux / macOS
```
```bat
upgrade.bat           :: Windows (cmd, or  .\upgrade.bat  in PowerShell)
```

It runs `git checkout main && git pull --ff-only` (which also **recovers a
detached-HEAD checkout**, e.g. after `git checkout vX.Y.Z`), reads `VERSION`, then
`docker compose up -d --build` with that tag. Because the image tag comes from
`VERSION`, this guarantees the rebuilt image matches the release. If you run behind
the reverse proxy, set `COMPOSE_FILE` once so the script uses both files:

```bash
export COMPOSE_FILE=docker-compose.yml:deploy/docker-compose.proxy.yml
```

### History store & retention

The built-in store, `dashboard.db` (SQLite — no external service), holds **failover events** and **session history**, so the Failover and Sessions tabs show real history rather than only what's live on the appliance. An [external database](#external-database) can hold them instead.

A **retention pass runs at startup and hourly**, deleting anything older than **`RETENTION_DAYS` (default 7)** — you always keep at least a week, and the file can't grow unbounded. Sessions are de-duplicated per **(node, stable session id)** — so repeated polls of the same session refresh **one row** instead of piling up — and marked `Active` while still being seen, `Terminated` afterwards.

Inspect it any time:

```bash
curl -k -b cookies.txt https://<host>/api/history-stats     # size, row counts, oldest data, retention window
```

Every `/api/...` endpoint needs a signed-in session (an unauthenticated call gets `401`); only `/healthz` is open.

Tune with `RETENTION_DAYS`, `RETENTION_INTERVAL_SECS`, `DASHBOARD_DB_FILE` (see `.env.example`). The DB is gitignored.

### Security tab

**Checklist.** Each entry is looked for on the selected node over NITRO (read-only): by its usual policy name or, when renamed, by what its rule does. The badge says what was found - *In place*, *Partly* (for example a policy that is not bound, a feature that is off, a log action that does not exist), *Not found*, or *Could not check* (the NITRO user may not read that object, or the build does not have it). Mark an entry **Done** or **Not relevant** yourself; marks are kept per instance (`security_checklist.json`, also copied to an external database). **Excel** and **PDF** export the checklist - every entry with what was detected, your mark (who and when), what counts towards the score, and what was found. Clicking an entry shows what it does, what to watch out for, and the commands for the node's version, filled in with the instance's Gateway virtual server, the node address and this dashboard's address. The entries live in `security_catalog.py`.

**Activity.** Hit counters come from the NetScaler (they are the appliance's own totals; the trend is sampled every `SECURITY_POLL_SECS` while the dashboard runs). Event details - WAF violations, brute-force blocks, hijack resets, failed logins, and the Gateway session lines the Sessions tab uses - come from the appliance's log:

- **Syslog (recommended)**: point a syslog server at the dashboard (the checklist entry *Send logs to this dashboard* has the commands). It listens on **UDP and TCP 514** (`SYSLOG_PORT`) and accepts messages only from the address of a node configured in Settings; if the NetScaler sends from another address (a SNIP), add it with `SYSLOG_EXTRA_SENDERS=address=instance id`. Senders that were refused are listed on the tab. `set appfw settings -CEFLogging ON` gives every field of a WAF violation.
- **Without syslog** the dashboard reads the appliance's last 256 audit lines every minute; violations that scroll past in between are not seen.

Events are kept like the other history: `RETENTION_DAYS`, at most `SECURITY_MAX_EVENTS` (default 200,000), in the external database when one is connected.

### External database

**Settings → Database** connects the dashboard to a database server of your own. Supported: **PostgreSQL**, **MySQL / MariaDB** and **Microsoft SQL Server**, entered as server / port / database / user / password or as one connection URL.

What goes into it:

| | Tables | Notes |
|---|---|---|
| Session history | `nsd_sessions` | one row per session, same retention as the built-in store |
| Failover history | `nsd_failover_events` | |
| A copy of the settings | `nsd_settings` | instances (**including NetScaler passwords**), the admin login (hash), LDAP settings, last HA state |

Not stored there: the TLS certificate and its CA, the session secret, and the database connection itself — those belong to one appliance.

- **Prepare an empty database and a user that owns it** (the dashboard creates its three tables itself; it never creates or drops a database). Use a Unicode character set.
- **Test Connection** signs in, creates the tables, writes, reads and deletes a row, and removes the tables again if they were not there before — so a test leaves nothing behind.
- **Restore with the same or a newer release.** The settings copy records its format; a dashboard that is too old for it refuses to load it rather than ending up with a login it cannot check.
- **Connecting moves** this dashboard's existing history into the database. If the database already holds settings from another dashboard you are asked which side wins: *use the settings in the database* (this is how a replacement appliance picks everything up) or *keep this dashboard's settings*.
- **Encryption** has three modes that do exactly what they say: off, encrypt without checking the certificate, or encrypt and verify it (against the public CAs or a CA you paste; verification is not available for SQL Server). Because the settings copy contains NetScaler passwords, use encryption unless the database is on a trusted segment.
- **If the database is unreachable** the dashboard keeps running: sign-in and settings never depend on it, new history is kept in the built-in store, a banner says so, and everything waiting is moved into the database automatically when it answers again.
- **Switching back** to the built-in store copies the history back and leaves the database untouched.
- One dashboard per database: two dashboards writing settings to the same database overwrite each other.

Tested against PostgreSQL 16/17, MySQL 8.4, MariaDB 11 and SQL Server 2022. PostgreSQL is part of the automated release test; the others are run with `tests/test_storage.py` and an end-to-end run before a release that touches the storage layer.

For a self-run container the same can be set with `DATABASE_URL` (e.g. `postgresql://user:password@host:5432/dbname`) and `DATABASE_TLS=off|on|verify`; the Settings section is then read-only. Other knobs: `DB_TABLE_PREFIX` (default `nsd_`), `DB_TIMEOUT_SECS` (default 10).

```bash
python tests/test_storage.py postgresql://user:pw@host/scratchdb mysql://user:pw@host/scratchdb   # storage tests against real servers
```

---

## How the appliance works

```
VM (Debian 13, minimal)
 ├─ ns-dashboard.service   runs the container: host networking, one bind mount (the data dir)
 ├─ ns-upgrade.path/.service   applies an uploaded upgrade - the only thing that talks to Docker
 ├─ ns-console             menu on the VM console: network, hostname, time zone, SSH, web-admin reset
 ├─ ns-issue.service       keeps the address on the console login screen current
 └─ /var/lib/ns-dashboard/data   config, LDAP, history DB, certificates - never part of an upgrade
```

- **No Docker socket in the container.** The web app only validates an uploaded bundle and parks it in the data directory with a `request` flag. `ns-upgrade` on the host re-verifies it (product, version, SHA-256 of every part), loads the new image beside the running one, retags, restarts and polls `GET /healthz`. If the new version is not healthy within 150 s the previous image is retagged and restarted, and the UI reports a rollback.
- **No address clashes.** The container uses the host's network stack and Docker's bridge is disabled, so no `172.17.0.0/16` route exists in the appliance to shadow a NetScaler subnet.
- **Unique per deployment.** The machine-id, SSH host keys, TLS CA/certificate and session secret are all created on first boot or first use — none are shipped in the image.
- **One description of the host layer.** `appliance/host-install.sh` installs `appliance/rootfs/` both when the disk is built and when an upgrade carries newer host files.

### Building and testing a release

```bash
appliance/build.sh         # -> dist/*.ova, dist/*.nsu, dist/SHA256SUMS   (needs only Docker)
appliance/smoke-test.sh    # boots the OVA in QEMU: first sign-in, upgrade by upload, external database, forced rollback, console menu
FROM_OVA=old.ova appliance/smoke-test.sh   # the same, but boots an older release and upgrades it to this build
```

Pushing a tag `vX.Y.Z` that matches `VERSION` runs both in GitHub Actions and publishes the files as a GitHub Release (`.github/workflows/release.yml`). The base image is the official Debian 13 cloud image, verified against Debian's published SHA-512. The disk is written with VMware's [open-vmdk](https://github.com/vmware/open-vmdk) (pinned to a commit): VMware's importer rejects a stream disk written by `qemu-img` with a manifest checksum error, even though the file is intact.

### Upgrade bundle format (`.nsu`)

A plain tar: `manifest.json` (product, version, SHA-256 of each member), `image.tar.gz` (the container image) and `host.tar.gz` (`host-install.sh` + `rootfs/`). Bundles are integrity-checked, not signed: only install files from this project's releases, and compare against `SHA256SUMS`.

---

## Running the container yourself (development)

The appliance is the supported way to run the dashboard. The same image runs directly under Docker or Python for development; upload upgrades are an appliance feature, so a self-run container is upgraded from its host (`upgrade.sh` / `upgrade.bat`).

### Check dependencies first (optional)

A read-only preflight script reports anything missing on your machine — Docker, the Docker
daemon, Compose v2, Git (or Python 3.9+/pip for the source install), plus whether ports 443/80
are free — and prints a download link for each gap:

```bash
./preflight.sh            # Linux / macOS  (add 'python' to check the source install)
```
```bat
preflight.bat             :: Windows
```

It installs nothing and changes nothing; it exits non-zero if a required dependency is missing.

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

- `GET  /healthz` — unauthenticated liveness + version (polled by the appliance's upgrade agent)
- `GET  /api/appliance/status` — running version, appliance mode, and upgrade progress
- `POST /api/appliance/upgrade` — upload an `.nsu` bundle (appliance only; raw request body)
- `GET  /api/caps` — per-node API capability + deployment mode
- `GET  /api/sdx/overview` — an `sdx` instance: platform, hardware health, license, its NetScaler instances
- `GET  /api/system-stats?node=primary|secondary`
- `GET  /api/ha-status` — HA nodes (or cluster members in cluster mode)
- `GET  /api/lb-vservers?node=...` / `GET /api/services?node=...` (NITRO)
- `GET  /api/failover-history` · `GET /api/user-sessions?node=...` · `GET /api/session-ica?user=...`
- `GET  /api/security/checklist?node=...` — the checklist with what was found on the node (`fresh=1` reads it again)
- `POST /api/security/mark` — `{ "id": "epa_referer", "state": "done" | "irrelevant" | "" }`
- `GET  /api/security/activity?range=1h|24h|7d` — counts, charts, policy hit counters, syslog receiver state
- `GET  /api/security/events?range=...&kind=...&q=...` — the events, newest first
- `POST /api/unlock-user` — `{ "node": "primary", "username": "user1" }`
- `GET/POST /api/settings` — read/update nodes + mode
- `GET  /api/database` — where data is stored, connection state, row counts
- `POST /api/database/test` — try connection settings without changing anything
- `POST /api/database` — connect an external database (`settings_from: local|database` when it already holds settings) or `{ "type": "builtin" }` to go back
- `POST /api/tls-cert` — replace the TLS cert (`{ "cert": "...PEM...", "key": "...PEM..." }`; key optional after a CSR)
- `GET  /api/tls-ca` — download the local CA certificate
- `POST /api/tls-csr` — generate a CSR (`{ "common_name": "..." }`)

---

## TLS certificates

On first boot the app generates a **local CA** (`certs/ca.crt` / `certs/ca.key`) and issues a server cert signed by it. Three ways to get trusted HTTPS, all under **Settings → TLS Certificate**:

1. **Install the local CA** — click *Download CA Certificate* and add it to each client's trust store (Windows: *Trusted Root Certification Authorities*; browsers may have their own store). The built-in certificate names this host: its host name and every address it has (so the address shown on the appliance console validates), plus anything in `TLS_SAN`. It is issued again by itself at the next start when those change, and before it expires.
2. **Upload your own** cert + key (PEM). It is checked first — a pair the server could not actually serve (half-pasted chain, weak key, expired, a CA certificate) is refused — and then used for new connections straight away; the previous pair is kept as `*.prev`.
3. **Generate a CSR** — enter the host name (and any extra names), click *Generate CSR*, have it signed by your corporate CA, then upload the signed certificate (leave the key field blank — the matching key stays on disk).

If HTTPS ever stops working, the appliance console has **New web certificate**, which goes back to a fresh certificate from the local CA.

## Running behind a reverse proxy

`deploy/nginx.conf` + `deploy/docker-compose.proxy.yml` terminate TLS at nginx and proxy to the app over internal HTTP:

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.proxy.yml up -d --build
```

This runs the app with `APP_SSL=0`, `APP_PORT=8080`, `TRUST_PROXY=1` (so it honors `X-Forwarded-Proto` for redirects, and marks the session cookie `Secure`) and publishes 443/80 from nginx. `gunicorn.conf.py` binds plain HTTP when `APP_SSL=0`, so nginx alone terminates TLS. Put a cert/key in `./certs` (a prior default run generates one, or drop your own).

## Versioning

`major.minor.patch`, starting at `1.0.0`. A small change/fix bumps the patch (`1.0.0 → 1.0.1`); a significant change/feature bumps the minor and resets patch (`1.0.0 → 1.1.0`). Each release is tagged `vX.Y.Z`; see [CHANGELOG.md](CHANGELOG.md).

## Security

- HTTPS-only on 443; CA-signed cert out of the box, replaceable from Settings.
- Response headers: HSTS (on HTTPS), CSP (the dashboard's own origin only), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- Secrets live in gitignored files (`nodes_config.json`, `ldap_config.json`, `db_config.json`, `auth_config.json`, `.env`, `.app_secret`, `certs/`); never commit them.
- Sign-in: the admin password is at least 8 characters and stored as a salted hash; five wrong attempts from one address lock that address out for five minutes (`LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECS`). A damaged login file closes local sign-in instead of falling back to the default password — reset it from the appliance console.
- NetScaler credentials are only ever sent to the configured node: redirects are not followed, and a stored password is not reused when a node's address or user is changed.
- The upgrade agent on the appliance (root) never writes through a name inside the dashboard's data directory and works on a private copy of the uploaded file.
- The Content-Security-Policy allows no other host - the UI's libraries and fonts are bundled (see *Third-party components*). It still allows inline scripts, because the UI uses inline handlers.
- The local admin password is stored as a salted, deliberately slow hash (scrypt via Werkzeug; PBKDF2-SHA256 if scrypt is unavailable) and checked in constant time. Hashes from 1.16.0 and earlier are upgraded on the next sign-in.
- Session cookies are HttpOnly + SameSite=Lax + Secure. The session secret is random and persisted to `.app_secret`.
- Restrict access to NetScaler management networks (firewall / allowlist).
- An external database receives a copy of the settings, **including NetScaler passwords** as stored on the appliance. Give the dashboard its own database and account, restrict who can read it, and encrypt the connection.

---

## Troubleshooting

- **Applications tab empty:** node doesn't support Next-Gen (cap bar shows `nitro`) — you'll see LB vServers/Services instead.
- **No failover/sessions:** check the selected date range; empty windows are normal.
- **TLS warning in browser:** expected with the default self-signed cert; upload a trusted cert from Settings.
- **Cluster shows no nodes:** confirm `primary` points at the CLIP and NITRO is reachable there.

---

## Third-party components

The appliance image contains Debian, Docker and the Python packages in `requirements.txt` (Flask, SQLAlchemy, requests, cryptography, ldap3, gunicorn, pg8000, PyMySQL, and pymssql with its bundled FreeTDS), each under its own license. The disk image is written with VMware's open-vmdk.

The web UI's browser libraries and fonts are bundled in `static/vendor` and served by the dashboard itself, so the administrator's browser needs no internet access: Tailwind CSS 3.4.17 (MIT), Chart.js 4.5.1 (MIT), SheetJS 0.18.5 (Apache-2.0), jsPDF 2.5.1 with AutoTable 3.8.2 (MIT), and the Inter and JetBrains Mono fonts (SIL Open Font License 1.1). Each is the published file; `static/vendor/README.md` lists where it came from, `static/vendor/SHA256SUMS` its checksum, and `static/vendor/licenses/` the license texts.

NetScaler and Citrix are trademarks of Cloud Software Group, Inc. This is an independent project; it is not affiliated with, endorsed by or supported by Cloud Software Group.

## License

MIT — see [LICENSE](LICENSE).
