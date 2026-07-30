# Changelog

Versioning: **major.minor.patch**, starting at `1.0.0`.
- **Patch** (small change / fix): bump the last digit — e.g. `1.0.0 → 1.0.1`.
- **Major** (significant change / new feature): bump the middle digit and reset patch — e.g. `1.0.0 → 1.1.0`.

Each release is tagged in git as `vX.Y.Z`.

## 1.6.1
- **Fix: Sessions tab showed the same session on many rows.** History was keyed on
  `(node, user, type, IP, start_time)`, but the start time is derived per poll
  (`now − duration`) and the source IP differs between the VPN and AAA views of a
  session — so a single session fragmented into a new row on every refresh. Rows
  are now keyed on the **stable NITRO session id** (`sessionkey`/`sessionid`, with
  a `user|kind` fallback), so each real session is **one line** that refreshes in
  place. A later poll's blank/`Unknown` IP or gateway no longer overwrites a good
  value already captured. Old-schema session tables migrate automatically on
  startup (the 7-day history rebuilds itself on the next poll).
- **Better gateway resolution.** The gateway/vserver lookup now checks more NITRO
  field names (`authnvsname`, `agname`, `vpnvservername`, `tmvserver`, …), and
  pure AAA/Web sessions — which have no gateway vserver — now read `N/A (AAA)`
  instead of a misleading `Unknown`.

## 1.6.0
- **Fix: LDAP group check for Domain Admins / primary groups.** The allowed-group
  match only looked at `memberOf`, which never contains a user's *primary* group
  (e.g. Domain Admins). It now uses AD **tokenGroups** (covers primary + nested
  groups), looks the group up by CN so an `OU=`/`CN=` or path typo still matches,
  and falls back to a lenient `memberOf` compare for non-AD directories.
- **Persistent data directory / no more re-configuring on updates.** All runtime
  state (config, LDAP, DB, certs, session secret) now lives under `DATA_DIR` on a
  Docker **named volume** (`ns_data`), so `git pull` / image rebuilds never touch
  it. Existing root-level files are migrated in automatically on first start, and
  loaders fall back to the legacy location so nothing is ever lost.
- **Richer Sessions tab.** Columns now show source IP, connection type
  (VPN / Web-Workspace / AAA) and start/end. Clicking a session expands a sub-row
  with the gateway, connection kind, protocol, end resource, intranet IP and
  client OS, plus live ICA/RDP connection detail (`/api/session-ica`) when the
  session is still active.

## 1.5.1
- **LDAP settings UX.** Filling in the LDAP fields and saving without ticking the
  small "Enable" checkbox left `enabled=false`, so the login page kept the LDAP
  button greyed out and it looked like nothing had saved. The Enable control is
  now a prominent labelled row with an **Enabled/Disabled status badge**, and
  saving a configured-but-disabled setup returns an explicit warning telling you
  to tick Enable.

## 1.5.0
- **Local history database.** New `dashboard.db` (SQLite, stdlib — no external
  service) stores **failover events** and **session history**, so those tabs show
  real history instead of only what's currently live on the appliance. Sessions
  are de-duplicated per (node, user, type, IP, start) and flip from `Active` to
  `Terminated` once they stop being seen.
- **Time-based retention.** A background pass runs at startup and hourly,
  deleting anything older than `RETENTION_DAYS` (**default 7**) — at least a
  week of history, and the file can't grow unbounded. Legacy
  `failover_history.json` is imported once on first start. New
  `GET /api/history-stats` reports size, row counts, oldest data and the window.
- **Login: the LDAP option is now always visible.** Previously the
  LOCAL/LDAP switch was hidden entirely until LDAP was configured, so it looked
  missing. It now always renders, with the LDAP button disabled plus a hint
  pointing to Settings → LDAP until it's set up.

## 1.4.1
- **Version-tagged Docker images.** The image is now built as
  `netscaler-dashboard:<version>` (was compose's auto-generated
  `netscaler-dashboard-netscaler-dashboard:latest`) and the version is stamped in
  as an OCI `org.opencontainers.image.version` label plus an `APP_VERSION` env.
  Build with `APP_VERSION=$(cat VERSION) docker compose ... up -d --build`.

## 1.4.0
- **Fix: HTTPS/443 to the NetScaler returned no data.** Appliance management
  interfaces negotiate legacy ciphers (TLSv1.2 + `AES256-SHA`) that OpenSSL 3
  rejects at its default security level, so the connection was reset while
  HTTP/80 worked. NITRO HTTPS calls now use an adapter with `SECLEVEL=1`, and
  `NITRO_VERIFY_SSL` defaults to `0` (appliances use self-signed certs).
- **New Certificates tab** (between Sessions and Unlock User): installed
  certificates with subject/issuer CN, key type/size, expiry countdown and
  status; a visual **certificate chain** view (leaf → intermediate → root) built
  from the appliance's cert links; and a **CRL** table with success/failed
  status. Backed by `GET /api/certificates`.
- **Settings:** choosing HTTPS auto-fills port 443 and HTTP auto-fills 80 — still
  editable by hand.
- **Login:** the auth-source selector is now a two-button switch
  (**LDAP Login** / **Local Admin**) matching the requested design.

## 1.3.1
- **Fix: password change / login not sticking.** Gunicorn ran multiple worker
  processes, each caching its own copy of the auth/config state, so a password
  change saved on one worker wasn't seen by the others and a later login could
  hit a stale worker. Now runs a single threaded worker so in-memory state
  (auth, nodes, LDAP config) is always consistent.
- **Bounded local storage** (no database — data lives in JSON files + stateless
  session cookies). Failover history now self-prunes: at 80% of a 5000-event cap
  it trims back to 50%, keeping the newest events, so `failover_history.json`
  can't grow without bound. The log file (`netscaler_complete.log`) now rotates
  at 5 MB × 3 backups. Both limits are env-configurable.

## 1.3.0
- **Login auth-source selector** — once LDAP is enabled, the login page shows a
  segmented **LOCAL / LDAP · AD** toggle so users pick which backend to
  authenticate against; the choice is honored server-side. The local admin
  account is always reachable via LOCAL to avoid lockout. Purple-accented styling.

## 1.2.0
- **LDAP/AD configuration in the UI** — new Settings → LDAP / Active Directory
  section to enable LDAP and set server, port/SSL, base DN, bind account, user
  attribute, timeout and optional allowed-group DN, with a **Test Connection**
  button. Persists to `ldap_config.json` (gitignored); `LDAP_*` env vars are now
  just defaults. The bind password is never sent back to the browser, and leaving
  it blank keeps the stored one. The local admin account always works.

## 1.1.1
- Fix "Failed to save settings" caused by the idle timeout: real user interaction
  (typing, clicking, mouse movement) now keeps the session alive via a throttled
  `/api/ping` keepalive, so you're not logged out mid-configuration. A truly idle
  session still expires and now redirects cleanly to the login page with a
  "session expired" notice instead of a generic error alert.

## 1.1.0
- **Session inactivity timeout** — logs users out after N minutes of inactivity
  (default **15**), configurable in Settings → Session Timeout. Enforced
  server-side (sliding); background auto-refresh polls don't reset the clock, and
  an expired session redirects to the login page.
- **Faster first load** — the overview now fetches system-stats and HA status in
  parallel, and NITRO calls use a short connect timeout
  (`NITRO_CONNECT_TIMEOUT_SECS`, default 3s) so an unreachable node fails fast
  instead of hanging for the full read timeout.

## 1.0.1
- Security hardening: escape the unlock-result message before inserting it into
  the DOM (removes a self-XSS / defense-in-depth gap flagged in security review).

## 1.0.0
Initial versioned release.

- HTTPS on 443 with a local-CA-signed certificate (auto-generated on first boot),
  replaceable from Settings; CA download and CSR generation supported.
- Local and LDAP/Active-Directory authentication.
- Standalone, HA-pair, and cluster (CLIP) deployment modes.
- Security response headers (CSP, HSTS, X-Frame-Options, etc.) and optional
  reverse-proxy support (`ProxyFix` + nginx example).
- Secret/state files kept out of git; random persisted session secret; secure cookies.
- Dockerised (`netscaler-dashboard`), with a direct-443 and a reverse-proxy compose.
