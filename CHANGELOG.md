# Changelog

Versioning: **major.minor.patch**, starting at `1.0.0`.
- **Patch** (small change / fix): bump the last digit — e.g. `1.0.0 → 1.0.1`.
- **Major** (significant change / new feature): bump the middle digit and reset patch — e.g. `1.0.0 → 1.1.0`.

Each release is tagged in git as `vX.Y.Z`.

## 1.10.0
- **HA status is now shown, including STAYPRIMARY / STAYSECONDARY.** The dashboard
  only read a node's `state` (Primary/Secondary) and ignored NITRO's `hastatus`,
  so *forced* HA modes were invisible — a node pinned with
  `set ha node -hastatus STAYPRIMARY` looked like an ordinary primary even though
  **failover is suppressed**. The HA panel has a new **HA Status** column
  rendering the real code: `Stay Primary (forced)` / `Stay Secondary (forced)`
  (amber, with a ⚠ marker), `Up` (green), and failure states such as
  `Route Monitor Failed`, `Partial/Complete Failure` (red), plus `HA Disabled`,
  `Initializing` and `No Peer`. Unknown codes are shown verbatim rather than
  dropped. The node's Overview panel gained a matching **HA Status** row.
- **Fix: a healthy Secondary was flagged red.** The HA table coloured any state
  that wasn't `UP`/`PRIMARY` as an error, so a perfectly healthy `Secondary`
  showed as danger. Secondary is now blue (normal standby); only genuine
  down/failed states are red.
- **HA panel also shows the node name/hostname** alongside the IP.

## 1.9.2
- **Fix: sessions (and failover events) vanished on days 1–12 of the month.** The
  date-range filter parsed the dashboard's own `DD/MM/YYYY HH:MM:SS` timestamps
  with JavaScript's `new Date()`, which reads them as **US M/D/Y** — so
  `03/08/2026` (3 Aug) became **8 March**, fell outside the default "last 24
  hours" window, and every row was filtered out. On days 13–31 the same string was
  an *invalid* date, which the filter let through — which is why the tab appeared
  to work for most of the month and then emptied. Timestamps are now parsed
  explicitly as day-first, for both the Sessions and Failover filters and for
  display.
- **Fix: audit-log timestamps were in the wrong order.** NetScaler writes
  `MM/DD/YYYY:HH:MM:SS`; Failed/Locked rows now convert it to the dashboard's
  day-first format so they sort and filter correctly.

## 1.9.1
- **Failed/Locked rows now persist** (they were vanishing a moment after appearing).
  They were read live from the audit log, which only holds recent messages — once
  a failed-login line scrolled out of that window it disappeared on the next poll.
  They're now stored in the history DB with an explicit status, so each failed
  attempt (time-stamped, per attempt) and each lockout sticks for the retention
  window (default 7 days).
- **Removed active management sessions from the list.** Listing every live admin
  session (e.g. `nsroot`) was noise. The Sessions tab now shows only what was
  asked for — **Failed** attempts and **Locked** accounts — plus any real
  VPN/AAA sessions.

## 1.9.0
- **Management (system) sessions & logins.** On an LB-only appliance there are no
  Gateway/AAA sessions — the real logins are **management** ones. The Sessions tab
  now lists active admin/API/CLI sessions from `/config/systemsession` (type
  `Management`, shown Active while live, Terminated after logout), so you finally
  see who's connected even without a Gateway configured.
- **Failed logins & lockouts from the audit log.** `Failed` and `Locked` rows are
  now parsed from the appliance **audit log** (`/config/auditmessages`) — the real
  source for management accounts (which aren't in `aaauser`). A failed sign-in
  shows status `Failed`, the attempt time and source IP, with the raw log line in
  the expanded detail; a lockout shows `Locked`. AAA-user lock/fail detection is
  still included for Gateway deployments.
- **`/api/session-debug`** now also dumps `systemsession` and recent
  login-related `auditmessages`, so the failed/locked parser can be tuned to a
  specific build's log format.

## 1.8.1
- **Fix: a node's hostname could blank out on a brief blip.** The header/node
  labels are fetched live from each node; when a node (typically the **secondary**)
  was momentarily unreachable, its name fell back to the generic "Secondary". The
  dashboard now caches the last-known hostname per node and keeps showing it
  through a transient outage.
- **`/api/session-debug` is now a one-shot diagnostic.** It reports, per node,
  **reachability + the hostname NITRO returns** (so the "secondary hostname
  missing" case is obvious), alongside the redacted raw field names for
  `hanode` / `vpnsession` / `aaasession` / `vpnicaconnection` / `aaauser` /
  `systemuser` — everything needed to pin gateway/locked/failed mapping to a
  specific build, in a single page.

## 1.8.0
- **Sessions: failed attempts & locked accounts.** The Sessions tab now also lists
  non-connection events — a **Failed** row (status `Failed`, the attempt time in
  Start, End left blank) and, when an account is locked on the NetScaler, a
  **Locked** row. Both are live appliance state (best-effort from `/config/aaauser`),
  shown on top of the stored session history.
- **Gateway name resolution.** The main session list is now enriched from live ICA
  connections (`/config/vpnicaconnection`), which carry the gateway/vserver name —
  so a session whose own object omitted it (including the AAA placeholder) shows
  the real gateway when the user has an active gateway/ICA connection.
- **New `/api/session-debug`** — a redacted, value-truncated dump of the raw
  `vpnsession` / `aaasession` / `vpnicaconnection` / `aaauser` / `systemuser`
  fields, so session field mapping (gateway, locked, failed) can be pinned to your
  appliance's exact NITRO field names across builds.

## 1.7.1
- **One-command upgrade.** New `upgrade.sh` (Linux/macOS) and `upgrade.bat`
  (Windows) do the whole update: re-attach to `main`, fast-forward to the latest
  release, then rebuild the **version-tagged** image and print what's running.
- **Fix: upgrades could build an old version tag.** The documented
  `git pull && git checkout vX.Y.Z` flow left the repo in *detached HEAD*, where a
  later `git pull` errors — so the working tree (and `VERSION`, which the image tag
  is read from) could stay on the previous release and the rebuilt image came out
  mislabelled. The upgrade scripts use `git checkout main && git pull --ff-only`,
  which always lands on the newest release **and recovers a detached-HEAD
  checkout**. `COMPOSE_FILE` is honored so reverse-proxy deployments upgrade the
  same way.

## 1.7.0
- **Multiple NetScaler instances.** The dashboard now manages many deployments at
  once — e.g. two HA pairs plus three standalones — instead of a single one. An
  **Instance switcher** in the header scopes every tab (Overview, HA, Sessions,
  Certificates, Unlock…) to the selected deployment, and **Settings → NetScaler
  Instances** lets you add/rename/remove instances, each with its own mode
  (standalone / HA / cluster) and node credentials. Config, session history and
  failover history are all keyed per instance. Your existing setup is migrated
  automatically into a single **"Default"** instance on first start — nothing to
  reconfigure. (First half of the multi-instance work; an all-instances health
  wall lands next.)
- **Docs:** clarified HA resilience — with one node of an HA pair down, the
  dashboard keeps polling the survivor (HA status fails over to whichever node
  answers), marks the dead node offline, and still records the failover; a dead
  node fails fast via the ~3s connect timeout rather than hanging.

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
