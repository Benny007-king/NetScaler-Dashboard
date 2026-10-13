# Changelog

Versioning: **major.minor.patch**, starting at `1.0.0`.
- **Patch** (small change / fix): bump the last digit — e.g. `1.0.0 → 1.0.1`.
- **Minor** (significant change / new feature): bump the middle digit and reset patch — e.g. `1.0.0 → 1.1.0`.

Each release is tagged in git as `vX.Y.Z`.

## 1.16.3
A release of fixes from a full QA pass (security, robustness, appliance, docs).

**Security**
- **Upgrade agent (appliance).** The agent runs as root and used to write its
  status through a file name inside the dashboard's data directory; a link
  planted there made root overwrite any file on the appliance. It now works from
  inside the real directory, renames finished files into place and installs from
  a private copy of the upload.
- **Script injection.** A virtual server's port and state, and an HA node's
  state, were written into the page without escaping - a NetScaler object could
  run script in the administrator's browser. Every value from an appliance is now
  text. The content security policy no longer allows `eval`.
- **Credentials stay where they belong.** NITRO / Next-Gen calls never follow a
  redirect (the credentials would have gone with it). A stored NetScaler or
  database password is only reused for the address and user it was entered for:
  changing the address with the password left blank now asks for it again
  instead of sending it to the new address.
- **Admin login.** A damaged `auth_config.json` (a crash or a full disk while it
  was being written) used to reset the login to `admin` / `admin`; now local
  sign-in stays closed until it is reset on purpose from the console. Five wrong
  attempts from one address lock that address out for five minutes. Passwords
  need 8 characters and cannot be the current, default or an obvious one.
  Logging out needs a POST, so a link elsewhere cannot do it.
- **LDAP allowed group.** A group given as a full DN means exactly that group;
  before, any group with the same name in another OU or domain was accepted.
- **Certificate upload.** An uploaded certificate is loaded with the TLS library
  before it replaces the working one, so a half-pasted chain or a weak key can no
  longer take HTTPS down; expired, not-yet-valid and CA certificates are refused,
  and the previous pair is kept. The console has **New web certificate** as a way
  back.

**Robustness**
- **Settings files are written atomically.** A full disk or a power cut can no
  longer leave an empty file; a damaged `nodes_config.json` no longer stops the
  dashboard from starting (it is kept as `.corrupt`).
- **Unreachable NetScalers no longer block the dashboard.** Start-up does not
  wait for them (40 dead nodes: 5 s instead of over 200 s, which could make an
  upgrade roll back); a node that stopped answering is left alone for a few
  seconds; background refreshes do not pile up. Three tabs on a dead HA pair used
  to make sign-in time out.
- **Failover history.** One failover is recorded once (it could be recorded five
  times with several tabs open); state is kept per instance, so two deployments
  using the same management addresses no longer produce endless false events.
- **Sessions.** One unreadable row no longer drops the whole list; two sessions
  of one user without a session key are kept apart; the audit-log parser handles
  non-ASCII user names, ignores App Firewall lines and never shows `nsroot`.
- **External database.** A row the server refuses (a NUL byte, for example) is
  skipped instead of marking the database unreachable for good; history is moved
  in steps without holding requests up (PostgreSQL: several times faster);
  settings from another dashboard are validated before use; an older dashboard
  no longer overwrites settings saved by a newer one; a damaged connection file
  is reported instead of silently ignored.
- **Built-in certificate.** It names the appliance's host name and addresses (so
  the address shown on the console validates once the CA is installed), follows
  `TLS_SAN` changes, and is renewed before it expires.
- Bad values in the settings file (text where a number belongs, quotes) no
  longer stop the start; `GUNICORN_WORKERS` is ignored (more than one worker
  broke sign-in); an unknown instance or node in a request is an error instead of
  silently meaning the first one; API calls without a session get 401.
- **Unlock user** reports success only when the appliance confirms it, shows the
  appliance's own reason otherwise, and logs who unlocked whom.

**Appliance and release**
- Console menu: leaves when its input ends (it used to spin), refuses addresses
  that cannot work (leading zeros, loopback, a gateway outside the subnet) and
  says when a static address did not take effect.
- Release workflow: upgrades from the newest *older* release, fails if that
  cannot be determined, and never publishes from a manual run. The boot test now
  proves the static-address step and that the OVA manifest covers the disk.

**Known, not changed in this release**
- The page still needs inline scripts, and loads its styling and chart
  libraries from public CDNs (a browser without internet access shows it
  unstyled).
- A response that trickles in slowly can still hold a request for as long as the
  appliance keeps sending.

## 1.16.2
- **SQL Server is now tested.** The external database feature was run end to end
  against Microsoft SQL Server 2022 (storage tests and the real dashboard:
  connect, encryption on and off, an outage and recovery, a restart, restoring
  a second dashboard). Two things that turned up are fixed:
  - Session ids and failover keys now compare **case-sensitively** on SQL Server,
    as on every other backend; before, two sessions whose ids differed only in
    case were stored as one. Tables created by 1.16.0 / 1.16.1 keep the old
    behaviour - to rebuild them, switch to the built-in store, drop the three
    `nsd_` tables and connect again.
  - SQL Server errors are shown as one readable line ("Login failed for user
    ...") instead of the driver's multi-line dump.
- **Settings from a newer dashboard are never loaded by an older one.** The copy
  of the settings in an external database now records its format. Choosing
  "use the settings in the database" on a dashboard that is too old for them is
  refused with an explanation, instead of leaving an admin login it cannot
  check. (Releases before 1.16.2 do not have this check: when restoring, use an
  appliance at least as new as the one that saved the settings.)
- The "database already holds settings" prompt shows which version saved them.
- Building the image from a folder that contains another checkout (and its
  `dist/`) no longer copies those release files into the image.

## 1.16.1
- **Stronger storage of the admin password.** The local admin password is now
  kept as a salted **scrypt** hash (PBKDF2-SHA256 where Python has no scrypt)
  instead of an unsalted SHA-256 digest, so reading `auth_config.json` - or the
  copy of the settings in an external database - no longer allows fast offline
  guessing. Password checks compare in constant time.
- **Nothing to do on upgrade.** A password stored by an earlier release still
  signs in, and is re-stored in the new format on that first successful sign-in.
  The default `admin` / `admin` login and its forced change work as before.
- Once a password has been re-stored, a release older than 1.16.1 can no longer
  check it: upgrade every dashboard that shares an external database, and after
  going back to an older release reset the admin password (console menu, or
  delete `auth_config.json` and restart).
- New `tests/test_auth.py` covers the default login, the forced change and
  sign-in with a hash from an earlier release.

## 1.16.0
- **External database.** New **Settings -> Database**: keep the dashboard's data in
  your own **PostgreSQL, MySQL / MariaDB or Microsoft SQL Server** instead of the
  built-in store. It holds session and failover history plus a copy of the
  settings (instances, admin login, LDAP, HA state), so a replacement appliance
  can be pointed at the database and pick everything up. Connect by server /
  port / database / user or by a connection URL; **Test Connection** proves the
  settings work and leaves nothing behind. Encryption can be off, on, or on with
  certificate verification (a CA can be pasted).
- **Built to survive the database being down.** Sign-in and settings never wait
  for it. During an outage new history is kept on the dashboard, a banner says
  so, and everything waiting is moved into the database when it answers again.
- Connecting moves existing history into the database; switching back copies it
  back. If the database already holds another dashboard's settings you choose
  which side wins - nothing is overwritten silently.
- The storage layer now runs on SQLAlchemy for both the built-in SQLite file and
  external servers; database files from earlier releases are used as they are.
  New `tests/test_storage.py` runs the storage tests against real servers.
- **Release tests.** The appliance boot test now also connects the appliance to a
  PostgreSQL server over TLS, stops and restarts it, and - new - upgrades the
  *previous release's* appliance with this release's upgrade file.
- SQL Server support is implemented but has not been run against a real server
  yet; PostgreSQL, MySQL and MariaDB are tested end to end.

## 1.15.0
- **Virtual appliance.** The dashboard now ships as an **OVA**: a minimal Debian 13
  virtual machine with Docker and the dashboard pre-installed, for VMware ESXi /
  Workstation / Fusion and VirtualBox. Import it, power it on, and browse to the
  address shown on its console (the screen follows address changes, and says so
  when there is no address yet) - nothing is installed on a host. A console menu
  (`nsadmin`) sets a static address, the hostname and SSH access, restarts the
  dashboard and resets the web admin password. The container uses host networking
  with Docker's bridge disabled, so no `172.17.x.x` route can shadow a NetScaler
  subnet; machine-id, SSH host keys and TLS material are generated per appliance.
- **Upgrades by upload.** A release is also published as a single **`.nsu`** file,
  uploaded in the new **Settings -> Software & Upgrade** section. The dashboard
  validates it (product, version, checksums; older versions are refused) and
  hands it to a host-side agent - the container never gets the Docker socket. The
  agent verifies it again, loads the new image beside the running one, restarts
  and health-checks it, and **rolls back automatically** if the new version does
  not come up. Configuration, history and certificates are not part of the swap.
- **The app knows its version.** Shown next to the logo and in Settings; new
  `GET /healthz` (liveness + version) and `GET /api/appliance/status`.
- **Release pipeline.** `appliance/build.sh` builds the OVA and the bundle with
  nothing but Docker; `appliance/smoke-test.sh` boots the OVA in QEMU and tests
  first sign-in, an upgrade by upload, a forced rollback and the console menu
  (over the serial port). The disk is written with VMware's open-vmdk so that
  VMware's importer accepts the OVA's checksum manifest. A pushed tag runs both
  in GitHub Actions and publishes the files as a GitHub Release with `SHA256SUMS`.
- The Docker / Python instructions remain for development, but the appliance is
  now the supported way to install and upgrade.

## 1.14.0
- **Preflight dependency check.** New `preflight.sh` (Linux/macOS) and
  `preflight.bat` (Windows) verify everything needed *before* the first install
  and print a download link for whatever is missing: Git, Docker, the Docker
  **daemon actually running**, Compose v2 — or Python 3.9+/pip with
  `preflight.sh python` for the source install — plus a warning if ports 443/80
  are already taken. Read-only (installs and changes nothing) and exits non-zero
  when a required dependency is absent, so it can gate a scripted setup.
- **Per-OS dependency guide on the docs site.** A new
  [Before you install](https://net-scaler-dashboard-web.vercel.app/docs.html#deps)
  section lists every dependency for **Windows / macOS / Linux**, split by install
  route (Docker vs from source), each with what it's for and a verified download
  link — including WSL 2, the Compose v2 plugin, Docker's non-root post-install
  step, and Docker Desktop alternatives (Rancher, Podman, OrbStack, Colima). The
  page preselects the visitor's OS.

## 1.13.0
- **Fix: Applications failed to load on a Next-Gen node.** The page requested
  `/api/applications` whenever a node was in Next-Gen mode — **a route that never
  existed**, so the tab always showed "Failed to load". It now uses the one
  endpoint that serves both stacks. And when Next-Gen reports **no** applications
  (common: the appliance runs Next-Gen but its config is still classic LB
  vServers), the dashboard **falls back to NITRO** instead of showing an empty
  table, so those vServers finally appear.
- **Fix: every service showed `UNKNOWN`.** Services report their runtime state in
  NITRO's `svrstate` field, but the table read `curstate` (which only exists on
  vServers), and it read `ip` where a service exposes `ipaddress`. Both now use
  the correct fields with fallbacks, so services show their real UP / DOWN /
  OUT OF SERVICE state and address.
- **Service groups are shown.** The backend had always returned them and the
  table silently ignored them; they now appear as `GRP` rows with their effective
  state and bound-member count. Services and service groups are also read over
  NITRO on Next-Gen nodes (they're NITRO objects), instead of returning empty.
- **Tabs follow the live primary.** Applications, Failover, Sessions,
  Certificates and Unlock User now open on the node that currently holds the
  **PRIMARY** role — reported by the new `primary_node` field in `/api/caps` —
  rather than whichever node happened to be selected. After a failover the tabs
  follow the new primary automatically. Overview still honours the node picker so
  you can inspect either node.

## 1.12.2
- **API capability is re-checked automatically; the "Re-detect API" button is
  gone.** A node's capability was decided once at startup, so a node that was
  briefly unreachable at boot stayed marked NITRO forever — even after the
  Next-Gen API was enabled and working on it. Detection now re-runs in the
  background every `API_DETECT_INTERVAL_SECS` (default **600s**, `0` disables),
  so it corrects itself with no restart and no button to press.
- **No real IP addresses in the repo or on the website.** The README example
  config and the site's HA preview used actual lab addresses; both now use the
  RFC 5737 documentation range (`192.0.2.x`), matching
  `nodes_config.example.json`. Appliance addresses belong in your (gitignored)
  config, never in committed files.

## 1.12.1
- **Sessions are AAA/gateway only — management logins are gone.** The audit-log
  parser matched *any* login event, so admin-plane activity (`API/CLI/GUI
  CMD_EXECUTED`, `SSHD` logins, role-based-auth messages for `nsroot`/`nsapi`)
  showed up as session rows. Management-plane lines are now skipped, and any
  account that exists as a **system user** on the appliance is excluded by name,
  so only real end-user AAA/gateway events (e.g. `SSLVPN` / `AAATM` login
  failures and lockouts) are listed. Rows are labelled `AAA login` / `AAA lockout`.
- **Legacy management rows are purged from history.** Builds 1.9.0–1.12.0 stored
  `Management` / `Mgmt login` / `Mgmt lockout` rows, which lingered for the 7-day
  retention window even after the feature was removed. They're now deleted on
  startup, so the tab is clean immediately rather than a week later.

## 1.12.0
- **Service / Application status colours now reflect the real state.** The tables
  coloured anything containing `UP` green and everything else red, so
  **PARTIAL-UP showed as healthy green** and **OUT OF SERVICE showed as a red
  failure**. States are now classified properly: `UP` green, `DOWN` red, and
  `OUT OF SERVICE`, `GOING/TRANSITION TO OUT OF SERVICE`, `PARTIAL-UP`,
  `DISABLED` and `UNKNOWN` in amber (the same warning colour as a forced HA
  mode). An unrecognised state is amber rather than falsely green.
- **Fix: the Next-Gen API was never used, even on 14.1 with it enabled.** Two
  causes: (1) the Next-Gen client did **not** mount the legacy-cipher TLS adapter
  that NITRO got in 1.4.0, so its login failed the same OpenSSL handshake that
  broke NITRO over 443; and (2) capability detection only ran **at startup and on
  settings save**, so enabling Next-Gen on the appliance afterwards was never
  noticed. Every failure was also swallowed silently, leaving no way to tell why.
- **Detection is now explainable and re-runnable.** `/api/caps` reports *why* each
  node is on its API mode, the capability line shows it on hover (and turns green
  for Next-Gen), and a **Re-detect API** button re-runs detection live — no
  restart. New `POST /api/detect-api` and `GET /api/nextgen-debug` (appliance
  version, which management paths answer, and the real login error). The
  management path is overridable via `NEXTGEN_BASE_PATH`.

## 1.11.0
- **All-instances health wall.** A new **All Instances** tab shows every configured
  deployment as a status card — overall state (**Operational / Degraded /
  Unreachable**), how many nodes are up, and per node the hostname, IP, HA role,
  HA status and live CPU/memory. Forced HA modes and unreachable nodes are called
  out as warnings on the card. **Click a card to open that instance** and land on
  its Overview; the instance switcher follows along. With more than one instance
  the wall is the landing view (a single instance goes straight to its dashboard).
- Backed by **`GET /api/instances-health`**, which probes every instance *and*
  every node **in parallel**, so the wall stays fast with a large fleet; the
  node picker is hidden on the wall, and the wall auto-refreshes on a slower
  cadence (15s) than the per-node Overview since each pass touches the whole fleet.

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
