# Changelog

Versioning: **major.minor.patch**, starting at `1.0.0`.
- **Patch** (small change / fix): bump the last digit — e.g. `1.0.0 → 1.0.1`.
- **Major** (significant change / new feature): bump the middle digit and reset patch — e.g. `1.0.0 → 1.1.0`.

Each release is tagged in git as `vX.Y.Z`.

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
