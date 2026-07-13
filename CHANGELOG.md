# Changelog

Versioning: **major.minor.patch**, starting at `1.0.0`.
- **Patch** (small change / fix): bump the last digit — e.g. `1.0.0 → 1.0.1`.
- **Major** (significant change / new feature): bump the middle digit and reset patch — e.g. `1.0.0 → 1.1.0`.

Each release is tagged in git as `vX.Y.Z`.

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
