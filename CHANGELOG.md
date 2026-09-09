# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-10

### Added

- **More reverse proxies.** A new status-only `/authz` endpoint for nginx
  `auth_request` — it answers `200` or `401` (never a redirect), and nginx does
  the redirect to the gate itself with `error_page`. Example configs for nginx
  and Envoy `ext_authz` join the existing Traefik one. Traefik, Caddy and Envoy
  use `/auth` (the `302`); nginx uses `/authz`. Both endpoints share one verdict,
  and both accept a trailing path prefix so Envoy's `path_prefix` works. A new
  [Reverse proxies](README.md#reverse-proxies) section explains which endpoint
  each proxy uses. Examples:
  [`deploy/nginx/kalitka.conf`](deploy/nginx/kalitka.conf),
  [`deploy/envoy/kalitka.yaml`](deploy/envoy/kalitka.yaml).

### Changed

- Internal refactor: `GateService` split into `ApprovalEngine` (the decision
  core, free of HTTP and Telegram), `INotifier`/`TelegramNotifier` (the Telegram
  face), and a thin `GateService` facade. No behaviour change — it makes room for
  more proxies and other notifiers without reopening the core.

## [0.2.1] - 2026-09-09

### Added

- **Test suite** (25 tests) covering the security-critical paths: forged and
  proxied `X-Forwarded-For`, cookie tampering / expiry / secret rotation, the
  `/auth` decision for armed, unarmed and bypass cases, the 401-vs-redirect
  split for sub-resources, wrong webhook secret, non-admin callback, and
  callback replay against resolved and expired requests. Time is injected via
  `TimeProvider`, so the time-based tests are deterministic.

### Changed

- `TelegramClient` now sits behind `ITelegramClient`, and `GateService` takes a
  `TimeProvider` — both to make the above testable, no behaviour change.

### Fixed

- **Sub-resources without a session now get `401`, not a redirect.** A `302` to
  the gate's HTML page is only meaningful to a top-level navigation. A WebSocket
  handshake cannot follow it, an XHR/fetch reads the HTML as its payload, and a
  single-page app behind the gate hung on a blank screen. The request kind is
  read from the browser's Fetch Metadata (`Sec-Fetch-Mode`; `Accept` as a
  fallback for older clients): only a real navigation is redirected, everything
  else fails cleanly with `401`. This is the "Single-page apps and a redirect
  gate" caveat, turned from a caveat into correct behaviour.
- `appsettings.json` carried JSON "comment" keys under `Logging:LogLevel` whose
  values were parsed as log levels and threw on first use. Removed; the tests
  caught it.

### Dependencies

- Adopted the safe GitHub Actions bumps (checkout, setup-dotnet, login,
  metadata, build-push). Major bumps of the .NET base images are held back and
  ignored by Dependabot — that is a runtime baseline change, done deliberately.

## [0.2.0] - 2026-09-09

First public release. The product is already whole — Telegram approval, allow
and block lists, optional Google sign-in, per-host arming, mute, session
control — so it ships now rather than waiting for thirty more features.

Not yet here: an automated test suite (tracked in the issues) and per-host
isolation of the Google session (see Known limitations).

### Added

- **Trusted proxies.** `TrustedProxies` (CIDR list) decides whether forwarded
  headers are believed at all. Requests that did not arrive from one of these
  are judged on the address the connection actually came from.
- **Rate limiting.** A sliding window per address (`MaxRequestsPerIp`,
  `RateWindowMinutes`) and a ceiling on requests waiting for an answer
  (`MaxPending`). Over the limit the door stays silent — the same answer a
  blocked caller gets, so there is nothing to learn from it.
- **Audit log.** One structured line per decision: request id, host, client
  address, identity, admin and reason. Secrets, tokens and cookie values are
  never logged.
- **`/allow` and `/block`.** Fill either list before anyone rings, instead of
  only being able to react to a request.

### Changed

- **`X-Forwarded-For` is read from the right**, past known proxies, instead of
  taking the leftmost entry. A proxy only ever appends on the right; everything
  to the left is whatever the caller wrote. Reading it the obvious way let a
  visitor choose their own address — and with it their own place on the allow
  list.
- **Redirect targets must be a currently guarded host**, not merely a name under
  the same domain. A forged `Host` header could otherwise steer visitors to a
  name that was never guarded.
- **Telegram callbacks expire.** A decision was already terminal after the first
  press; now the request also has to still be within its lifetime, so an old
  button cannot resurrect one.

### Security

- Startup refuses `BypassNetworks` without `TrustedProxies`. Behind a proxy every
  visitor would otherwise appear to come from the proxy, and a bypass range
  containing that address would wave everyone through while the configuration
  looked entirely correct.

### Known limitations

- A Google sign-in grants a session for every guarded host under the cookie
  domain. Manual approvals are already per-host. Per-host isolation of the
  Google session is tracked as a feature (one-time hand-off token) and is not in
  this release.

### Upgrading

Set `TrustedProxies` to the range your reverse proxy connects from. For Docker:

```
docker network inspect proxy -f '{{(index .IPAM.Config 0).Subnet}}'
```
