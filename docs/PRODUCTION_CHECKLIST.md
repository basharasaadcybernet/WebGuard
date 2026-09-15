# WebGuard Controlled Beta Production Checklist

No public deployment is part of Phase 10. Complete and record this checklist for the exact release
candidate and hosting environment before controlled beta exposure.

## Identity and TLS

- [ ] Public domain replaces every `.invalid` placeholder.
- [ ] DNS records point only to the intended ingress.
- [ ] HTTPS certificate is valid, automatically renewable, and covers the exact hostname.
- [ ] Plain HTTP redirects to HTTPS without accepting scan requests.
- [ ] HSTS is enabled at the TLS edge only after HTTPS is confirmed.

## Application configuration

- [ ] `WEBGUARD_ENV=production` is set.
- [ ] `WEBGUARD_DEBUG=false` and API documentation exposure is an explicit decision.
- [ ] `WEBGUARD_ALLOWED_HOSTS` lists only exact public hostnames and contains no wildcard.
- [ ] Same-origin uses an explicit empty `WEBGUARD_CORS_ORIGINS`, or separate-origin lists only the
  exact HTTPS frontend origins.
- [ ] `WEBGUARD_TRUSTED_PROXIES` lists only direct proxy IPs/CIDRs, or is empty.
- [ ] No secret exists in `.env`, an image layer, frontend `VITE_*` values, or repository history.
- [ ] Production configuration validation succeeds and unsafe test values fail startup.

## Proxy and ingress

- [ ] The API port is private; only the reverse proxy can reach it.
- [ ] Proxy Host validation matches the backend allowlist.
- [ ] Forwarded headers are overwritten by the trusted proxy, not appended from client input.
- [ ] External rate limiting returns 429 and connection saturation returns 503.
- [ ] Request body limit is 4 KiB or lower and proxy/API limits are aligned.
- [ ] Proxy connect/send/read timeouts are bounded and the read timeout exceeds the API deadline.
- [ ] `/api/` responses use `Cache-Control: no-store`; no shared API cache is configured.

## Resource and network security

- [ ] Concurrent-scan and scan-timeout values are load-tested without raising safety limits.
- [ ] CPU, memory, PID, file-descriptor, and connection limits are configured.
- [ ] Backend runs as non-root with dropped capabilities and `no-new-privileges`.
- [ ] Runtime filesystem is read-only except reviewed temporary paths.
- [ ] No Docker socket, privileged mode, host networking, or unnecessary volume is present.
- [ ] Outbound egress permits required public DNS and HTTP/HTTPS only.
- [ ] LAN, private, link-local, metadata, cluster/service, and host-management destinations are
  denied independently of WebGuard's SSRF validation.
- [ ] The deployment resolver and routing policy cannot silently expose private services.

## Browser and response policy

- [ ] Static frontend was built with the intended public `VITE_*` values.
- [ ] Production bundle contains no source maps, credentials, development API URL, analytics, or
  unexpected third-party scripts.
- [ ] CSP works for the actual frontend and permits no unnecessary external origin.
- [ ] HSTS, `nosniff`, referrer, framing, and Permissions Policy headers are verified over HTTPS.
- [ ] Hashed assets are long-cacheable while `index.html` is revalidated.

## Operations

- [ ] External rate limiting and abuse controls are configured at the edge/CDN/proxy.
- [ ] Correlation-aware logs exclude URLs with query secrets, headers, bodies, cookies, credentials,
  raw exceptions, IP/socket internals, and tracebacks.
- [ ] Log destination, access control, retention, rotation, and deletion are approved.
- [ ] `/api/v1/health` is monitored without making an external scan.
- [ ] Graceful shutdown, cancellation, 429, 503, and 504 behavior are smoke-tested.
- [ ] Backup/recovery requirements are evaluated; v0.1 has no persistent application data.

## Release evidence

- [ ] Full pytest, security/API tests, Ruff, strict mypy, `pip check`, and clean wheel build pass.
- [ ] `npm ci`, frontend tests, TypeScript, ESLint, and production build pass.
- [ ] Python and npm audit findings are reviewed; major upgrades are not applied automatically.
- [ ] Backend and frontend images/configuration validate under the target container engine.
- [ ] Reviewed image digests and resolved Python dependencies are recorded for this release.
- [ ] Authorized public smoke test passes through HTTPS using the deployed frontend and API.
- [ ] Rollback owner, previous image/config pair, trigger, and procedure are recorded.
- [ ] No cloud account, DNS, server, registry push, or public deployment occurred before approval.
