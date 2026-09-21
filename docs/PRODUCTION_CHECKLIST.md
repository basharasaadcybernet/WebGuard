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

- [x] `WEBGUARD_ENV=production` is set.
- [x] `WEBGUARD_DEBUG=false` and API documentation exposure is an explicit decision.
- [ ] `WEBGUARD_ALLOWED_HOSTS` lists only exact public hostnames and contains no wildcard.
- [x] Same-origin uses an explicit empty `WEBGUARD_CORS_ORIGINS`, or separate-origin lists only the
  exact HTTPS frontend origins.
- [x] `WEBGUARD_TRUSTED_PROXIES` lists only direct proxy IPs/CIDRs, or is empty.
- [ ] No secret exists in `.env`, an image layer, frontend `VITE_*` values, or repository history.
- [x] Production configuration validation succeeds and unsafe test values fail startup.

## Proxy and ingress

- [x] The API port is private; only the reverse proxy can reach it.
- [x] Proxy Host validation matches the backend allowlist.
- [x] Forwarded headers are overwritten by the trusted proxy, not appended from client input.
- [ ] External rate limiting returns 429 and connection saturation returns 503.
- [x] Request body limit is 4 KiB or lower and proxy/API limits are aligned.
- [x] Proxy connect/send/read timeouts are bounded and the read timeout exceeds the API deadline.
- [x] `/api/` responses use `Cache-Control: no-store`; no shared API cache is configured.

## Resource and network security

- [ ] Concurrent-scan and scan-timeout values are load-tested without raising safety limits.
- [ ] CPU, memory, PID, file-descriptor, and connection limits are configured.
- [ ] Production host/cloud ingress firewall exposes only the intended TLS ingress and approved
  administrative access.
- [x] Backend runs as non-root with dropped capabilities and `no-new-privileges`.
- [x] Runtime filesystem is read-only except reviewed temporary paths.
- [x] No Docker socket, privileged mode, host networking, or unnecessary volume is present.
- [ ] Outbound egress permits required public DNS and HTTP/HTTPS only.
- [ ] LAN, private, link-local, metadata, cluster/service, and host-management destinations are
  denied independently of WebGuard's SSRF validation.
- [ ] The deployment resolver and routing policy cannot silently expose private services.

## Browser and response policy

- [x] Static frontend was built with the intended public `VITE_*` values.
- [x] Production bundle contains no source maps, credentials, development API URL, analytics, or
  unexpected third-party scripts.
- [x] CSP works for the actual frontend and permits no unnecessary external origin.
- [ ] HSTS, `nosniff`, referrer, framing, and Permissions Policy headers are verified over HTTPS.
- [x] Hashed assets are long-cacheable while `index.html` is revalidated.

## Operations

- [ ] External rate limiting and abuse controls are configured at the edge/CDN/proxy.
- [x] Correlation-aware logs exclude URLs with query secrets, headers, bodies, cookies, credentials,
  raw exceptions, IP/socket internals, and tracebacks.
- [ ] Log destination, access control, retention, rotation, and deletion are approved.
- [ ] `/api/v1/health` is monitored without making an external scan.
- [ ] Graceful shutdown, cancellation, 429, 503, and 504 behavior are smoke-tested.
- [x] Backup/recovery requirements are evaluated; v0.1 has no persistent application data.

## Release evidence

- [x] Full pytest, security/API tests, Ruff, strict mypy, `pip check`, and clean wheel build pass.
- [x] `npm ci`, frontend tests, TypeScript, ESLint, and production build pass.
- [ ] Python and npm audit findings are reviewed; major upgrades are not applied automatically.
- [x] Backend and frontend images/configuration validate under the target container engine.
- [ ] Reviewed image digests and resolved Python dependencies are recorded for this release.
- [ ] Authorized public smoke test passes through HTTPS using the deployed frontend and API.
- [ ] Rollback owner, previous image/config pair, trigger, and procedure are recorded.
- [x] No cloud account, DNS, server, registry push, or public deployment occurred before approval.

## Phase 10.5 local evidence

- Docker Desktop 4.91.0 / Engine 29.8.0 / Compose 5.5.1 on WSL2 built and ran both production
  images on 2026-09-17.
- Local validation used `webguard.localhost`, loopback port `127.0.0.1:8080`, same-origin `/api/`,
  and no direct backend publication.
- Real Nginx configuration validation, browser scans, 429/503/504 controls, security/cache headers,
  read-only/non-root execution, resource limits, image-content review, restart, shutdown, and clean
  recreation were exercised locally.
- The Docker health check was exercised locally; production monitoring and alerting remain pending.
- HSTS was observed in HTTP responses but is intentionally not considered verified until a real
  HTTPS deployment exists.
