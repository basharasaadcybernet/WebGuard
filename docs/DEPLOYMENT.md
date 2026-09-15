# Controlled Beta Deployment Guide

Phase 10 prepares WebGuard for deployment but does not deploy it. The files in this repository are
provider-neutral examples. Replace every reserved `.invalid` hostname, review every limit against
the selected host, and complete `PRODUCTION_CHECKLIST.md` before exposing the service.

## Recommended topology

The preferred production layout is same-origin:

```text
Browser
   | HTTPS
TLS edge / reverse proxy
   |-- /          -> immutable static frontend files
   `-- /api/      -> one private WebGuard API process
                         `-> protected HTTP/HTTPS egress only
```

The browser then uses an empty `VITE_WEBGUARD_API_URL`, and production CORS is an explicit empty
list. This reduces the browser trust boundary. A separate HTTPS frontend origin is also supported:
build the public API origin into `VITE_WEBGUARD_API_URL` and list only the exact frontend HTTPS
origin in `WEBGUARD_CORS_ORIGINS`. Neither option changes scanner security policy.

The supplied Nginx configuration is an HTTP application gateway intended to sit behind a provider
TLS terminator. If Nginx is the public TLS edge instead, add a reviewed `listen 443 ssl` and managed
certificate configuration before use. Never expose the backend port publicly.

## Runtime profiles

- `development` uses loopback binding, localhost Host/CORS values, API documentation, and no proxy
  header trust. Debug still remains off unless explicitly enabled.
- `test` allows controlled test configuration without weakening production validation.
- `production` requires explicit bind, Host, and CORS decisions; disables documentation by default;
  rejects debug, wildcard/malformed hosts, HTTP CORS origins, and malformed proxy allowlists.

`ApiSettings` validates configuration at process startup. There is no fallback from an invalid
production setting to a development value.

## Environment variables

Copy `.env.example` to a private deployment configuration and replace the reserved hostname. Do
not commit the resulting file.

| Variable | Safe default / production rule |
| --- | --- |
| `WEBGUARD_ENV` | `development`; set `production` for deployment |
| `WEBGUARD_BIND_HOST` | `127.0.0.1`; required explicitly in production |
| `WEBGUARD_BIND_PORT` | `8000`, range 1-65535 |
| `WEBGUARD_DEBUG` | `false`; `true` is rejected in production |
| `WEBGUARD_LOG_LEVEL` | `INFO`; one of CRITICAL, ERROR, WARNING, INFO, DEBUG |
| `WEBGUARD_DOCS_ENABLED` | on outside production, off by default in production |
| `WEBGUARD_ALLOWED_HOSTS` | comma-separated exact hosts; required, never `*` |
| `WEBGUARD_CORS_ORIGINS` | exact origins; required in production and may be empty for same-origin |
| `WEBGUARD_TRUSTED_PROXIES` | empty; IP/CIDR allowlist only, never `*` or a hostname |
| `WEBGUARD_MAX_CONCURRENT_SCANS` | `4`, maximum 64; immediate 503 when full |
| `WEBGUARD_SCAN_TIMEOUT_SECONDS` | `90`, maximum 300; returns 504 on expiry |
| `WEBGUARD_MAX_REQUEST_BODY_BYTES` | `4096`, maximum 65536; keep proxy limit aligned |
| `WEBGUARD_RATE_LIMIT_REQUESTS` | `10` requests per local window |
| `WEBGUARD_RATE_LIMIT_WINDOW_SECONDS` | `60`, maximum 3600 |
| `WEBGUARD_RATE_LIMIT_MAX_CLIENTS` | `4096`, bounded in-memory peer entries |
| `VITE_WEBGUARD_API_URL` | public build-time API origin; empty selects same-origin `/api` |
| `VITE_CYBERNET_CONTACT_URL` | optional public contact link; never a secret |

Scanner egress limits remain code-controlled safety policy: ports 80/443, at most eight protected
requests and five redirects, 2 MiB per response, a 15-second total outbound request deadline, and
bounded DNS/connect/read/write/pool timeouts. They are deliberately not deployment environment
switches.

## Reverse proxy boundary

The proxy must:

- terminate valid HTTPS (or receive traffic only from a trusted TLS terminator), redirect HTTP to
  HTTPS, preserve the original `Host`, and reject other public hostnames;
- cap request bodies at 4 KiB, bound connections, apply an external scan rate limit, and return 429
  or 503 without building an unbounded queue;
- use a backend read timeout slightly above the 90-second API deadline and a short connect/send
  timeout;
- disable shared caching for `/api/` and allow long caching only for hashed `/assets/` files;
- overwrite `X-Forwarded-For` instead of appending client input, clear `Forwarded` and
  `X-Forwarded-Host`, and send proxy information only from an allowlisted proxy peer; and
- remove or avoid duplicate security headers so one layer owns the effective browser policy.

The included Nginx example rate-limits by its direct peer. If another load balancer sits in front,
configure that product's real-IP feature with its exact source networks; never trust arbitrary
client forwarding headers. WebGuard enables Uvicorn proxy processing only when
`WEBGUARD_TRUSTED_PROXIES` is non-empty. The default is to ignore all forwarded client data.

The application limiter remains deliberately process-local. Run one API worker per container and
scale only with an external global limit and a measured capacity plan. A reverse proxy or CDN is
the primary public rate limiter; no Redis or distributed state is introduced in v0.1.

## Container execution

`Dockerfile.backend` builds a wheel in one stage and installs runtime dependencies into a clean
Python image. The runtime uses UID/GID 10001, has no development tools, exposes only port 8000, and
needs no privileged mode, Docker socket, host network, persistent volume, or secret baked into the
image. `Dockerfile.frontend` builds static Vite assets and serves them through unprivileged Nginx.

The production Compose example adds a read-only root filesystem, small temporary filesystem,
dropped Linux capabilities, `no-new-privileges`, PID/memory/CPU limits, a private proxy network,
and a separate backend egress network. Its public bind defaults to loopback so running the example
does not itself publish WebGuard.

Compose assigns the isolated proxy network `172.30.10.0/28` and trusts that exact CIDR so the
frontend proxy can supply the client peer used by the bounded application limiter. Only the
frontend and backend join that network. If the subnet or topology changes, update the trusted CIDR
to the direct proxy network or leave it empty to disable forwarded-header handling.

Example validation and local controlled start:

```powershell
$env:WEBGUARD_ALLOWED_HOSTS = "webguard.example.invalid"
docker compose -f docker-compose.production.yml config
docker compose -f docker-compose.production.yml build
docker compose -f docker-compose.production.yml up
```

Do not use the reserved hostname for a real beta. Container tags are readable version pins, not
immutable digests; a production operator should pin reviewed image digests in release automation.

## Egress defense in depth

Application SSRF controls and infrastructure egress filtering are independent layers. Keep both.
The backend needs DNS plus outbound TCP 80/443 to public destinations. At the host, firewall,
container platform, or egress gateway:

- deny loopback, link-local, RFC 1918/private, carrier-grade NAT, multicast, reserved/special-use,
  cloud metadata, cluster/service, host-management, and organizational LAN ranges;
- deny other outbound ports and direct access to the Docker host or control plane;
- use an approved resolver that cannot return or route private service addresses unexpectedly;
- prevent the proxy-only network from becoming a general egress route; and
- alert operationally outside WebGuard if denied egress indicates abuse.

Do not add an HTTP proxy through environment variables: WebGuard's protected transport ignores
environment proxy configuration. If a future platform requires an egress proxy, it needs a separate
security design rather than bypassing destination pinning.

## HTTP security and caching

Direct API responses set `Cache-Control: no-store`, an API-specific `default-src 'none'` CSP,
`nosniff`, `no-referrer`, framing denial, and a conservative Permissions Policy. The proxy example
hides these upstream copies and emits one equivalent API policy, while it owns HSTS because it owns
HTTPS. Frontend responses use a React-compatible same-origin CSP: scripts/styles/connect are
limited to self, images to self/data, objects and framing are denied.

Hashed frontend assets may be cached for one year. `index.html` is revalidated/no-cache so new
asset hashes deploy promptly. API health, version, errors, and scan results are never shared-cache
candidates. Do not add proxy caching to `/api/` without a new privacy design.

Vite production source maps are explicitly disabled. The bundle has no analytics, external runtime
scripts, CDN dependency, or development-only API URL. All `VITE_*` values are public because Vite
embeds them into static JavaScript.

## Logging and privacy

Application logs contain only startup/shutdown, random request correlation ID, public scan ID,
completion state, duration, and high-level rate/capacity/timeout/target-policy classes. Uvicorn
access logging is disabled by the provided entry point because it exposes raw peer addresses and is
not correlation-aware.

Never log target query strings, request bodies, response bodies, cookies, Authorization, credentials,
raw exceptions, tracebacks, filesystem paths, resolved/pinned IPs, or socket data. Forward logs only
to a deployment-controlled sink with retention and access controls; Phase 10 adds no external
logging or analytics service.

## Health, lifecycle, and rollback

`GET /api/v1/health` is a cheap process-liveness/readiness signal: startup has already validated
configuration and loaded registry/scoring policy. It performs no DNS lookup or target scan and
returns only `{"status":"ok"}`. A second readiness endpoint would add no meaningful distinction
for this stateless process.

Each scan has a deadline and disconnect polling. Cancellation awaits child task cleanup and always
releases its capacity slot. Give the container at least 20 seconds to stop, stop accepting traffic
before termination, and let the orchestrator send SIGTERM. Roll back by redeploying the previous
reviewed image/config pair; there is no database migration or scan-state recovery in v0.1.

## Dependency and release discipline

Python keeps compatibility ranges in `pyproject.toml`; `requirements.production.txt` records the
reviewed Python 3.12 transitive production resolution and constrains container wheel creation.
Regenerate it deliberately after dependency review. Frontend builds use the committed
`frontend/package-lock.json` and `npm ci`. For reproducible beta releases, record image digests plus
the resolved Python environment from the validated release job. Review dependency audit output;
do not apply automatic major upgrades.
