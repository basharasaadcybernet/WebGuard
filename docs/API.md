# REST API

Phase 8 exposes the existing WebGuard engine through a deliberately small, stateless FastAPI
adapter. It adds no target HTTP client, security checks, score calculation, persistence, or HTML
download endpoint.

## Development server

Install the project and run the package entry point:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\webguard-api.exe
```

The default listener is `http://127.0.0.1:8000`. Interactive OpenAPI documentation is available at
`/docs`; disable it with `WEBGUARD_DOCS_ENABLED=false`. `webguard-api` deliberately runs one worker,
disables raw access logging, and trusts proxy headers only when exact peer IPs/CIDRs are configured.

## Endpoints

### `GET /api/v1/health`

Returns `{"status":"ok"}`. It performs no scan, DNS lookup, dependency probe, or environment
inspection.

### `GET /api/v1/version`

Returns the public WebGuard software, API, API schema, report schema, check ruleset, and scoring
ruleset versions. It exposes no Python, filesystem, username, or environment details.

### `POST /api/v1/scans`

The complete accepted input is:

```json
{"target":"https://example.com"}
```

Extra fields are rejected. Clients cannot submit methods, headers, cookies, credentials, ports
outside scanner policy, redirect policy, TLS options, request budgets, or SSRF switches.

A successful execution returns:

```json
{
  "api_version": "v1",
  "api_schema_version": "1.0",
  "request_id": "2f0b75a9-6547-45e8-894f-2ff92e079caf",
  "report": {"report_schema_version": "1.0", "...": "ReportDocument fields"}
}
```

`report` is the Phase 7 `ReportDocument`, not a second scan schema. It contains the sanitized
target, scan metadata/completion state, severity counts, full scoring breakdown (raw/final score,
grade, coverage, version, categories, rule contributions, exclusions, and caps), non-pass
findings, operational errors, methodology, limitations, and disclaimer. Decimal scoring values
remain JSON strings. Query values, response bodies, pinned addresses, sockets, and exceptions are
not part of the model.

## HTTP and error policy

Errors use one stable shape:

```json
{
  "code": "INVALID_REQUEST",
  "message": "The request body is invalid.",
  "request_id": "2f0b75a9-6547-45e8-894f-2ff92e079caf"
}
```

| Status | Meaning |
| --- | --- |
| 200 | A sanitized scan result is available, including partial/failed observations or negative findings. |
| 400 | Invalid Host/HTTP envelope. |
| 413 | Body exceeds `WEBGUARD_MAX_REQUEST_BODY_BYTES`. |
| 415 | Scan request is not `application/json`. |
| 422 | Invalid JSON/model or a target rejected during syntactic URL policy validation. |
| 429 | Direct peer exceeded the process-local fixed-window allowance. |
| 499 | Client disconnected; primarily an internal/diagnostic status because the client is gone. |
| 503 | All process scan slots are active; the request is not queued. |
| 504 | API-wide scan deadline expired and the scan task was cancelled. |
| 500 | Unexpected internal failure; details are not returned. |

An address-based SSRF rejection discovered during protected DNS/address validation is preserved as
the engine's sanitized `FAILED` scan result (HTTP 200). The API does not inspect DNS internals to
reclassify it. A site's HIGH/MEDIUM/LOW findings, low grade, score cap, or score withholding are
never HTTP failures.

Every HTTP response includes `X-Request-ID`; success/error bodies also carry that UUID where useful.
It is random, contains no identity, and is not persisted.

All `/api/` responses, including boundary and 500 errors, carry `Cache-Control: no-store`, a
no-content CSP, `nosniff`, `no-referrer`, framing denial, and a conservative Permissions Policy.
The TLS reverse proxy remains responsible for HSTS.

## Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `WEBGUARD_ENV` | `development` | Runtime profile: development, test, or production. |
| `WEBGUARD_BIND_HOST` | `127.0.0.1` | Listener; must be explicit in production. |
| `WEBGUARD_BIND_PORT` | `8000` | Listener port. |
| `WEBGUARD_DEBUG` | `false` | Explicit local debugging; forbidden in production. |
| `WEBGUARD_LOG_LEVEL` | `INFO` | CRITICAL, ERROR, WARNING, INFO, or DEBUG. |
| `WEBGUARD_DOCS_ENABLED` | profile-based | Defaults off in production and on otherwise. |
| `WEBGUARD_MAX_CONCURRENT_SCANS` | `4` | Immediate per-process active-scan capacity. |
| `WEBGUARD_SCAN_TIMEOUT_SECONDS` | `90` | Overall API deadline; does not weaken inner network timeouts. |
| `WEBGUARD_MAX_REQUEST_BODY_BYTES` | `4096` | Complete inbound HTTP body cap. |
| `WEBGUARD_RATE_LIMIT_REQUESTS` | `10` | Scan starts allowed per direct peer/window/process. |
| `WEBGUARD_RATE_LIMIT_WINDOW_SECONDS` | `60` | Fixed rate window. |
| `WEBGUARD_RATE_LIMIT_MAX_CLIENTS` | `4096` | Hard cap on temporary hashed peer entries. |
| `WEBGUARD_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated exact frontend origins. |
| `WEBGUARD_ALLOWED_HOSTS` | `localhost,127.0.0.1,testserver` | Comma-separated accepted HTTP Host names. |
| `WEBGUARD_TRUSTED_PROXIES` | empty | Exact proxy IP/CIDR allowlist; enables forwarded-client handling. |

Unsafe/invalid configuration fails process startup. Production additionally requires explicit
bind, Host, and CORS variables, rejects debug and HTTP CORS origins, and permits an empty CORS list
for the preferred same-origin topology. Wildcard Host/CORS/proxy trust is rejected. CORS credentials
are always disabled. The limiter keys the ASGI peer after Uvicorn's optional trusted-proxy boundary,
uses a process-random keyed hash, and evicts old peers to remain bounded. Each worker has independent
concurrency and rate state.

## Production deployment requirements

Phase 10 does not deploy WebGuard. A controlled beta deployment must provide:

- an HTTPS reverse proxy/CDN with public request-size and distributed rate limits;
- explicit Uvicorn trusted-proxy configuration, or proxy headers kept disabled;
- private API binding and exact `WEBGUARD_ALLOWED_HOSTS`/`WEBGUARD_CORS_ORIGINS` values;
- outbound firewall/egress policy blocking local, private, metadata, and control-plane networks;
- conservative worker/process sizing aligned with outbound scan capacity;
- CPU, memory, file-descriptor, and execution limits;
- sanitized structured-log collection and retention policy; and
- secrets/environment management outside source control.

Do not trust arbitrary `X-Forwarded-For`, `X-Forwarded-Host`, or `X-Forwarded-Proto`. CORS does not
replace authentication or ingress controls. Multi-process deployments require proxy/CDN limiting
because the built-in limiter is intentionally not distributed.

See `DEPLOYMENT.md` for the same-origin and separate-origin topologies, egress model, containers,
headers, caching, lifecycle, and logging policy. Use `PRODUCTION_CHECKLIST.md` as the release gate.

## Deferred HTML support

Phase 8 does not rescan for, upload, or download HTML. A later authorized design can render from a
server-held trusted `ReportDocument` or another integrity-protected result reference. Accepting an
arbitrary client-forged `ScanResult` merely to render HTML would create avoidable trust and
injection complexity, so no stateless rendering endpoint is included.
