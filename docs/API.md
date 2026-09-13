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
`/docs`; disable it with `WEBGUARD_DOCS_ENABLED=false`. `webguard-api` is a single-process
development command and deliberately disables proxy-header trust.

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

## Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `WEBGUARD_MAX_CONCURRENT_SCANS` | `4` | Immediate per-process active-scan capacity. |
| `WEBGUARD_SCAN_TIMEOUT_SECONDS` | `90` | Overall API deadline; does not weaken inner network timeouts. |
| `WEBGUARD_MAX_REQUEST_BODY_BYTES` | `4096` | Complete inbound HTTP body cap. |
| `WEBGUARD_RATE_LIMIT_REQUESTS` | `10` | Scan starts allowed per direct peer/window/process. |
| `WEBGUARD_RATE_LIMIT_WINDOW_SECONDS` | `60` | Fixed rate window. |
| `WEBGUARD_RATE_LIMIT_MAX_CLIENTS` | `4096` | Hard cap on temporary hashed peer entries. |
| `WEBGUARD_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated exact frontend origins. |
| `WEBGUARD_ALLOWED_HOSTS` | `localhost,127.0.0.1,testserver` | Comma-separated accepted HTTP Host names. |
| `WEBGUARD_DOCS_ENABLED` | `true` | Development OpenAPI/docs exposure. |
| `WEBGUARD_BIND_HOST` | `127.0.0.1` | Development entry-point listener. |
| `WEBGUARD_BIND_PORT` | `8000` | Development entry-point port. |

Unsafe/invalid configuration fails process startup. Wildcard CORS and Host lists are rejected.
CORS credentials are always disabled. The limiter keys only the ASGI direct peer, uses a
process-random keyed hash, ignores all forwarding headers, and evicts old peers to remain bounded.
Each worker has independent concurrency and rate state.

## Production deployment requirements

Phase 8 does not deploy WebGuard. A future production deployment must provide:

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

## Deferred HTML support

Phase 8 does not rescan for, upload, or download HTML. A later authorized design can render from a
server-held trusted `ReportDocument` or another integrity-protected result reference. Accepting an
arbitrary client-forged `ScanResult` merely to render HTML would create avoidable trust and
injection complexity, so no stateless rendering endpoint is included.
