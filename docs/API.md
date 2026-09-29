# Internal REST API

The FastAPI adapter is the same-process backend used by `webguard web`. It is stateless and adds no
network client, security check, score calculation, persistence, or HTML-report endpoint of its own.
The installed package intentionally exposes no second server command.

Start the supported local interface with:

```text
webguard web
```

The command prints the selected origin. API routes are beneath that origin and are primarily an
implementation contract for the bundled page, not a promise of a publicly hosted service.

## Endpoints

- `GET /api/v1/health` returns `{"status":"ok"}` without performing network work.
- `GET /api/v1/version` returns public software and schema/ruleset versions.
- `POST /api/v1/scans` accepts exactly `{"target":"https://example.com"}` and returns a sanitized
  report envelope.

Clients cannot submit methods, credentials, headers, cookies, redirect policy, TLS options, request
budgets, ports outside scanner policy, or SSRF bypasses.

## Response contract

A successful execution returns an API version, schema version, random request ID, and the same
`ReportDocument` used by CLI JSON/HTML reports. It includes target display data, scan state,
severity counts, transparent scoring, findings, operational limitations, methodology, and the
permanent disclaimer. Query values, raw response bodies, pinned addresses, sockets, and exception
details are not included.

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
| 200 | A sanitized report is available, including partial or failed assessment states. |
| 400 | Invalid Host or HTTP envelope. |
| 413 | Request body is too large. |
| 415 | Scan request is not JSON. |
| 422 | Invalid model or target rejected by syntactic target policy. |
| 429 | Per-client process-local rate limit reached. |
| 499 | Client disconnected before completion. |
| 503 | All scan slots are active; requests are not queued. |
| 504 | Overall scan deadline expired. |
| 500 | Sanitized unexpected internal failure. |

An SSRF destination rejection discovered during protected resolution remains a sanitized `FAILED`
report. A security finding, low grade, score cap, or withheld score is never an HTTP execution
failure.

Every API response carries a correlation ID, `Cache-Control: no-store`, a no-content CSP,
`nosniff`, `no-referrer`, frame denial, and a conservative Permissions Policy. The local command
accepts loopback Host values only and does not trust forwarded-client headers.

The adapter remains importable for controlled tests and application development through
`webguard.api.app.create_app`; that internal API is not a separate end-user startup workflow.
