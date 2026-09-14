# Architecture

## Current milestone

The package uses a `src` layout under `backend/src/webguard`. The implemented layers are:

1. `domain`: immutable Pydantic contracts and stable enums.
2. `security`: URL policy, DNS resolution, public-address validation, redaction, request
   budgets, destination pinning, and bounded HTTP retrieval.
3. `scanner`: immutable observations, the typed check protocol, an explicit deterministic
   registry, centralized per-scan network service, and failure-isolating orchestration.
4. `checks`: nineteen explicitly registered Phase 5B transport, header, cookie, content, and
   hygiene rules that inspect only `ScanContext` observations.
5. `scoring`: versioned TOML policy loading, fail-closed registry/config validation, deterministic
   Decimal calculations, and transparent score contribution models.
6. `reporting`: pure projection of public scan results into a versioned report model, deterministic
   JSON, and self-contained escaped HTML.
7. `cli`: a small Typer adapter and restrained Rich terminal presentation.
8. `api`: a FastAPI adapter with strict public schemas, bounded process-local admission/rate
   controls, request correlation, CORS/Host policy, and cancellable scan execution.

The security package is deliberately the only public home for outbound networking. Future
scanner checks receive an immutable `ScanContext`; they do not receive a raw HTTP client or the
scanner network service. Future additional observations must be collected by orchestration through
`ScanNetworkService`, which delegates to `SafeHttpClient` and owns the one shared request budget.

AST-based architecture regression tests reject HTTP-client imports outside
`security/transport.py`, raw-socket imports outside the two networking modules, and any networking
or security-client import from future `checks` modules. These tests are not a sandbox, but turn an
accidental boundary bypass into a normal test failure.

## Dependency direction

```text
CLI / FastAPI v1
          |
      ScanEngine
       /       |       \
ScanContext  CheckRegistry  ScoringEngine -- weights.toml v1.0
     |          |               |
 observations  sequential checks  ScoreBreakdown
          |
ScanNetworkService -- landing + HTTPS + one-hop HTTP + security.txt
          |                 one shared RequestBudget
          |
    SafeHttpClient
  |       |       |
URL    Resolver  PinnedTransport
policy    +          |
       IP policy  public destination only

ScanResult -- ReportBuilder -- ReportDocument v1.0
                                  |    |    |      |
                               terminal JSON HTML API envelope
```

Domain contracts do not depend on interfaces or scanner implementations. Scanner orchestration
depends on domain and security contracts. The network boundary depends on domain target models,
but domain models do not depend on the network layer.

`ScanContext` is a trusted in-process dataclass graph. Response headers are sanitized before they
enter it, cookie values are removed while safe cookie flags are retained, and bounded response
body bytes are marked internal and never copied to public contracts. `ScanResult` contains only
validated public models such as redacted `NormalizedTarget`, `FetchHop`, `Finding`, and
non-vulnerability `ScanError` records.

Checks run sequentially by `(order, rule_id)`. A check may be inapplicable, return structured
findings, raise an expected evaluation error, or crash. Check failures are isolated and produce a
`PARTIAL` scan; target or protected-network failures produce `FAILED`; negative findings do not
change an otherwise `COMPLETED` scan.

For transport checks, the orchestrator reuses successful landing-chain observations when possible.
Otherwise it makes a direct HTTPS observation and a one-hop HTTP observation through
`ScanNetworkService`. Probe URLs omit the submitted query, and every request consumes the same
scan budget. The verified TLS adapter exposes only the certificate `not_after` timestamp and a
bounded failure category: expired, hostname mismatch, or untrusted chain.

The default registry is explicit: transport and TLS checks run first, followed by header checks.
Header checks inspect the final landing response; HSTS applies only to HTTPS and CSP/clickjacking
apply only to HTML-like content. Cookie checks inspect redacted `Set-Cookie` metadata across the
landing chain, mixed content parses only the bounded final HTTPS HTML, and disclosure checks read
only explicitly returned headers. No check imports the network or security layer.

`CheckMetadata.auxiliary_requests` is the only Phase 5B observation declaration mechanism. The
`hygiene.security_txt` rule declares one fixed HTTPS path; `ScanEngine` gathers unique compatible
declarations in registry order, builds URLs from the normalized target hostname without its query,
and routes `fetch` or `fetch_once` through `ScanNetworkService`. The resulting named
`AuxiliaryObservation` enters immutable `ScanContext`. Redirects repeat URL, DNS, IP, and pinned
transport validation, and every hop consumes the same scan budget. A rule sees a success or a safe
failure category, never a client, resolver, transport, or arbitrary-URL fetch primitive.

After checks finish, `ScoringEngine` reconciles the explicit registry with findings and rule-level
errors. Missing outcomes and findings marked `NOT_APPLICABLE` become exclusions. Rule errors stay
applicable but unevaluated, reducing coverage without earning points or creating deductions. The
engine calculates rule contributions, category normalization, overall coverage, withholding,
rounding, grades, and the three configured transport caps without reading clocks, networks, or
mutable global state.

`weights.toml` is loaded and validated when the default `ScanEngine` is constructed. Configuration
must cover the real registry exactly; category weights must total 100; rule weights must reconcile
to categories; credits, grades, essential rules, and cap triggers must be valid. Invalid policy
fails startup rather than silently changing output. Public `ScoreBreakdown` retains raw and final
scores, category/rule math, deductions, exclusions and reasons, scoring version, coverage,
withholding reasons, and an applied cap. It never copies finding evidence.

Phase 7 reporting begins only after `ScanEngine` has produced an immutable public `ScanResult`.
`ReportBuilder` selects and orders non-pass findings, derives severity counts, and adds fixed
methodology and limitations. JSON, HTML, and terminal renderers consume the same versioned
`ReportDocument`; none recalculates scores or imports scanner networking. The JSON schema version,
software version, and scoring version remain distinct compatibility signals.

The HTML renderer escapes every dynamic value, permits only HTTP(S) links, embeds neutral CSS, and
ships no JavaScript or external runtime dependency. CLI file output uses explicit user paths,
requires an existing parent directory, and creates files exclusively rather than overwriting.
Operational exit codes stay separate from security findings and grades.

Phase 8 follows `HTTP -> FastAPI validation -> ScanEngine -> ReportBuilder -> ScanApiResponse`.
The only scan input is `target`; routes cannot configure ports, redirects, TLS, headers, methods,
budgets, or SSRF policy. The API package imports neither HTTP clients nor scanner-network/security
transport objects, and AST tests enforce that boundary. A successful API execution returns the
same `ReportDocument` used by Phase 7, nested in a small versioned envelope with a random request
ID. It does not recalculate score or duplicate findings.

One process admits at most a configured number of scans. Admission is immediate: when all slots
are active, the API returns 503 instead of retaining an unbounded work queue. A bounded-memory,
fixed-window limiter hashes the ASGI peer address and returns 429 after the per-client allowance.
It deliberately ignores forwarding headers. Each admitted scan also has an API-wide deadline and
disconnect polling; cancellation always releases its capacity slot. These process-local controls
are defense in depth, not a substitute for reverse-proxy/CDN rate limiting in a multi-process
deployment.

The outer ASGI boundary validates Host, caps the complete body before JSON parsing, and assigns a
UUID correlation ID. CORS has an explicit origin list, never wildcard credentials, and production
must configure both allowed origins and public Host names. The application stores no target,
result, client address, or request ID. The rate limiter retains only keyed hashes temporarily in
bounded process memory.

Phase 9 adds an independent browser adapter:

```text
React App -> useScan state machine -> typed API client -> POST /api/v1/scans
    |                                      |
    +-> results components                 +-> runtime response validation
          |-- backend score/grade/coverage (display only)
          |-- severity and category summaries
          |-- client-only finding filters and native details
          `-- limitations and configurable contact CTA
```

The state machine is `idle -> scanning -> success | error`, with an AbortController for explicit
cancellation and a bounded client timeout. Components never call `fetch` directly. The API client
accepts only the configured base URL plus the fixed scan path and validates the public response
shape before rendering it. Scanned data remains untrusted text; React escaping, scheme-validated
reference links, and the absence of raw HTML insertion form the browser security boundary.

Results receive the API's `ReportDocument` as their sole authority. The frontend formats decimal
fractions for display but does not compute a score, grade, cap, finding, or completion state. An
optional `expertRecommendations` component slot exists at the results boundary but Phase 9 does
not populate it.

## Deferred components

Persistence, history, monitoring, PDF output, HTML-over-API rendering, expert recommendations,
and public deployment remain deferred.
Active exploitation, fuzzing, enumeration, and port scanning are outside product scope.

## Current limitations

The transport selects the first validated public DNS address and does not yet retry another public
answer if the connection fails. It requests identity encoding and fails closed when a server sends
compressed content anyway; bounded streaming decompression can be added later without weakening
the size limit. API admission/rate limits are process-local, so each worker has independent state.

Phase 8 adds controlled API contract, privacy, CORS, Host, size, rate, concurrency, timeout,
cancellation, and architecture tests. The normal suite remains deterministic and never requires
external DNS or Internet access.
