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
future CLI / API / reports
          |
      ScanEngine
       /      \
ScanContext  CheckRegistry
     |          |
 observations  metadata declarations + sequential checks
          |
ScanNetworkService -- landing + HTTPS + one-hop HTTP + security.txt
          |                 one shared RequestBudget
          |
    SafeHttpClient
  |       |       |
URL    Resolver  PinnedTransport
policy    +          |
       IP policy  public destination only
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
change an otherwise `COMPLETED` scan. Phase 5B deliberately calculates no score.

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

## Deferred components

Scoring, grades, reports, REST endpoints, CLI scan commands, persistence, and the frontend remain
deferred. Active exploitation, fuzzing, enumeration, and port scanning are outside product scope.

## Current limitations

The transport selects the first validated public DNS address and does not yet retry another public
answer if the connection fails. It requests identity encoding and fails closed when a server sends
compressed content anyway; bounded streaming decompression can be added later without weakening
the size limit. Application-wide concurrency limits belong to the future orchestration/API layer.

Phase 5B uses controlled transport and rule fixtures as its source of truth. The normal suite
remains fully deterministic and never requires external DNS or Internet access.
