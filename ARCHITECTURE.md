# Architecture

## Current milestone

The package uses a `src` layout under `backend/src/webguard`. The implemented layers are:

1. `domain`: immutable Pydantic contracts and stable enums.
2. `security`: URL policy, DNS resolution, public-address validation, redaction, request
   budgets, destination pinning, and bounded HTTP retrieval.
3. `scanner`: immutable observations, the typed check protocol, an explicit deterministic
   registry, centralized per-scan network service, and failure-isolating orchestration.

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
 observations  sequential checks
          |
ScanNetworkService -- one RequestBudget
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
change an otherwise `COMPLETED` scan. Phase 4 deliberately calculates no score.

## Deferred components

Real rule checks, scoring, reports, REST endpoints, CLI scan commands, and the frontend are
intentionally deferred to later milestones.

## Current limitations

The transport selects the first validated public DNS address and does not yet retry another public
answer if the connection fails. It requests identity encoding and fails closed when a server sends
compressed content anyway; bounded streaming decompression can be added later without weakening
the size limit. Application-wide concurrency limits belong to the future orchestration/API layer.

Phase 3.5 added controlled transport tests and opt-in public smoke tests. The normal suite remains
fully deterministic and never requires external DNS or Internet access.
