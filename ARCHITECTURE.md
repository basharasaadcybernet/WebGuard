# Architecture

## Current milestone

The package uses a `src` layout under `backend/src/webguard`. The implemented layers are:

1. `domain`: immutable Pydantic contracts and stable enums.
2. `security`: URL policy, DNS resolution, public-address validation, redaction, request
   budgets, destination pinning, and bounded HTTP retrieval.

The security package is deliberately the only public home for outbound networking. Future
scanner checks will receive already collected observations and will not receive a raw HTTP
client.

An AST-based architecture regression test rejects HTTP-client imports outside
`security/transport.py` and raw-socket imports outside the two networking modules. This is not a
sandbox, but it turns an accidental boundary bypass into a normal test failure.

## Dependency direction

```text
future CLI / API / reports
          |
future ScanEngine
          |
SafeHttpClient
  |       |       |
URL    Resolver  PinnedTransport
policy    +          |
       IP policy  public destination only
```

Domain contracts do not depend on interfaces or scanner implementations. The network boundary
depends on domain target models, but domain models do not depend on the network layer.

## Deferred components

Scanner orchestration, rule checks, scoring, reports, REST endpoints, CLI scan commands, and the
frontend are intentionally deferred to later milestones.

## Current limitations

The transport selects the first validated public DNS address and does not yet retry another public
answer if the connection fails. It requests identity encoding and fails closed when a server sends
compressed content anyway; bounded streaming decompression can be added later without weakening
the size limit. Application-wide concurrency limits belong to the future orchestration/API layer.

Phase 3.5 added controlled transport tests and opt-in public smoke tests. The normal suite remains
fully deterministic and never requires external DNS or Internet access.
