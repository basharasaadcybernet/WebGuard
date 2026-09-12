# Changelog

All notable changes will be recorded here. This project uses semantic versioning once releases
begin.

## Unreleased

### Added

- Python 3.12 `src`-layout project foundation.
- Immutable Pydantic domain contracts.
- Fail-closed URL, DNS, IP, redirect, destination pinning, resource limit, and redaction layers.
- Security regression tests and learning documentation.
- Phase 3.5 controlled tests for pinned sockets, Host and SNI preservation, verified TLS setup,
  transport failures, streamed limits, malformed responses, and resource cleanup.
- Opt-in harmless public-network smoke tests, excluded from normal pytest runs.
- Git ignore rules for environments, caches, IDE state, secrets, reports, and build artifacts.
- Phase 4 immutable scan observations, typed check protocol, explicit deterministic registry,
  centralized scan network service, and sequential `ScanEngine` orchestration.
- Public operational error contracts and explicit `COMPLETED`, `PARTIAL`, and `FAILED` scan states.
- Check failure isolation, shared per-scan request budgets, safe internal-to-public hop conversion,
  and architecture tests preventing networking imports in future check modules.

### Fixed

- Compare effective HTTP/HTTPS ports in the pinned HTTP adapter so normal URLs using implicit ports
  80 and 443 are accepted without weakening the explicit destination match.
- Close the raw connection socket when socket-option setup, connection setup, or cancellation fails
  before ownership transfers to the HTTP stream.

### Security

- Expose HTTPS-to-HTTP redirect downgrade observation for future rule evaluation.
- Assert that the TLS context requires certificate and hostname verification.
- Redact response authorization and cookie values before checks receive headers, while retaining
  non-secret cookie flags needed by future rules.
- Keep check exception details, response bodies, and sensitive target queries out of public scan
  serialization.
