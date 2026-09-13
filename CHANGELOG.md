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
- Phase 5A explicit registry of twelve real transport-security and HTTP security-header checks.
- Protected one-hop HTTP probing for redirect assessment and minimal verified-certificate
  expiration metadata for TLS checks.
- Controlled rule tests covering positive, negative, malformed, unavailable, and not-applicable
  outcomes without authoritative live targets.
- Phase 5B cookie Secure, HttpOnly, and SameSite checks with deterministic grouped evidence and no
  cookie values.
- RFC 9116-oriented security.txt collection through declarative auxiliary observations, the shared
  request budget, and the protected redirect path.
- Bounded static mixed-content detection for active and passive HTML references, with deduplicated
  redacted URL evidence.
- Separate informational Server and X-Powered-By disclosure rules with conservative version-detail
  handling and no CVE matching.
- Controlled Phase 5B rule and boundary tests for parsing, privacy, redirect SSRF protection,
  budget exhaustion, oversized responses, ordering, failure isolation, and serialization.
- Phase 6 scoring ruleset `1.0` with versioned TOML category/rule weights, status and
  severity-specific credits, grade bands, a 70% coverage threshold, essential transport evidence,
  and three explicit transport caps.
- Immutable per-rule contributions, category normalization, exclusions, withholding reasons, raw
  and final scores, coverage, grades, deductions, and applied-cap contracts.
- Named excellent, average, weak, transport-broken, and low-coverage regression profiles plus
  fail-closed configuration, determinism, grade-boundary, and serialization tests.
- Phase 7 `webguard` Typer entry point with help, version, human scan, JSON, HTML, and explicit
  output-file behavior.
- Restrained Rich terminal summaries with score withholding/caps, coverage, categories, ordered
  findings, and operational errors kept separate from vulnerabilities.
- Report schema `1.0`, deterministic JSON, and self-contained neutral HTML with finding details,
  methodology, technical references, print styling, and no runtime network dependency.

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
- Classify expired, hostname-mismatched, and untrusted TLS certificates at the protected boundary
  without disabling certificate verification or exposing raw TLS errors.
- Redact redirect query values before Location observations enter `ScanContext`.
- Keep security.txt Contact values and raw bodies out of public results, and never fetch resources
  named inside the file.
- Route metadata-declared auxiliary observations through `ScanNetworkService`; check modules still
  cannot import networking or security-boundary code.
- Redact and bound mixed-content evidence URLs and collapse duplicate insecure references.
- Mark no-cookie observations explicitly NOT_APPLICABLE so scoring cannot award artificial cookie
  points, while keeping missing HttpOnly an applicable informational observation.
- Keep finding evidence out of scoring contributions so the scoring layer cannot duplicate secret
  material from evidence fields.
- Replace the permanently zero finding score placeholder with authoritative versioned
  `RuleContribution` records.
- Escape all target-controlled HTML report data, restrict report links to HTTP(S), emit no
  JavaScript, and add a restrictive report Content Security Policy.
- Exclude transport internals from report contracts, HTML-escape JSON delimiters, keep JSON stdout
  clean, suppress public tracebacks, and refuse implicit directories or report overwrites.
