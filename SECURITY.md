# Security Policy and Threat Model

## Scope

WebGuard accepts attacker-controlled URLs. Its primary current threat is server-side request
forgery (SSRF): tricking the service into connecting to internal, local, metadata, or otherwise
unintended destinations.

## Boundary guarantees

Every outbound request must pass through `SafeHttpClient`. The boundary:

- accepts only explicit HTTP and HTTPS URLs;
- rejects credentials, malformed hosts, encoded controls, and non-default ports;
- resolves hostnames and rejects the entire answer set if any address is non-public;
- pins a validated address into the TCP connection;
- retains the original hostname for HTTP Host and TLS SNI/certificate verification;
- re-runs URL, DNS, and address checks for every redirect;
- limits redirects, requests, time, and decoded response bytes;
- requests identity transfer encoding and rejects unexpected compression to avoid decompression
  bombs in the current milestone;
- does not read proxy configuration from environment variables; and
- redacts URL queries and secret-bearing headers from evidence and log context.

There is no production option to turn SSRF validation off. Tests use injected fake dependencies.

## Phase 3.5 validation

The transport boundary is tested at three levels:

- policy tests cover URL, DNS, address, redirect, rebinding, and redaction behavior;
- controlled transport tests exercise numeric-IP socket connection, Host preservation, verified
  TLS context construction, SNI enforcement, timeout/error mapping, response limits, malformed
  responses, and cleanup; and
- opt-in public smoke tests exercise the real resolver, socket, TLS, HTTP, and redirect path.

Normal tests never relax the public-address policy. Optional public tests are excluded unless the
developer explicitly selects the `live` marker.

The Phase 3.5 review found and fixed a raw-socket cleanup gap: failures while applying socket
options, and cancellation before stream ownership transferred, could leave the unconnected socket
open. The connection setup now closes the socket on every unsuccessful ownership-transfer path.

## Defense in depth

Production deployment should additionally apply outbound firewall rules, container resource
limits, ingress rate limiting, and a fixed public resolver policy. Those controls supplement the
application boundary; they do not replace it.

The application cannot prove how the host network routes an otherwise public IP address. Egress
filtering remains important protection against unusual routing or infrastructure interception.

## Data handling

Targets and results are not persisted by default. Cookie values, authorization values, and full
queries must not enter findings or logs. Untrusted response content must be escaped before any
future HTML rendering.

## Phase 4 orchestration boundary

`ScanEngine` creates one `RequestBudget` per scan and gives it only to `ScanNetworkService`.
Landing-page retrieval and every future auxiliary observation therefore consume the same bounded
resource. Checks receive only `ScanContext` and cannot make network requests directly.

Internal bounded body content is available to trusted in-process checks but is never serialized in
`ScanResult`. Response authorization values are removed, cookie values are redacted, sensitive URL
queries remain excluded, and public redirect locations pass through URL redaction. Check exception
messages and tracebacks are not exposed: public errors use fixed safe codes and messages.

Operational failures remain separate from vulnerabilities. A target-policy or network failure is
a failed scan, while an isolated check failure is a partial scan. A negative security finding is a
valid check result and does not become an operational error.

## Phase 5A transport and header observations

The orchestrator collects the landing page, a verified HTTPS observation, and a one-hop HTTP
redirect observation. It reuses landing responses where possible, removes the submitted query from
auxiliary probe URLs, and charges every request and redirect to one per-scan budget. A one-hop probe
cannot silently follow an HTTP redirect outside the normal validation path.

TLS verification remains enabled. Successful TLS proves that the system trust store, certificate
validity checks, and hostname validation accepted that connection. Verification failures are
reduced to safe categories for expired, hostname-mismatched, or untrusted certificates. Only the
verified peer certificate expiration time is retained; subjects, serials, chains, socket state, and
raw exception text are not exposed.

Response `Location` values are converted to absolute redacted URLs before checks receive them.
Authorization values and cookie values remain redacted, response bodies remain internal, and all
finding evidence is bounded by public model validation.

Phase 5A findings describe observed posture, not exploitability. Missing HSTS, CSP,
X-Content-Type-Options, Referrer-Policy, or Permissions-Policy is worded as absent hardening unless
the rule confirms a stronger misconfiguration such as `max-age=0`. No Phase 5A rule uses CRITICAL
severity and no score is calculated.

A confirmed endpoint connection failure can support an HTTPS-availability finding. A timeout or
other indeterminate network error cannot: it becomes an operational evaluation error so temporary
uncertainty is not mislabeled as a security weakness.

## Phase 5B passive-content and disclosure observations

Rules may declare fixed auxiliary requests in metadata, but they still receive no networking
object. `ScanEngine` turns the `security_txt` declaration into an HTTPS request for
`/.well-known/security.txt` on the normalized target hostname. It follows redirects only through
`SafeHttpClient`, revalidates every destination, and charges every hop to the same `RequestBudget`
used by landing, HTTPS, and HTTP observations. A blocked redirect, exhausted budget, oversized
response, or other protected-fetch failure becomes an operational check error, not a finding.

The security.txt parser has a 64 KiB rule-level ceiling inside the global response limit. It checks
only successful HTTPS `text/plain` UTF-8 content, Contact presence, and one future RFC 3339 Expires
value. Contact values and referenced URLs are not copied into findings or fetched. This avoids
turning a policy document into an unbounded crawler or an SSRF route.

`Set-Cookie` is redacted before `ScanContext` construction. Checks can see only a bounded cookie
name and the recognized `Secure`, `HttpOnly`, and `SameSite` flags; values, tokens, and session IDs
are replaced with `[redacted]`. Results group names and counts by attribute instead of reproducing
headers. Authorization data remains fully redacted.

Mixed-content analysis uses the standard non-executing HTML parser on the already-bounded final
HTTPS landing body. It does not start a browser, execute script, fetch subresources, or evaluate
raw HTML. Only explicit `http://` attributes are considered. Evidence URLs pass through the same
credential, query, and fragment redaction used by public hop data; duplicates are collapsed.

Server and X-Powered-By checks consume only sanitized final-response header observations. They do
not fingerprint, contact external services, or turn banner versions into CVE claims. Generic
presence is informational; a concrete Server version is at most a LOW disclosure warning.

Phase 5B uncovered no bypass of the protected network boundary. The auxiliary-fetch work did add
regression coverage demonstrating that private redirect destinations, over-budget requests, and
oversized security.txt responses fail without creating vulnerability findings.

## Responsible use

WebGuard is intended for systems the operator owns or is authorized to assess. The planned rule
set is passive and low impact; active exploitation, credential testing, enumeration, fuzzing,
and port scanning are out of scope.

## Reporting a security issue

Until a public disclosure address is established, report security issues privately to the
repository owner and do not publish exploit details.
