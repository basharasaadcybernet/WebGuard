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

## Responsible use

WebGuard is intended for systems the operator owns or is authorized to assess. The planned rule
set is passive and low impact; active exploitation, credential testing, enumeration, fuzzing,
and port scanning are out of scope.

## Reporting a security issue

Until a public disclosure address is established, report security issues privately to the
repository owner and do not publish exploit details.
