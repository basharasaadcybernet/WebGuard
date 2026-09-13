# Learning WebGuard

This document explains why the networking layer is designed more strictly than an ordinary web
client.

## What SSRF means

Server-side request forgery (SSRF) happens when a server accepts a destination from a user and
then connects somewhere the user should not be able to reach. A URL such as
`http://127.0.0.1/admin` could make a public WebGuard installation talk to a private service on
its own machine. Cloud providers also expose metadata services on special local addresses; those
services may contain credentials.

Simply checking that text starts with `https://` does not solve this. A hostname can resolve to a
private address, redirects can point to a private address, and DNS answers can change.

## DNS resolution

People use domain names, while network connections use IP addresses. DNS resolution turns a name
such as `example.com` into one or more IPv4 or IPv6 addresses. WebGuard inspects every returned
address before it opens a connection. If the answer mixes a public address with a private one,
WebGuard rejects the target instead of guessing which answer is safe.

## Public and private addresses

Public addresses are intended to be routed across the internet. Private, loopback, link-local,
multicast, reserved, and unspecified ranges have special meanings and must not be reachable
through a public scanning service. IPv4 addresses can also be embedded inside IPv6; WebGuard
unwraps those mapped addresses before deciding whether they are public.

## Redirects

An HTTP response can tell a client to request a different URL. A harmless public address can
redirect to `localhost` or a cloud metadata endpoint. Automatic redirects would skip WebGuard's
decision point, so the safe client processes redirects itself and repeats the full validation for
every destination. It also stops loops and long redirect chains.

## DNS rebinding

In a DNS rebinding attack, a hostname first resolves to a public address that passes validation,
then resolves to a private address when the HTTP library connects. WebGuard prevents this
time-of-check/time-of-use gap by connecting to the exact address it already validated. A fresh
connection requires fresh resolution and validation.

## TLS SNI and certificate hostname validation

HTTPS encrypts a connection and authenticates the server. During the TLS handshake, Server Name
Indication (SNI) tells a shared server which hostname the client wants. Certificate hostname
validation checks that the certificate is valid for that original hostname.

WebGuard connects the TCP socket to a pinned IP address, but it deliberately keeps the original
domain name for SNI and certificate checking. Connecting safely must not weaken HTTPS identity
verification.

## Why checks cannot request URLs directly

Future checks may need information from a landing page or a standardized location such as
`/.well-known/security.txt`. If each check creates its own `httpx` client, one forgotten policy
check could reopen SSRF. Instead, checks will request observations through the scanner, and the
scanner will use `SafeHttpClient`. The lower transport accepts a validated destination object,
not an arbitrary URL.

## Current request flow

1. `URLPolicy` parses and normalizes untrusted text.
2. `Resolver` returns IP addresses for the normalized hostname.
3. `PublicAddressPolicy` rejects the complete set if one address is unsafe.
4. The client selects a validated address and creates a pinned destination.
5. The transport connects to that IP while preserving the hostname for HTTPS.
6. The response is streamed under time and size limits.
7. A redirect starts the same process again.
8. Only bounded, redacted metadata is allowed into public contracts and logs.

Tests inject fake DNS and transport objects. This makes unusual attacks repeatable without adding
a dangerous production switch or connecting the test suite to real private services.

## Unit tests, integration tests, and live networking

A unit test checks a small piece of behavior in isolation. For example, WebGuard can give the IP
policy a private address and confirm that it is rejected. These tests are fast, deterministic, and
make it easy to reproduce rare attack inputs.

An integration test checks several pieces working together. The controlled transport tests connect
the safe client, HTTP wrapper, stream limits, and error mapping through fake network endpoints.
They verify the boundaries between components without requiring a real Internet service.

Mocked networking is valuable because tests can precisely produce timeouts, partial responses,
invalid TLS results, DNS rebinding, and connection failures. Waiting for those conditions to happen
on the public Internet would make the suite slow and unreliable. Mocks must still be paired with
tests of the real adapter setup; otherwise a mock can prove only that the mock works.

Real-network smoke tests confirm that DNS, sockets, TLS, and HTTP work together in the developer's
actual environment. Security tools need both controlled tests and a small real-path check. Live
tests are not authoritative because external DNS, networks, certificates, redirects, and service
availability can change without a WebGuard code change. They are therefore opt-in and excluded
from the normal suite.

Run the optional tests explicitly with:

```powershell
.\.venv\Scripts\python.exe -m pytest -m live backend/tests/live
```

## What an orchestrator does

An orchestrator coordinates a complete scan. WebGuard's `ScanEngine` validates the request,
normalizes the target, creates one request budget, asks the protected client for observations,
runs checks in a fixed order, and assembles the result. It coordinates these jobs without becoming
a security rule itself.

## What ScanContext is

`ScanContext` is an immutable snapshot of what WebGuard safely observed for one scan: the target,
landing response, redirect responses, sanitized headers, bounded body content, connection metadata,
budget state, timestamps, and notices. All checks see the same snapshot, so one check cannot change
the evidence seen by another. It is an internal object, not a public report model.

## Why checks are independent

Each check should answer one narrow security question from the shared observations. If checks
mutate each other's data or depend on execution side effects, one bug can make unrelated results
unreliable. Independent checks are easier to test, reason about, and continue safely after a
failure.

## Why networking is centralized

A normal HTTP request is dangerous when the destination is controlled by a user. Centralizing all
requests keeps URL policy, DNS validation, destination pinning, redirects, timeouts, body limits,
and the shared request budget in one protected path. If a future rule needs `security.txt` or an
HTTP probe, orchestration must collect that observation through `ScanNetworkService`; the rule does
not open the connection itself.

## What failure isolation means

Failure isolation means a broken check does not automatically erase useful results from independent
checks. WebGuard catches expected evaluation failures and unexpected check exceptions, records a
safe error without a traceback, continues in deterministic order, and marks the scan `PARTIAL`.

Three outcomes must not be confused:

- A vulnerability finding is a successfully evaluated security result, including a negative one.
- A check error means WebGuard could not evaluate one rule reliably.
- A network error means the protected client could not collect the main observations, so the scan
  is `FAILED`.

## Why deterministic execution matters

Security results must be reproducible. Stable ordering by configured priority and rule ID makes
output, tests, diffs, debugging, and later scoring predictable. Phase 4 therefore runs checks
sequentially and rejects duplicate rule IDs instead of relying on discovery order or concurrency.

## HTTPS and HTTP

HTTP carries web traffic without transport encryption. HTTPS is HTTP carried inside TLS, which
protects traffic against ordinary network reading and modification and authenticates the server.
WebGuard separately observes whether HTTPS works and whether an HTTP request is redirected to it.
A redirect Location alone is not treated as proof that the HTTPS destination actually works.

## What TLS certificates do

A server certificate binds public-key material to names under rules enforced by certificate
authorities and client trust stores. During a verified TLS handshake, the client checks the trust
chain, the requested hostname, and the certificate validity period. Encryption without those
identity checks would not reliably tell the client which server it reached.

Certificate trust means the chain leads to an authority accepted by the scanner's system trust
store. A self-signed or incomplete chain will normally fail that check. Hostname validation is a
separate question: a trusted certificate for another domain must still be rejected. Expiration is
also separate because certificates are valid only within a defined time window.

WebGuard keeps TLS verification enabled. It classifies a verification failure as expired,
hostname-mismatched, or untrusted and does not expose the raw error. For a successful connection it
retains only the expiration time needed by the rule. Phase 5A warns when 30 days or fewer remain;
that threshold is centralized in `RuleConfig`.

## HSTS

HTTP Strict Transport Security tells a browser to use HTTPS for future visits to a host. A positive
`max-age` enables the policy; zero disables it. `includeSubDomains` can extend it to subdomains.
Preload is optional and is not required for a WebGuard PASS. HSTS is evaluated only on HTTPS because
browsers do not establish an HSTS policy from an insecure HTTP response.

## Content Security Policy

Content Security Policy lets a site restrict where browsers may load scripts, styles, frames, and
other resources. It can reduce the impact of injection bugs, but a header's presence does not prove
that XSS is impossible. Phase 5A checks only that an enforced CSP exists and contains a recognized,
non-empty directive; it is deliberately not a full policy analyzer.

## MIME sniffing and nosniff

Browsers sometimes infer a resource type from bytes instead of trusting `Content-Type`; this is
called MIME sniffing. `X-Content-Type-Options: nosniff` asks the browser to respect the declared
type. WebGuard checks that exact value but does not verify the Content-Type of every site resource.

## Referrer-Policy

A browser may send the previous page's URL when navigating or loading another resource.
Referrer-Policy controls how much of that URL is shared. Different applications can reasonably
choose different policies, so WebGuard accepts several privacy-conscious values, treats clearly
weak values separately, and records a missing explicit policy as informational.

## Permissions-Policy

Permissions-Policy controls access to browser capabilities such as geolocation or camera in a page
and its frames. Whether a capability should be available depends on the application. Phase 5A
therefore checks only presence and obvious syntax problems; it does not guess business intent.

## Clickjacking, X-Frame-Options, and frame-ancestors

Clickjacking places a target page inside a deceptive frame and tricks a user into interacting with
it. `X-Frame-Options: DENY` blocks framing, while `SAMEORIGIN` allows the same origin to frame the
page. CSP `frame-ancestors` is the more flexible modern control and can name permitted parents;
`'none'` blocks all framing. WebGuard prefers `frame-ancestors` when both headers exist and does not
require both mechanisms.

## Missing hardening is not always a vulnerability

Security headers are defense-in-depth controls whose importance depends on content and application
behavior. A missing Permissions-Policy does not prove a dangerous browser feature is used, and a
missing CSP does not prove an injection bug exists. Findings therefore distinguish confirmed
misconfiguration, recommended hardening, informational observation, and inability to evaluate.
Severity communicates the observed posture without claiming an exploit that WebGuard did not test.

## What cookies are

An HTTP cookie is a small name/value item that a server asks a browser to store and send on later
matching requests. Cookies can support login sessions, preferences, analytics, shopping carts, and
many other purposes. Seeing a cookie does not tell WebGuard which purpose it serves.

WebGuard never exposes the value. It keeps only the cookie name and three recognized attributes:
Secure, HttpOnly, and SameSite. Multiple affected cookies are grouped into one finding per
attribute so a page that sets many cookies does not produce a wall of duplicate findings.

### Secure

`Secure` tells a browser to send the cookie only over HTTPS. Missing it on a cookie delivered by an
HTTPS response is useful hardening evidence, but WebGuard does not assume that every cookie is an
authentication cookie. That is why the result is conservative rather than HIGH severity.

### HttpOnly

`HttpOnly` prevents JavaScript from reading a cookie through ordinary browser APIs. It can reduce
the exposure of session cookies if script injection occurs. Some preference or integration cookies
intentionally need JavaScript access, however, so missing HttpOnly is informational and is not
automatically a vulnerability.

### SameSite

`SameSite` controls when a browser includes a cookie with cross-site requests. `Strict` is most
restrictive, `Lax` permits selected navigation flows, and `None` permits cross-site use but must be
paired with `Secure` in modern browsers. A missing setting can weaken CSRF-related hardening, but it
does not prove a cross-site request forgery flaw: exploitability also depends on application
actions, request validation, browser behavior, and other defenses.

## security.txt and responsible disclosure

`security.txt` is a small, machine-readable policy file defined by RFC 9116. A site publishes it at
`https://domain/.well-known/security.txt` so researchers can find an approved contact and current
vulnerability-disclosure instructions. Contact tells a researcher where to report; Expires signals
when the published information has become stale.

Responsible vulnerability disclosure means reporting a suspected flaw through the owner's stated
channel, limiting unnecessary exposure, respecting authorization and scope, and giving the owner a
reasonable opportunity to investigate. A security.txt file helps communication; it does not grant
permission to test a system and its absence is not a vulnerability.

WebGuard fetches only the well-known file through its protected network boundary. It does not fetch
Contact, Policy, Encryption, Canonical, or other URLs found inside the document. Phase 5B checks a
small useful subset: HTTPS delivery, successful bounded UTF-8 plain text, Contact presence, and one
future RFC 3339 Expires value. It is not a complete signature or ABNF validator.

## Mixed content

Mixed content occurs when an HTTPS page refers to a resource over plaintext HTTP. HTTPS protects
the page connection, but an insecure subresource can still be observed or modified on the network.

Active or blockable content such as scripts, iframes, stylesheets, and form submissions can affect
page behavior or sensitive user actions, so WebGuard gives those static references more weight.
Images, audio, and video are lower-risk passive/display content in this simplified classification,
although they still create privacy and integrity concerns.

Phase 5B is deliberately a static check. It parses only the bounded final landing HTML, executes no
JavaScript, downloads no resources, and does not act like a browser. Dynamically generated URLs,
CSS references, `srcset`, and browser upgrade/blocking behavior can therefore create false
negatives or make a reported literal reference harmless in practice.

## Information disclosure and server banners

Response headers such as `Server` and `X-Powered-By` can name software chosen by a server or
framework. A detailed version may help someone inventory a deployment, but banner text can be
generic, removed, stale, misleading, or supplied by an intermediary. Presence is therefore usually
informational, and hiding a banner is not a substitute for patching the real service.

WebGuard does not match banner versions to CVEs. Reliable vulnerability matching would require an
accurate product identity, build and vendor-patch knowledge, configuration context, and a current
vulnerability database. A header cannot provide that proof. Phase 5B records only what the server
explicitly returned and never claims that a named version is exploitable.

## Why security scoring is difficult

A single number can make unlike observations look more precise than they are. HTTPS availability,
a missing optional header, an expired disclosure policy, and a server banner do not carry the same
meaning. A score also becomes misleading when half the checks could not run. WebGuard therefore
treats the number as a summary of its own limited passive controls, not a measurement of every way
a website could be attacked.

## Severity is not scoring weight

Severity describes the security relevance of one observed condition. Weight describes how much a
rule contributes to WebGuard's particular posture model. They are related but not identical. CSP
has more score weight than Permissions-Policy because the tested control has broader defensive
importance in this model; that does not mean every missing CSP is an exploitable vulnerability.

Missing headers are not equal for the same reason. HSTS, CSP, `nosniff`, referrer controls,
browser-feature policy, and framing restrictions defend different risks and have different
confidence limits. Phase 6 stores each rule's weight and warning credit in one versioned file so
the distinction is reviewable instead of hidden in code.

## Why NOT_APPLICABLE cannot mean PASS

If a site sets no cookies, WebGuard cannot evaluate Secure, HttpOnly, or SameSite behavior. Giving
those rules PASS would award 15 free points for controls that were never exercised. Subtracting the
points would also be unfair. NOT_APPLICABLE removes those rules from both earned points and the
denominator, while the breakdown records exactly what was excluded.

## Why errors reduce confidence

An ERROR means WebGuard tried to evaluate an applicable rule but lacked reliable evidence. It is
not a security failure, yet it cannot earn credit. Errors are excluded from score arithmetic and
remain in the applicable coverage denominator. The resulting lower coverage tells a reader that
the visible score rests on less evidence. Below 70% coverage, WebGuard withholds the number and
grade entirely. Essential transport-rule errors also cause withholding even if total coverage is
otherwise high.

## What coverage means

Coverage is evaluated applicable rule weight divided by all applicable rule weight. It is reported
overall and per category. A score of 95 at 100% coverage is better supported by WebGuard's checks
than a score of 95 at 75% coverage. Neither one proves the site is secure: untested application
logic, authorization, dependencies, infrastructure, and active attack paths remain outside this
passive ruleset.

## How deterministic scoring works

Scoring ruleset `1.0` loads category weights, rule weights, status credits, grade thresholds,
minimum coverage, essential rules, and transport caps from `weights.toml`. PASS earns full credit,
FAIL earns none, and each rule defines INFO and WARNING credit. Mixed-content warnings can use a
configured severity-specific fraction without adding policy conditionals to the engine.

The engine uses Decimal arithmetic, normalizes each category over evaluated rules, combines active
category weights, and rounds half-up to a public integer. Identical findings, errors, applicability,
and configuration always produce the same breakdown. Per-rule contributions show available,
earned, and deducted points plus reasons; exclusions show why a rule did not enter the score.

Finally, three visible caps prevent a failed HTTPS availability, certificate-trust, or hostname
control from coexisting with a passing grade. The raw score is retained, the final score is capped
at 59/F only when necessary, and the triggering reason is public. This is a small explicit safety
rule, not a hidden second scoring system.
