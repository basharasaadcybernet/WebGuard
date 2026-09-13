# Security Checks

Phase 5B completes nineteen initial passive checks. Rules inspect immutable observations collected through
`SafeHttpClient`; rule modules cannot perform network requests. PASS means the limited condition
described below was observed, not that the site is vulnerability-free. Inapplicable rules emit no
finding. An unavailable required observation becomes an operational check error rather than a
security failure.

## Transport security

### `transport.https_available`

- **Purpose:** Determine whether a verified HTTPS response is available.
- **Checks:** A direct or actually fetched HTTPS response, never a redirect Location alone.
- **PASS:** A protected HTTPS request completed.
- **WARNING/FAIL:** FAIL/MEDIUM for a confirmed unavailable endpoint or classified TLS certificate
  failure. Timeouts and indeterminate network failures are operational check errors.
- **Limitations:** Does not evaluate protocol versions, cipher suites, or application content.
- **References:** [MDN HTTPS](https://developer.mozilla.org/en-US/docs/Glossary/HTTPS).

### `transport.http_redirect`

- **Purpose:** Check whether ordinary HTTP navigation is upgraded to HTTPS.
- **Checks:** One protected HTTP response and its sanitized Location value.
- **PASS:** A standard redirect status points directly to an HTTPS URL.
- **WARNING/FAIL:** FAIL/MEDIUM when HTTP remains available or redirects somewhere other than
  HTTPS; probe failure is an operational error.
- **Limitations:** Checks the normalized target path without its query and does not crawl routes.
- **References:** [MDN HTTPS](https://developer.mozilla.org/en-US/docs/Glossary/HTTPS).

### `transport.tls_validity`

- **Purpose:** Confirm that the server certificate chain is trusted.
- **Checks:** The result of the system trust-store verification used by the real TLS connection.
- **PASS:** Certificate-chain trust validation succeeded.
- **WARNING/FAIL:** FAIL/HIGH for a classified untrusted or self-signed chain.
- **Limitations:** Does not inventory the chain or assess certificate-authority policy.
- **References:** [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

### `transport.tls_hostname`

- **Purpose:** Confirm that the certificate identity covers the requested hostname.
- **Checks:** Hostname verification from the protected TLS handshake.
- **PASS:** The certificate matched the original validated hostname.
- **WARNING/FAIL:** FAIL/HIGH for a classified hostname mismatch.
- **Limitations:** Does not expose or report certificate subject names.
- **References:** [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

### `transport.tls_expiry`

- **Purpose:** Identify expired or soon-to-expire certificates.
- **Checks:** Only the verified peer certificate `not_after` time against scan time.
- **PASS:** More than 30 days remain.
- **WARNING/FAIL:** WARNING/MEDIUM at 30 days or fewer; FAIL/HIGH when expired.
- **Limitations:** The 30-day threshold is configurable. Missing metadata is an evaluation error;
  chain contents are not retained.
- **References:** [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

### `transport.https_downgrade`

- **Purpose:** Detect a redirect transition from HTTPS to plaintext HTTP.
- **Checks:** The validated landing and HTTPS redirect observations.
- **PASS:** No HTTPS-to-HTTP transition was observed.
- **WARNING/FAIL:** WARNING/MEDIUM when a downgrade transition occurred; it is not described as
  proof of compromise.
- **Limitations:** Covers only the bounded redirect chains fetched in this scan.
- **References:** [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).

## HTTP security headers

### `headers.strict_transport_security`

- **Purpose:** Check HSTS hardening on the final HTTPS response.
- **Checks:** One HSTS field, a parseable numeric `max-age`, positive lifetime, and observes
  `includeSubDomains` when present.
- **PASS:** `max-age` is greater than zero; preload is not required.
- **WARNING/FAIL:** Missing or malformed is WARNING/LOW; `max-age=0` is FAIL/MEDIUM.
- **Limitations:** Not applicable to an HTTP-only final response and does not verify preload status.
- **References:** [MDN HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).

### `headers.content_security_policy`

- **Purpose:** Observe baseline enforced CSP posture on HTML.
- **Checks:** Header presence and at least one recognized, non-empty directive.
- **PASS:** A non-empty enforced policy with a recognized directive is present.
- **WARNING/FAIL:** Missing, empty, or obviously unusable policy is WARNING/MEDIUM.
- **Limitations:** Does not grade source expressions or claim that CSP proves XSS prevention.
- **References:** [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).

### `headers.x_content_type_options`

- **Purpose:** Check the browser MIME-sniffing opt-out.
- **Checks:** Exactly `X-Content-Type-Options: nosniff`, case-insensitively.
- **PASS:** The recognized `nosniff` value is present.
- **WARNING/FAIL:** Missing, duplicate, or unexpected value is WARNING/LOW.
- **Limitations:** Does not validate whether every resource has the correct Content-Type.
- **References:** [MDN X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).

### `headers.referrer_policy`

- **Purpose:** Classify the explicit response referrer policy conservatively.
- **Checks:** Recognized comma-separated tokens and the last supported fallback.
- **PASS:** `no-referrer`, `origin`, `origin-when-cross-origin`, `same-origin`, `strict-origin`, or
  `strict-origin-when-cross-origin`.
- **WARNING/FAIL:** Missing is INFO; `unsafe-url` and `no-referrer-when-downgrade` are WARNING/LOW;
  unsupported values are WARNING/LOW.
- **Limitations:** Does not inspect element-level or CSP referrer policy and does not assert one
  universally correct policy.
- **References:** [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).

### `headers.permissions_policy`

- **Purpose:** Observe explicit browser-feature restriction hardening.
- **Checks:** Presence and only obvious `feature=(allowlist)` or wildcard syntax problems.
- **PASS:** A syntactically plausible policy is present.
- **WARNING/FAIL:** Missing is INFO; empty or obviously malformed is WARNING/LOW.
- **Limitations:** Does not decide which browser features are appropriate for the application.
- **References:** [MDN Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).

### `headers.clickjacking_protection`

- **Purpose:** Assess framing restrictions on HTML responses.
- **Checks:** CSP `frame-ancestors` first, then X-Frame-Options when CSP does not define it.
- **PASS:** `frame-ancestors 'none'`, a restricted CSP list containing `'self'`, XFO `DENY`, or XFO
  `SAMEORIGIN`.
- **WARNING/FAIL:** No recognized restriction, empty/wildcard `frame-ancestors`, or malformed XFO is
  WARNING/MEDIUM. Explicit CSP origin lists are INFO because application intent is unknown.
- **Limitations:** Not applicable to non-HTML responses; does not prove a practical clickjacking
  exploit and does not require both CSP and XFO.
- **References:** [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), [MDN frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors), [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options).

## Cookie security

Cookie attributes are parsed only from already-redacted `Set-Cookie` observations across the
validated landing redirect chain. Values never enter check evidence. Each attribute produces one
grouped finding: affected cookie names are sorted, deduplicated, capped for display, and summarized
with affected/total counts. This avoids one finding per cookie while retaining actionable names.

### `cookies.secure`

- **Purpose:** Observe whether cookies set by HTTPS responses opt out of plaintext transport.
- **Checks:** The `Secure` attribute on each redacted cookie observed over HTTPS.
- **PASS:** Every HTTPS cookie observation has `Secure`.
- **WARNING/FAIL:** Missing `Secure` is WARNING/LOW. No cookies, or cookies seen only on HTTP,
  produce INFO/not-applicable and no security credit.
- **Limitations:** Does not determine whether a cookie carries authentication state or observe
  cookies set by JavaScript or unvisited routes.
- **References:** [MDN cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies).

### `cookies.http_only`

- **Purpose:** Observe whether server-set cookies opt out of JavaScript access.
- **Checks:** The `HttpOnly` attribute on redacted cookies in the landing chain.
- **PASS:** Every observed cookie has `HttpOnly`.
- **WARNING/FAIL:** Missing `HttpOnly` is INFO, not a vulnerability, because some cookies
  intentionally support client-side code. No cookies produce INFO/not-applicable.
- **Limitations:** Does not determine cookie purpose, XSS exposure, or client-side cookie usage.
- **References:** [MDN cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies).

### `cookies.same_site`

- **Purpose:** Observe explicit cross-site cookie handling.
- **Checks:** Recognized `Strict`, `Lax`, or `None`; `SameSite=None` must also have `Secure`.
- **PASS:** Every observed cookie has a usable explicit SameSite setting.
- **WARNING/FAIL:** Missing SameSite or `None` without `Secure` is WARNING/LOW and is described as
  CSRF-related hardening, not proof of CSRF. No cookies produce INFO/not-applicable.
- **Limitations:** Does not simulate browser defaults, validate application request flows, or prove
  whether cross-site cookie use is intended.
- **References:** [MDN cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies).

## Static page content

### `content.mixed_content`

- **Purpose:** Find explicit plaintext resource references in the final HTTPS landing HTML.
- **Checks:** `script`/`iframe` sources, stylesheet links, form actions, and practical image/media
  references using literal `http://` URLs.
- **PASS:** No explicit insecure reference is present in the bounded static HTML.
- **WARNING/FAIL:** Script, iframe, stylesheet, or form references are WARNING/MEDIUM; only
  image/media/other link references are WARNING/LOW.
- **Limitations:** Uses Python's non-executing HTML parser. It does not execute JavaScript, expand
  CSS, inspect `srcset`, download resources, or reproduce browser mixed-content decisions. Relative,
  protocol-relative, data, invalid, and dynamically generated URLs are not reported. Duplicate URLs
  are grouped, and displayed absolute URLs have credentials, fragments, and query values removed.
- **References:** [MDN mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content).

## Disclosure and operational hygiene

### `hygiene.security_txt`

- **Purpose:** Observe an RFC 9116-oriented vulnerability disclosure file.
- **Checks:** A protected HTTPS fetch of `/.well-known/security.txt`, status 200, a 64 KiB parsing
  ceiling inside the global response limit, `text/plain`, UTF-8, at least one Contact, exactly one
  parseable RFC 3339 Expires, and a future expiry time.
- **PASS:** The bounded HTTPS response has Contact and a current Expires value.
- **WARNING/FAIL:** Absence or other non-200 response is INFO; HTTP downgrade, missing fields,
  malformed/expired Expires, wrong media type, or invalid UTF-8 is WARNING/LOW. Network, redirect,
  budget, or size failures are operational check errors.
- **Limitations:** This is a small v0.1 parser, not full ABNF, signature, Canonical, or URI
  validation. Contact and other referenced fields remain private text and are never fetched.
- **References:** [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html).

### `hygiene.server_disclosure`

- **Purpose:** Record technology information explicitly returned in `Server`.
- **Checks:** Header absence, generic banner text, and a conservative version-like pattern.
- **PASS:** None; absence and generic presence are INFO and do not award artificial credit.
- **WARNING/FAIL:** Explicit version-like detail is WARNING/LOW because it may aid inventorying.
- **Limitations:** Does not fingerprint beyond the header, determine the true backend, or match
  versions to CVEs. A banner is not itself an exploitable vulnerability.
- **References:** [OWASP framework fingerprinting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework).

### `hygiene.x_powered_by`

- **Purpose:** Record application technology explicitly returned in `X-Powered-By`.
- **Checks:** Header presence and sanitized bounded text.
- **PASS:** None; presence and absence are both INFO.
- **WARNING/FAIL:** None in v0.1.
- **Limitations:** Does not infer technology, verify accuracy, or perform version-to-CVE matching.
- **References:** [OWASP framework fingerprinting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework).

Phase 6 assigns every stable rule a configuration-driven weight and status credit. Check logic
still contains no scoring constants. Explicit NOT_APPLICABLE cookie outcomes, omitted findings for
other inapplicable rules, and operational errors are excluded according to
[the scoring model](SCORING.md); they are never treated as passing findings.
