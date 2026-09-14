# Transparent posture scoring

WebGuard scoring ruleset `1.0` converts the frozen 19-rule passive result into a deterministic
0-100 posture score. It represents only the controls WebGuard actually evaluated. It is not a
probability of compromise, a vulnerability count, proof of compliance, or proof that a website is
secure.

> This score reflects only the security controls tested by WebGuard and does not prove that the
> website is free of vulnerabilities.

All weights, status credits, grade thresholds, essential-rule behavior, and caps live in
`backend/src/webguard/scoring/weights.toml`. Configuration loading fails if category weights do not
total 100, the configured IDs differ from the real registry, a rule/category assignment is
incomplete, fractions are outside 0-1, grade bands are invalid, or a cap references an unknown
rule/status.

## Category and rule weights

| Category | Weight | Rules |
| --- | ---: | --- |
| Transport Security | 30 | HTTPS availability 10; HTTP redirect 4; TLS trust 6; hostname 4; expiry 3; downgrade 3 |
| Security Headers | 35 | HSTS 7; CSP 10; nosniff 5; Referrer-Policy 4; Permissions-Policy 2; clickjacking 7 |
| Cookie Security | 15 | Secure 7; HttpOnly 3; SameSite 5 |
| Content Protection | 10 | mixed content 10 |
| Information Disclosure / Hygiene | 10 | security.txt 4; Server 3; X-Powered-By 3 |

The exact stable IDs are recorded in the TOML and validated against `default_check_registry()`.
Changing a weight requires a new scoring version and corresponding regression-fixture updates.

## Status credit

PASS always earns 100% and FAIL always earns 0%. INFO and WARNING credit is explicit per rule:

| Rule | INFO | WARNING |
| --- | ---: | ---: |
| `transport.https_available` | 100% | 50% |
| `transport.http_redirect` | 100% | 50% |
| `transport.tls_validity` | 100% | 50% |
| `transport.tls_hostname` | 100% | 50% |
| `transport.tls_expiry` | 100% | 50% |
| `transport.https_downgrade` | 100% | 25% |
| `headers.strict_transport_security` | 100% | 50% |
| `headers.content_security_policy` | 100% | 25% |
| `headers.x_content_type_options` | 100% | 50% |
| `headers.referrer_policy` | 75% | 50% |
| `headers.permissions_policy` | 75% | 50% |
| `headers.clickjacking_protection` | 75% | 25% |
| `cookies.secure` | 100% | 50% |
| `cookies.http_only` | 75% | 50% |
| `cookies.same_site` | 100% | 50% |
| `content.mixed_content` | 100% | 25% default; LOW 50%, MEDIUM 25%, HIGH 0% |
| `hygiene.security_txt` | 50% | 25% |
| `hygiene.server_disclosure` | 100% | 50% |
| `hygiene.x_powered_by` | 100% | 50% |

The mixed-content severity override preserves the rule's passive-versus-active distinction without
embedding content policy in Python conditionals. The reduced INFO credits for missing optional
headers, HttpOnly, and security.txt make their limited hardening/maturity value visible without
calling them vulnerabilities. Generic disclosure INFO remains neutral.

## Applicability, errors, and coverage

NOT_APPLICABLE is never PASS. Its rule weight is removed from both the earned points and score
denominator. For example, when the landing chain sets no cookies, all three cookie findings carry
an explicit `NOT_APPLICABLE` evaluation state: the 15-point cookie category earns nothing, loses
nothing, and has no category coverage value.

NOT_EVALUATED is also excluded from score points, but it remains applicable and therefore reduces
coverage. It represents an operational evidence failure, not a security PASS, FAIL, or deduction.
Overall coverage is:

```text
evaluated applicable rule weight / all applicable rule weight
```

Each category exposes the same calculation. A category with no applicable rules has
`coverage = None`; an applicable category in which every rule errored has zero coverage.

Within a category, earned points are normalized over successfully evaluated rules. Categories with
no evaluated rules do not enter the numerical score. The configured weights of active categories
are then normalized back to 100. This preserves category priorities, avoids free points for
inapplicable controls, and keeps failures visible through coverage.

## Score withholding

The numerical raw score, final score, and grade are all withheld when:

- evaluated coverage is below the configured 70% minimum;
- `transport.https_available`, `transport.tls_validity`, or `transport.tls_hostname` is
  NOT_EVALUATED; or
  or
- no rule produced an evaluated outcome.

The essential-rule condition applies to operational NOT_EVALUATED only. A confirmed negative
transport finding remains evaluated and is handled by its points and cap. A TLS failure that blocks
the landing response leaves dependent header, cookie, content, and disclosure rules
NOT_EVALUATED; those weights reduce coverage and normally cause score withholding. Withheld output
says:

> Scan incomplete — insufficient coverage for a reliable score.

`withholding_reasons` provides the exact machine-readable explanation.

## Rounding, grades, and caps

Decimal arithmetic is used throughout. Raw scores and coverage are rounded half-up to three
decimal places; the published integer score is rounded half-up to the nearest whole number.

- A: 90-100
- B: 80-89
- C: 70-79
- D: 60-69
- F: 0-59

Only three transparent safety caps exist. A FAIL for HTTPS availability, TLS certificate trust, or
TLS hostname validation caps the final score at 59/F. These conditions mean WebGuard could not
establish a reachable, authenticated HTTPS posture; allowing unrelated headers to produce a high
grade would be misleading. The breakdown retains the raw score and records the triggering rule,
maximum score, and configured reason. A cap does not apply when the score is already 59 or lower.

## Per-rule and category output

`RuleContribution` records the stable ID, category, evaluation state, configured/available/earned
points, credit fraction, deduction, concise finding reason, and any exclusion reason.
`CategoryScore` records configured, applicable, evaluated/available, earned and normalized points,
deductions, and coverage. `ScoreBreakdown` adds raw/final scores, grade, scoring version, totals,
exclusions, withholding reasons, and any applied cap. Finding evidence is not copied into scoring
models.

## Worked example

The `average_site` regression profile has a near-expiry certificate; missing/weak HSTS and CSP;
insecure cookie hardening; active mixed content; no usable security.txt; and detailed Server
disclosure. Its category earnings are:

| Category | Earned / evaluated |
| --- | ---: |
| Transport | 28.50 / 30 |
| Headers | 24.00 / 35 |
| Cookies | 8.25 / 15 |
| Content | 2.50 / 10 |
| Hygiene | 6.50 / 10 |

Total earned points are 69.75 of 100 with full coverage. The raw score is 69.750, which rounds to
70 and grade C. No transport cap applies.

Named regression fixtures make policy drift visible:

- `excellent_site`: 100/A, 100% coverage.
- `average_site`: raw 69.750, final 70/C, 100% coverage.
- `weak_site`: 0/F, 100% coverage.
- `transport_broken`: raw 90, capped to 59/F, 100% coverage.
- `low_coverage_site`: 65% coverage; score and grade withheld.

## Known limitations

The model scores only one bounded passive observation set. It does not measure application logic,
authorization, dependency vulnerabilities, exploitability, impact, or controls outside the 19
rules. Category weights and partial credits are explicit policy judgments, not empirical breach
probabilities.

In v0.1, absent and generic Server observations are both INFO, and X-Powered-By presence and
absence are both INFO. Their INFO credit is therefore deliberately neutral; only the Server rule's
version-detail WARNING changes points today. WebGuard does not silently infer stronger banner
outcomes to make those weights appear more active. A future semantic change must update both the
check ruleset and scoring version.
