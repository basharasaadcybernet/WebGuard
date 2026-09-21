# JSON and HTML reporting

Phase 7 uses one pure reporting pipeline:

```text
ScanEngine -> ScanResult -> ReportBuilder -> ReportDocument
                                      |-> JSON
                                      |-> self-contained HTML
                                      |-> terminal presentation
```

`ReportBuilder` consumes only immutable public `ScanResult` and `ScoreBreakdown` data. It has no
network client and cannot fetch subresources. Internal response bodies, pinned destinations, raw
queries, socket state, and exception objects are not part of `ReportDocument`.

## Versioned JSON schema

Report schema `1.0` is independent from the WebGuard software and scoring ruleset versions. The
document includes all three, plus the public target, scan metadata/state, severity counts, score
and coverage breakdown, ordered non-pass findings, operational errors, methodology, limitations,
and the permanent disclaimer. Decimal values remain exact strings. Serialization is deterministic
for identical input, and HTML-sensitive JSON delimiters are Unicode escaped.

## Self-contained HTML

The HTML renderer embeds neutral, print-friendly CSS and no JavaScript, fonts, images, stylesheets,
or CDN assets. It includes report identity, metadata, posture/coverage, category and severity
summaries, finding summaries and details, score contributions, operational errors, methodology,
limitations, references, and the disclaimer. It is a posture assessment, not a penetration-test
report.

Every target-derived value passes through contextual HTML escaping. Reference and evidence links
accept only HTTP or HTTPS schemes. A restrictive CSP blocks scripts, connections, objects, forms,
and base-URL changes. Tests inject script tags, event attributes, malicious banners, cookie names,
redirect text, evidence, descriptions, and unsafe URLs to verify they remain inert text.

Generated output is intentionally neutral and isolated from the Bashar Asaad application theme,
so branding can be changed without coupling presentation to scanning or scoring logic.
