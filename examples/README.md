# WebGuard examples

Run examples only against systems you own or are authorized to assess. `example.com` is used below
as a reserved documentation target; live results can change and are not authoritative regression
fixtures.

```text
webguard scan https://example.com
webguard scan https://example.com --format json
webguard scan https://example.com --format json --output result.json
webguard scan https://example.com --report report.html
```

WebGuard creates output files exclusively and will not overwrite an existing report. The JSON and
HTML documents contain the public target, assessment state, coverage, score when available,
findings, operational errors, methodology, and limitations. They exclude response bodies, cookie
values, authorization values, sensitive query values, pinned addresses, and socket details.

An illustrative, shortened JSON shape is:

```json
{
  "report_schema_version": "1.0",
  "webguard_version": "0.1.0",
  "completion_state": "COMPLETED",
  "target": {
    "display_url": "https://example.com/"
  },
  "score": {
    "score": "site-dependent",
    "coverage": "site-dependent"
  },
  "findings": [],
  "operational_errors": []
}
```

The placeholders above deliberately avoid presenting a live site's score as a stable expected
result. See `docs/REPORTING.md` for the complete versioned contract.
