# Command-line interface

The installed `webguard` command is the local Phase 7 interface to the same `ScanEngine` used by
future adapters.

```powershell
webguard --help
webguard version
webguard scan https://example.com
webguard scan https://example.com --format json
webguard scan https://example.com --format json --output result.json
webguard scan https://example.com --report report.html
```

Human output uses restrained Rich tables and panels. Structured JSON written to standard output
contains JSON only. Confirmations and command errors use standard error so shell pipelines are not
corrupted. `--output` is valid only with `--format json`.

Output files must use `.json` or `.html`, and their parent directory must already exist. WebGuard
creates new files exclusively and never silently overwrites an existing report.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed as software execution; findings may still exist. |
| 2 | Invalid target, invalid option combination, or invalid output destination. |
| 3 | Target/network scan failure. |
| 4 | Partial scan with one or more operational failures. |
| 5 | Unexpected internal WebGuard failure. |

A security finding, low score, or F grade does not itself produce a non-zero exit code. Exit codes
describe command execution, while findings and scores describe observed posture.
