# Command-line interface

The installed `webguard` command exposes the local web interface and direct terminal scans. Python
3.12 or newer is required.

## Installation

From the extracted repository on Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\webguard.exe --help
```

On Linux or macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/webguard --help
```

A release Wheel can be supplied instead of `.`. Activation is optional when the executable is
invoked by its full virtual-environment path.

## Commands

| Command | Purpose |
| --- | --- |
| `webguard version` | Print the installed WebGuard version. |
| `webguard web` | Start the complete bundled local web interface. |
| `webguard scan URL` | Scan one authorized public HTTP(S) target in the terminal. |

### Web interface

```text
webguard web
webguard web --port 8080
webguard web --host 127.0.0.1
webguard web --no-open
```

By default WebGuard selects an available port and opens the local page. `--no-open` prints the URL
without launching a browser. Only loopback hosts are accepted. See [WEB.md](WEB.md).

### Terminal scan and reports

```text
webguard scan https://example.com
webguard scan https://example.com --format json
webguard scan https://example.com --format json --output result.json
webguard scan https://example.com --report report.html
```

Human output uses restrained Rich tables and panels. JSON sent to standard output contains JSON
only. `--output` is valid only with `--format json`. Output files must use `.json` or `.html`, their
parent directory must already exist, and WebGuard never overwrites an existing file.

## Scan exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed as software execution; findings may still exist. |
| 2 | Invalid target, option, output destination, local host, or local port. |
| 3 | Target/network scan failure. |
| 4 | Partial scan with one or more operational failures. |
| 5 | Unexpected internal WebGuard failure. |

A finding, low score, or F grade does not by itself produce a non-zero exit code. Exit codes
describe execution; findings and scores describe observed posture. Stop the long-running web
interface with `Ctrl+C`.
