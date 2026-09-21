# Command-line interface

The installed `webguard` command is the local interface to the same `ScanEngine` used by the REST
API. Python 3.12 or newer is required.

## Installation

From the repository root on Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

On Linux or macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
```

To install a downloaded GitHub Release Wheel, replace `.` with the Wheel path. WebGuard v0.1.0 is
not documented as a PyPI or standalone-executable distribution.

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

## Simple Windows usage

If the prompt begins with `(.venv)`, the Python virtual environment is already active. Do not
activate it again.

### PowerShell

From the repository directory:

```powershell
.\.venv\Scripts\Activate.ps1
webguard scan https://example.com
```

To run the local API instead of the CLI scan:

```powershell
webguard-api
```

### Windows CMD

From the repository directory:

```bat
.venv\Scripts\activate.bat
webguard scan https://example.com
```

To run the local API instead of the CLI scan:

```bat
webguard-api
```

The API command keeps running until you stop it with `Ctrl+C`. To leave the Python environment in
either shell, run:

```text
deactivate
```

## Linux and macOS usage

Activation is optional. From the repository directory, either activate the environment or invoke
the executable directly:

```bash
source .venv/bin/activate
webguard scan https://example.com
deactivate
```

Equivalent direct invocation:

```bash
.venv/bin/webguard scan https://example.com
```
