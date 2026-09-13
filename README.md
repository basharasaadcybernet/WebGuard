# CyberNet WebGuard

WebGuard is a production-oriented foundation for safe, low-impact inspection of a website's
externally visible security posture. It is not an exploitation framework, vulnerability proof,
or unrestricted HTTP proxy.

This repository currently contains milestones 1-6:

- reproducible Python project configuration;
- stable domain contracts for future CLI, API, and report adapters;
- a fail-closed outbound networking boundary with SSRF protections;
- deterministic scanner orchestration with a shared request budget;
- nineteen passive transport, header, cookie, content, and disclosure checks; and
- versioned, deterministic, coverage-aware scoring with per-rule contributions.

The implemented checks cover HTTPS availability, HTTP upgrade redirects, TLS trust/hostname/
expiration, HTTPS downgrade behavior, HSTS, CSP presence, `nosniff`, Referrer-Policy,
Permissions-Policy, and combined CSP/X-Frame-Options clickjacking protection.
Phase 5B adds grouped Secure/HttpOnly/SameSite cookie observations, an RFC 9116-oriented
`security.txt` check, bounded static mixed-content detection, and separate Server and
X-Powered-By disclosure observations.

The default scanner now produces a transparent score breakdown when at least 70% of applicable
rule weight is evaluated and essential transport evidence is available. No report generator, CLI
scan command, API, frontend, or persistence is implemented.

## Development setup

Python 3.12 or newer is required.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe
```

Optional harmless public-network smoke tests are excluded from normal runs. Invoke them explicitly:

```powershell
.\.venv\Scripts\python.exe -m pytest -m live backend/tests/live
```

These make a small number of ordinary requests to `example.com`, `httpbin.org`, and BadSSL's
certificate test hosts. They require working direct Internet and DNS access.

When Docker is available, the same checks can run in a clean Python 3.12 container:

```powershell
docker compose run --build --rm backend-checks
```

All outbound HTTP access must use `webguard.security.SafeHttpClient`. Real checks receive only
immutable observations; HTTPS and one-hop HTTP probes are collected centrally under the same
per-scan request budget. Fixed auxiliary observations such as `/.well-known/security.txt` are
declared by rule metadata and collected by the same orchestrator and protected client. See
`SECURITY.md` before adding network behavior, `docs/CHECKS.md` for exact rule semantics, and
`docs/SCORING.md` for the complete scoring calculation.

## Product scope

WebGuard will report only the controls it actually evaluates. A favorable result will never
mean that a website is free of vulnerabilities.

> This score reflects only the security controls tested by WebGuard and does not prove that
> the website is free of vulnerabilities.
