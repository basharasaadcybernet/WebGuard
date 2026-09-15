# CyberNet WebGuard

WebGuard is a production-oriented foundation for safe, low-impact inspection of a website's
externally visible security posture. It is not an exploitation framework, vulnerability proof,
or unrestricted HTTP proxy.

This repository currently contains milestones 1-10:

- reproducible Python project configuration;
- stable domain contracts for future CLI, API, and report adapters;
- a fail-closed outbound networking boundary with SSRF protections;
- deterministic scanner orchestration with a shared request budget;
- nineteen passive transport, header, cookie, content, and disclosure checks; and
- versioned, deterministic, coverage-aware scoring with per-rule contributions; and
- a Typer/Rich CLI plus versioned JSON and self-contained HTML reports; and
- a minimal FastAPI REST adapter with bounded admission, rate, request, and execution controls; and
- a responsive CyberNet-branded React/TypeScript application for interactive local scans; and
- fail-closed production configuration, hardened containers, a same-origin reverse-proxy example,
  security headers, cache policy, and controlled-beta deployment guidance.

The implemented checks cover HTTPS availability, HTTP upgrade redirects, TLS trust/hostname/
expiration, HTTPS downgrade behavior, HSTS, CSP presence, `nosniff`, Referrer-Policy,
Permissions-Policy, and combined CSP/X-Frame-Options clickjacking protection.
Phase 5B adds grouped Secure/HttpOnly/SameSite cookie observations, an RFC 9116-oriented
`security.txt` check, bounded static mixed-content detection, and separate Server and
X-Powered-By disclosure observations.

The default scanner produces a transparent score breakdown when at least 70% of applicable rule
weight is evaluated and essential transport evidence is available. Phase 7 presents that same
public result through terminal, JSON, and offline HTML output. Phase 8 exposes the same immutable
report contract through a stateless `/api/v1/` API; it adds no scanner or scoring logic. Phase 9
adds a production-build-ready frontend that displays this contract without recalculating it. No
database, persistence, history, monitoring, public deployment, or active scanner is implemented.
Phase 10 prepares provider-neutral artifacts only; it does not publish the service.

## Development setup

Python 3.12 or newer is required.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe
```

The editable installation provides the real `webguard` and `webguard-api` executables:

```powershell
webguard --help
webguard version
webguard scan https://example.com
webguard scan https://example.com --format json
webguard scan https://example.com --format json --output result.json
webguard scan https://example.com --report report.html
webguard-api
```

The API development server binds to `127.0.0.1:8000` by default. Its three endpoints are
`GET /api/v1/health`, `GET /api/v1/version`, and `POST /api/v1/scans`. See `docs/API.md` for the
request/response contract, environment settings, status policy, and production deployment
requirements. FastAPI docs are available at `/docs` unless explicitly disabled.

Production mode requires explicit bind, Host, and CORS decisions and rejects debug or wildcard
trust. See `docs/DEPLOYMENT.md`, `.env.example`, and `docs/PRODUCTION_CHECKLIST.md` before running a
controlled beta. The preferred topology serves the static frontend and `/api/` through one HTTPS
origin while keeping the API listener private. `requirements.production.txt` pins the reviewed
Python 3.12 container resolution; the frontend uses its committed npm lockfile.

Run the local product in two terminals:

```powershell
# Terminal 1, from the repository root
.\.venv\Scripts\webguard-api.exe

# Terminal 2
cd frontend
npm.cmd install
npm.cmd run dev
```

The API listens on `http://127.0.0.1:8000` and Vite on `http://127.0.0.1:5173`. Vite proxies
same-origin `/api` requests during development. Set `VITE_WEBGUARD_API_URL` at build time only
when the production frontend will call a different API origin. Frontend commands are documented
in `docs/FRONTEND.md`; a production bundle is created with `npm.cmd run build`.

JSON sent to stdout contains JSON only. WebGuard refuses to overwrite report files, and report
parent directories must already exist. See `docs/CLI.md` for exit codes and output behavior, and
`docs/REPORTING.md` for schema and HTML security details.

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

Production-oriented images and a local-only-by-default Compose example are separate from that
check container. Validate them only after setting the reserved Host placeholder:

```powershell
$env:WEBGUARD_ALLOWED_HOSTS = "webguard.example.invalid"
docker compose -f docker-compose.production.yml config
```

All outbound HTTP access must use `webguard.security.SafeHttpClient`. Real checks receive only
immutable observations; HTTPS and one-hop HTTP probes are collected centrally under the same
per-scan request budget. Fixed auxiliary observations such as `/.well-known/security.txt` are
declared by rule metadata and collected by the same orchestrator and protected client. See
`SECURITY.md` before adding network behavior, `docs/CHECKS.md` for exact rule semantics,
`docs/SCORING.md` for scoring, `docs/REPORTING.md` for the report boundary, and `docs/API.md` for
the REST boundary.

## Product scope

WebGuard will report only the controls it actually evaluates. A favorable result will never
mean that a website is free of vulnerabilities.

> This score reflects only the security controls tested by WebGuard and does not prove that
> the website is free of vulnerabilities.
