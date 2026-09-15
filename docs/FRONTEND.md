# Phase 9 frontend

The `frontend/` directory contains the React 19, TypeScript, and Vite application for CyberNet
WebGuard. It is a stateless browser client for the Phase 8 REST API. It adds no checks, scanner
networking, scoring rules, accounts, history, persistence, analytics, or deployment configuration.

## Component and state architecture

```text
App
|-- AppHeader
|-- ScanHero
|-- idle: ScopeOverview
|-- scanning: ScanProgress
|-- error: ErrorState
`-- success: ResultsView
    |-- ScoreCard
    |-- SeveritySummary
    |-- CategoryBreakdown
    |-- OperationalErrors
    |-- FindingsSection -> FindingCard
    |-- optional future expertRecommendations slot (empty in Phase 9)
    |-- limitations and permanent disclaimer
    `-- ProfessionalCTA
```

`useScan` owns the small `idle -> scanning -> success | error` state machine and the active
AbortController. `src/api/client.ts` is the only fetch layer. It sends the target exactly as
validated, adds a browser-side timeout, maps public API failures to fixed copy, and validates the
success envelope before components render it. `src/api/types.ts` mirrors the actual Phase 8
public response contract.

The API remains authoritative. Components display `score`, `raw_score`, `grade`, `coverage`, caps,
categories, findings, and completion state from `ReportDocument`; they never reproduce backend
scoring logic. Severity filtering and disclosure state are local presentation state only.

Phase 9.5 labels rule-linked operational limitations as NOT EVALUATED, labels genuine
inapplicability as N/A, and retains FAIL solely for evaluated negative security findings. A
withheld score remains unavailable rather than becoming zero. When a successful landing chain sets
no cookies, the API still carries the three independent NOT_APPLICABLE cookie outcomes for
auditability and scoring; the findings view groups that exact pattern into one concise Cookie
Security context card. It does not turn absence into a PASS or change the backend score. Finding
details omit a scoring reason only when it is textually identical to the visible description;
distinct exclusion and cap reasons remain visible.

## Local development

Python 3.12 and Node 22.12 or newer are required. From the repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\webguard-api.exe
```

In a second terminal:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

The API defaults to `http://127.0.0.1:8000`; Vite serves `http://127.0.0.1:5173` and proxies
development `/api` requests to that API. This keeps browser calls same-origin locally.

Copy `.env.example` to an ignored local environment file only when configuration is needed:

```text
VITE_WEBGUARD_API_URL=https://api.example.invalid
VITE_CYBERNET_CONTACT_URL=https://contact.example.invalid
```

`VITE_WEBGUARD_API_URL` is optional. When absent, builds use the same-origin `/api/v1/scans` path;
no development API host is baked into production. Set it in the build environment when a deployed
frontend and API have different origins, and configure the backend CORS/Host allowlists separately.
`VITE_CYBERNET_CONTACT_URL` accepts HTTP(S) or `mailto:` and otherwise leaves an honest disabled
contact action. All `VITE_` variables are public bundle data and must never contain secrets.

## Verification commands

```powershell
cd frontend
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
```

Tests use controlled fixtures and no live Internet. They cover submission and keyboard behavior,
validation, loading and cancellation, completed/partial/failed results, 100/A, weak, capped and
withheld scores, not-evaluated limitations, grouped cookie N/A context, duplicate-text suppression,
service errors, filtering, native disclosures, malicious values, reference-link safety, responsive
rules, and reduced motion.

An explicitly opt-in local integration check can exercise the running API and compare its returned
score, grade, coverage, and finding count with the React-rendered result:

```powershell
$env:WEBGUARD_LIVE_API_URL = "http://127.0.0.1:8000"
npm.cmd run test:integration
Remove-Item Env:WEBGUARD_LIVE_API_URL
```

This opt-in check performs one real scan of `https://example.com`; it is skipped in the normal test
suite and must be used only where that harmless outbound request is authorized.

The production bundle is written to `frontend/dist/`. Phase 9 does not supply a public host,
reverse proxy, Netlify/Vercel/Cloudflare configuration, or deployment procedure.

## Simple Windows usage

Start `webguard-api` in one terminal using the instructions in [CLI.md](CLI.md). If the prompt
begins with `(.venv)`, Python's virtual environment is already active. In a second terminal, enter
the frontend project and start Vite.

### PowerShell

```powershell
cd frontend
npm run dev
```

### Windows CMD

```bat
cd frontend
npm run dev
```

Open the local address Vite prints. Stop either server with `Ctrl+C`. Run `deactivate` in a terminal
that shows `(.venv)` when you want to leave the Python environment. If PowerShell's script policy
blocks the `npm` launcher, use `npm.cmd run dev` for the same command.

## Failed and partial assessment presentation

An HTTP 200 response containing a valid `ReportDocument` always enters the results view.
`COMPLETED`, `PARTIAL`, and `FAILED` describe assessment coverage; they are not frontend or server
exceptions. A valid FAILED report shows its target, status, withheld score, coverage, established
findings, and safe operational limitations. Repeated rule-level `check.evaluation_failed` entries
are summarized as one not-evaluated count with optional affected-rule details.

HTTP 429, 503, and 504 retain their dedicated request-error guidance. API connectivity failures
remain distinct. The generic internal-problem screen is reserved for HTTP 500, malformed successful
responses, unexpected frontend exceptions, and genuine internal service failures.

## Browser security and accessibility

All report content is untrusted text. The application uses no raw HTML insertion, rejects malformed
success payloads, filters references to credential-free HTTP(S), and opens them with `noopener
noreferrer`. Target content is never executed or evaluated. The browser cannot alter the scanner's
network policy or scoring inputs.

The interface uses semantic headings and landmarks, associated labels, visible keyboard focus,
native `details`/`summary`, live loading and error announcements, textual severity labels, strong
contrast, reduced-motion behavior, and overflow-safe URL/evidence presentation. Desktop, tablet,
mobile, and narrow-mobile arrangements are explicitly defined.
