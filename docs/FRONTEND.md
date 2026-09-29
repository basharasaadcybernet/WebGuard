# Frontend

The WebGuard interface is a React and TypeScript single-page application. Its production bundle is
included in the Python package and served by `webguard web` on the same origin as the API.

## End-user behavior

End users install only the Python package and run:

```text
webguard web
```

They do not need Node.js or a separate development server. See [WEB.md](WEB.md).

## Development

Node.js 22.13+ is required only when changing the frontend. Install the Python project in editable
mode, then start the local API/bundled page on the development proxy port:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\webguard.exe web --port 8000 --no-open
```

In a second terminal:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

Open the Vite URL printed in the second terminal. Its `/api` requests are proxied to the local
WebGuard process at `127.0.0.1:8000`. Scanned data remains untrusted text; components do not insert
raw HTML, and technical reference links are scheme-validated.

The only optional public build value is `VITE_CYBERNET_CONTACT_URL`, which accepts an HTTP(S) or
`mailto:` destination for the professional-review action. If absent or invalid, the action remains
honestly disabled. Never place secrets in a `VITE_` value because build values become public
JavaScript.

## Verification and bundle generation

```powershell
cd frontend
npm.cmd ci
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
```

The build writes directly to `backend/src/webguard/web/static/`, replacing the prior generated
bundle. That directory is intentionally versioned so source archives and Wheels work without a
Node.js build step. Source maps are disabled. The generated bundle must be committed whenever
frontend source changes.

Tests cover submission and keyboard behavior, validation, loading/cancellation, all completion
states, scoring edge cases, operational limitations, malicious strings, safe links, responsive
rules, and reduced motion. The optional `WEBGUARD_LIVE_API_URL` integration test may perform one
authorized real scan and is skipped by the normal suite.

## Presentation boundary

The API report is the sole authority for scores, grades, caps, findings, and completion state. The
frontend only validates and presents that contract. `COMPLETED`, `PARTIAL`, and `FAILED` describe
assessment coverage; a valid failed report still renders established findings and safe operational
limitations.
