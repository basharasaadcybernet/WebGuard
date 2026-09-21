# WebGuard v0.1.0 release notes — draft

**Status:** Release candidate. This release has not been tagged or published.

WebGuard v0.1.0 is the first public-release candidate of Bashar Asaad's passive web security
posture auditor. It is intended for local, authorized assessment through either a Python CLI or a
complete Docker-hosted web interface.

## Highlights

- 19 deterministic passive checks across transport, headers, cookies, static mixed content, and
  disclosure hygiene.
- SSRF-resistant HTTP boundary with URL/DNS/address validation, destination pinning, TLS hostname
  preservation, redirect revalidation, and bounded requests/responses.
- Transparent scoring ruleset 1.0 with per-rule contributions, coverage, exclusions, withholding,
  grades, and transport caps.
- Human CLI output plus deterministic JSON and self-contained, script-free HTML reports.
- Stateless FastAPI adapter and a responsive React interface that display the same report contract.
- Non-root, read-only backend/frontend containers behind a same-origin Nginx gateway.
- Local-only Docker profile bound to `127.0.0.1:8080` with no direct backend publication.

## Important limitations

- WebGuard is not a penetration test and performs no exploitation, credential testing,
  enumeration, fuzzing, port scanning, dependency scanning, or CVE matching.
- Results describe only the bounded evidence and 19 controls WebGuard evaluated.
- A high score does not prove that a website is secure or compliant.
- `FAILED` describes insufficient assessment evidence or a target/network failure; it is distinct
  from a vulnerability finding and may still include established findings.
- Public hosted deployment has not been performed. The Docker workflow is for local use; a future
  hosted beta requires separate infrastructure validation.

## Installation routes

- Install the Python source tree or release Wheel into a Python 3.12+ virtual environment, then use
  the `webguard` command.
- Build and run the full local web interface with Docker Compose and open
  `http://webguard.localhost:8080`.

See the root README for complete Windows, Linux, and macOS commands.

## Verification status

The release candidate passed the following local verification on Windows with Docker Desktop and
WSL 2:

- 453 backend tests passed and 5 opt-in live tests were deselected; Ruff, strict mypy, and
  `pip check` passed;
- 28 frontend tests passed and 1 was skipped; TypeScript, ESLint, and the production Vite build
  passed;
- the Wheel and source distribution built as version `0.1.0`, and the Wheel metadata, MIT license,
  and packaged scoring data were inspected;
- the Wheel installed in a fresh Python 3.12 virtual environment and generated JSON and HTML from
  one low-impact `example.com` scan without using the development `.venv`; and
- production and local-validation Compose configuration, clean-checkout image builds, Nginx
  configuration, container health/startup, and a local HTTP/API end-to-end scan passed at
  `http://webguard.localhost:8080`.

A representative local-interface screenshot was captured and visually reviewed; it contains only
the WebGuard identity, explanatory interface copy, and the reserved `example.com` placeholder.
GitHub-hosted CI remains unverified until the repository is published and the workflow runs there.

## License and branding

The original source code is licensed under MIT. Bashar Asaad's personal name, logo, and visual
identity are covered separately by `BRANDING.md`; modified third-party distributions must not
imply official status or endorsement.
