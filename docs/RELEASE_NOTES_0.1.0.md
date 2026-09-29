# WebGuard v0.1.0 release notes — draft

**Status:** Release candidate. This release has not been tagged or published.

WebGuard v0.1.0 is the first public-release candidate of Bashar Asaad's passive web security
posture auditor. It is intended for local, authorized assessment through either the terminal or a
complete bundled web interface.

## Highlights

- 19 deterministic passive checks across transport, headers, cookies, static mixed content, and
  disclosure hygiene.
- SSRF-resistant HTTP boundary with URL/DNS/address validation, destination pinning, verified TLS,
  redirect revalidation, and bounded requests/responses.
- Transparent scoring ruleset 1.0 with contributions, coverage, exclusions, withholding, grades,
  and transport caps.
- Human terminal output plus deterministic JSON and self-contained HTML reports.
- Responsive React interface and stateless FastAPI adapter bundled into the Python Wheel.
- One local command, `webguard web`, with automatic port selection/browser opening and optional
  `--host`, `--port`, and `--no-open` controls.

## Important limitations

- WebGuard is not a penetration test and performs no exploitation, credential testing,
  enumeration, fuzzing, port scanning, dependency scanning, or CVE matching.
- Results describe only the bounded evidence and 19 controls WebGuard evaluated.
- A high score does not prove that a website is secure or compliant.
- `FAILED` describes insufficient evidence or a target/network failure; it is distinct from a
  vulnerability finding and may still include established findings.
- The local web command binds only to loopback and is not a public hosting mechanism.
- Public hosting has not been performed or validated.

## Installation

Install the source tree or release Wheel into a Python 3.12+ virtual environment, then run
`webguard web` or `webguard scan URL`. The web bundle is included, so normal use requires no
frontend build tools or second server process.

## Verification status

The release candidate is verified locally through the backend suite, Ruff, strict mypy,
dependency checks, frontend tests/type checking/lint/build, package builds, Wheel-content
inspection, isolated Wheel installation, and local HTTP/API smoke tests. GitHub-hosted CI remains
unverified until the repository is published and the workflow runs there.

## License and branding

The original source code is licensed under MIT. Bashar Asaad's personal name, logo, and visual
identity are covered separately by `BRANDING.md`; modified third-party distributions must not
imply official status or endorsement.
