# WebGuard v0.1.0 public release checklist

This checklist covers source publication and local use. It does not authorize or validate a
publicly hosted scanner.

## Release candidate

- [x] Original source code is licensed under MIT with Bashar Asaad as copyright holder.
- [x] Personal branding is governed separately without restricting MIT code rights or truthful
  attribution.
- [x] Python package and application version are `0.1.0`.
- [x] README documents CLI, reports, Docker local use, limitations, and authorized use.
- [x] Windows and POSIX command variants are documented.
- [x] Local Docker binds the frontend to loopback and does not publish the backend.
- [x] No private `.env`, report, log, credential, or large generated binary is tracked.
- [x] Owner has approved the final branding policy direction and closeout language.
- [x] Owner has approved publication of the existing Git author metadata; history and commit
  identities remain unchanged.
- [x] Owner selected GitHub Private Vulnerability Reporting as the intended private disclosure
  channel; no contact email is designated.

## Verification before the preparation commit

- [x] Full backend tests, security tests, Ruff, strict mypy, and `pip check` pass.
- [x] Frontend tests, TypeScript, ESLint, and production build pass.
- [x] Wheel and source distribution build with version `0.1.0`, MIT metadata, LICENSE, and scoring
  data included.
- [x] The Wheel installs in a fresh isolated environment and runs CLI version, JSON, and HTML report
  commands without relying on the development `.venv`.
- [x] Production and local-validation Compose configurations pass.
- [x] Nginx configuration and the local HTTP/API smoke test pass using
  `http://webguard.localhost:8080`.
- [x] Documentation links, release diff, and `git diff --check` pass.
- [x] A representative browser screenshot of the local idle interface is included and contains no
  personal, client, or scan-result data.

## Publication — separately approved only

- [ ] Owner reviews the release candidate and all unresolved items.
- [ ] GitHub repository is created and branch protection/security settings are reviewed.
- [ ] GitHub Private Vulnerability Reporting is enabled before the repository is made public.
- [ ] CI succeeds on the future GitHub repository.
- [ ] The preparation commit is tagged `v0.1.0`.
- [ ] The Wheel, source archive, checksums, and reviewed release notes are attached to the release.

Do not check hosted-beta TLS, DNS, firewall, egress, monitoring, public smoke-test, or rollback
requirements here; those remain in `PRODUCTION_CHECKLIST.md` for the separate hosted-beta phase.
