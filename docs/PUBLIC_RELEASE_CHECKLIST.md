# WebGuard v0.1.0 public release checklist

This checklist covers source publication and local use. It does not authorize or validate a
publicly hosted scanner.

## Release candidate

- [x] Original source is MIT-licensed with Bashar Asaad as copyright holder.
- [x] Personal branding is governed separately without restricting MIT rights or truthful
  attribution.
- [x] Package and application version are `0.1.0`.
- [x] README documents installation, `webguard web`, terminal reports, limitations, and authorized
  use.
- [x] The web interface is bundled in the Python package and needs no second end-user server.
- [x] The local web command accepts loopback hosts only and chooses an available port by default.
- [x] No private environment file, report, log, credential, or large generated binary is tracked.
- [x] Existing Git author metadata remains unchanged as approved by the owner.
- [x] GitHub Private Vulnerability Reporting is the intended private disclosure channel; no contact
  email is designated.

## Local verification

- [x] Backend tests, Ruff, strict mypy, and dependency checks pass.
- [x] Frontend tests, TypeScript, ESLint, and production build pass.
- [x] Wheel contains version/license/scoring data and the complete web bundle.
- [x] A fresh isolated Wheel installation runs CLI help/version and the local web interface.
- [x] Local page, health endpoint, security/cache headers, and a bounded scan flow pass.
- [x] Documentation links and `git diff --check` pass.
- [x] The representative local-interface screenshot contains no personal, client, or scan-result
  data beyond the approved publisher identity.

## Publication — separately approved only

- [ ] Owner reviews the final release candidate.
- [ ] Official GitHub repository and security settings are created.
- [ ] GitHub Private Vulnerability Reporting is enabled before publication.
- [ ] CI succeeds in the official repository.
- [ ] The approved commit is tagged `v0.1.0`.
- [ ] Wheel, source archive, checksums, and reviewed notes are attached to the release.

Public HTTPS, DNS, ingress/egress firewalls, monitoring, public smoke testing, and server rollback
remain unverified and out of scope for this local release workflow.
