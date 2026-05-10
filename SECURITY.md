# Security Policy

## Reporting a vulnerability

To report a security issue in the `llmo` CLI:

- Preferred: GitHub Private Vulnerability Reporting at https://github.com/openllmo/cli/security/advisories/new
- Email: security@llmo.org

Please include a description of the issue, the affected CLI version (`llmo --version`), and steps to reproduce.

## Scope

This policy covers the `llmo` CLI source under `src/` and the vendored schema under `src/schema/`. Issues in the LLMO protocol specification or the reference validator are reported at https://github.com/openllmo/llmo.org/blob/main/SECURITY.md.

Out of scope:

- Dependency advisories without a CLI-specific exploitation path (report to the dependency's maintainer).
- Abuse of the LLMO protocol by third parties (not a CLI defect).
- Social engineering or physical attacks against project maintainers.

## Response expectations

- Acknowledgment within 5 business days.
- Triage update within 10 business days.
- Resolution or coordinated disclosure within 90 days.

The full safe-harbor terms and detailed reporting guidance are at https://github.com/openllmo/llmo.org/blob/main/SECURITY.md and apply to reports filed against this repository.
