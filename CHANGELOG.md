# Changelog

## [Unreleased]

## [0.1.10] - 2026-05-11

Security-review hardening of v0.1.9's postinstall hook and skill
vendor pipeline. Re-vendors the skill at openllmo/llmo.org commit
`a7100ce` (PR #133), which tightens phases 05, 07, and 08 of the
`/llmo` skill (per-email-domain DNS verification clarification, `kid`
regex validation, literal-filename `rm`). Same protocol parity as
v0.1.9; same two-command publish flow (`npm install -g llmo` →
`/llmo` in Claude Code).

### Security

- **`scripts/postinstall.js`: `cpSync` no longer dereferences symlinks** (`dereference: false`, `verbatimSymlinks: false`). Pre-copy, the script walks `skill/` and refuses to install if any symlink is present. Closes the class where a symlink shipped in the vendored skill would dereference at install time and read a file from outside the install path when the Claude Code harness loaded the phase.
- **`scripts/postinstall.js`: `LLMO_SKILL_DIR` is normalized and confined to HOME** via `path.resolve()` + prefix check. Out-of-HOME targets are refused unless `LLMO_ALLOW_OUT_OF_HOME=1` is set (CI test escape hatch). Closes the class where a transitive postinstall earlier in the same `npm install` could set `LLMO_SKILL_DIR=/etc/cron.d` and redirect our writes there.
- **`scripts/postinstall.js`: refuses to run under root unless `LLMO_ALLOW_ROOT_INSTALL=1`** is set. `sudo npm install -g llmo` no longer writes skill files into the root user's home directory by surprise. Ordinary unprivileged installs are unaffected.

### Changed

- **`scripts/vendor.sh`: skill source is pinned via `LLMO_SKILL_REF`** with the resolved ref recorded to `skill/.vendored-from` after a successful fetch. Resolution order: `LLMO_SKILL_REF` env var → contents of `skill/.vendored-from` → `main` (TOFU fallback for first-time vendoring). The vendor-drift CI job uses the pin transparently; bumps go through `LLMO_SKILL_REF=<sha> ./scripts/vendor.sh`.
- **`skill/.vendored-from` (new)** records the upstream commit SHA the current `skill/` was vendored from. Pinned to `a7100ce7a549828795e014560ea858d8dbeed43c` for this release.
- **`.github/workflows/ci.yml` vendor-drift PR check** extended to cover `skill/` (was previously scoped to `src/schema` and `test/fixtures` only). A PR with skill content out-of-sync with the pinned upstream SHA will now fail the gate at PR time, not only at the scheduled daily run.
- **`.github/workflows/vendor-drift.yml` issue body** generalized to mention `src/schema/`, `test/fixtures/`, and `skill/` since the workflow already runs unfiltered `git diff --exit-code`.

### Skill content (vendored)

Re-vendor pulls in the three skill phase doc tightenings from openllmo/llmo.org PR #133:

- Phase 05 (verify-contacts): documents that DNS verification is per email-address domain, not per apex. A publisher with addresses at both `example.com` and `mail.example.com` adds two TXT records.
- Phase 07 (keygen): requires the publisher-supplied `kid` to match `^[a-z0-9][a-z0-9-]{0,31}$` before any shell or filename use. Closes an injection vector via identifiers that reach `rm`, `llmo keygen --kid`, `llmo sign --kid`, and `llmo-private-<kid>.pem`.
- Phase 08 (sign): the `rm` to delete the private key uses the literal filename string emitted by `llmo keygen` in phase 07. No re-templating, no globs, no relative paths with `..`.

## [0.1.9] - 2026-05-11

Bundles the `/llmo` Claude Code skill into the npm package. After
`npm install -g llmo`, typing `/llmo` in any Claude Code session
launches a guided publish wizard (TurboTax-style) that walks
non-developer publishers through the full lifecycle: interview, derive
claims from public sources, review, verify domain control via DNS TXT,
optional `dns_corroboration`, keygen + custody, sign, deploy, and live
validation. No protocol or schema changes; spec parity remains at
v0.1.8.

### Added

- `skill/` directory containing the `/llmo` Claude Code skill, vendored
  from `https://raw.githubusercontent.com/openllmo/llmo.org/main/.claude/skills/llmo/`
  via `scripts/vendor.sh`. The skill comprises `SKILL.md` (orchestrator),
  `README.md` (install + invocation), and ten phase files under
  `phases/` (01-greet through 10-validate). ~900 lines total.
- `scripts/postinstall.js`: copies the bundled skill into
  `~/.claude/skills/llmo/` so `/llmo` is available in Claude Code
  immediately after install. Idempotent on upgrades (overwrites with the
  version shipped in the release). Non-fatal: errors log a warning and
  the install proceeds. Honors `LLMO_SKILL_DIR` env var for testing.
- `package.json` `files` extended to include `skill/` and the
  postinstall script.
- `scripts/vendor.sh` extended to fetch the skill files from
  `raw.githubusercontent.com/openllmo/llmo.org/main` alongside the
  schema and test fixtures. Re-running `scripts/vendor.sh` refreshes the
  bundled skill the same way it refreshes the schema; the existing
  vendor-drift CI job covers both.

## [0.1.8] - 2026-05-11

Implementer parity with llmo.org's v0.1.8 spec release. The CLI's vendored schema is refreshed to v0.1.8 (six new core claim types, five new top-level optional fields, structured `external_ids` with a new `irs_ein` well-known key, `provenance_markers` on the claim envelope, three schema-encoded conditional constraints). The CLI's S4 URL-ownership dispatch gains the `categories` claim type with schema.org primary and secondary URIs classified as third-party-allowed. The per-claim verify output surfaces `provenance_markers` when populated, matching the validator at https://llmo.org/validator/.

### Changed

- `src/schema/v0.1.json` re-vendored from `https://llmo.org/spec/v0.1/schema.json`. The schema's `$id` is unchanged (in-place patch convention per llmo.org [ADR-0006](https://llmo.org/adr/0006-version-bump-and-release-cut/)); contents now include the v0.1.8 additions. Documents conforming to any earlier v0.1.x patch continue to validate unchanged.
- `src/lib/tier.ts` `collectClaimUrls` extended for the new `categories` claim type. Schema.org Organization subtype URIs in `categories.primary` and `categories.secondary` are classified as third-party-allowed for S4, matching the treatment of `pointer.url` and the parallel logic in `static/js/validator.js` on llmo.org. The other five new claim types (`contact_points`, `locations`, `hours`, `attributes`, `operational_status`) have no URL-typed fields S4 evaluates.
- `src/commands/verify.ts` `PerClaimSignatureResult` gains a `provenance_markers?: string[]` field. The verify command extracts the claim envelope's `provenance_markers` array (when populated) and surfaces it in both the JSON output and the human-readable text output under a new "Per-claim provenance markers:" section. Advisory signal per [ADR-0007](https://llmo.org/adr/0007-claude-as-builder/): consumers MAY use as confidence or freshness signal but MUST NOT treat as authoritative.
- `src/lib/schema.ts` AJV setup adds `strictRequired: false`. v0.1.8 uses the idiomatic JSON Schema conditional-required pattern (`if`/`then` with `required` in the `then` block; the required properties are defined in the parent schema's `properties` via `allOf` composition). AJV's `strictRequired=true` (default under strict) rejects this even though the schema is valid Draft 2020-12. We keep `strict: true` for unknown-keyword detection and opt out of the same-scope-properties requirement only.

### Added

- `test/tier.test.ts` v0.1.8 categories S4 third-party-allowed test (89 tests total, all passing).

## [0.1.7] - 2026-05-08

Same-day follow-up release closing two small surfaces from the v0.1.6 publish:
the CLI's `--version` output is now derived from package.json (closing a
release-versioning SSOT gap); a transitive dependency advisory on fast-uri is
resolved (lockfile-only bump). Neither change affects llmo's runtime semantics
for end users; v0.1.6 documents are evaluated identically by v0.1.7.

### Changed

- CLI version string in `--version` output is now derived from package.json at runtime (read via `node:fs` from the file adjacent to the published package root). Previously the version was hardcoded in src/cli.ts and required a separate manual bump per release. Future releases need only update package.json (the lockfile updates automatically via `npm install`).

### Security

- Bumped transitive dependency fast-uri from 3.1.0 to 3.1.2 to close two npm audit advisories (GHSA-q3j6-qgpj-74h6, GHSA-v39h-62p7-jpjc). Zero runtime exposure for llmo's actual code paths (ajv uses fast-uri only on llmo-controlled static schema URIs; user-supplied URLs go through ajv-formats's regex uri() validator). Fixed despite zero exposure to keep the published package's public-facing audit status clean.

## 0.1.6 - 2026-05-08

### Fixed

- §5.2 S4 (URL ownership) and §5.3 X4 (URL-claims-domain-ownership) now enforced rather than emitted as informational notes. Documents that fail S4 or X4 will now correctly fail standard or strict tier in `llmo verify`. Previously these rules were marked "not evaluated in v0.1.0; informational"; the validator at /validator/ had always enforced them, so this brings the CLI to parity.

## 0.1.5 - 2026-05-07

The CLI's version tracks the spec version it implements. Spec versions 0.1.1 through 0.1.4 were patches that did not require CLI code changes (the JCS canonicalization, JWS profile, and schema were re-vendored automatically via `scripts/vendor.sh` without affecting the CLI's logic). 0.1.5 is the first spec version that introduced new CLI logic, so the CLI jumps from 0.1.0 directly to 0.1.5. This policy is documented in `NOTES.md`.

### Verification

- `llmo verify` now performs per-claim signature verification per [§5.3](https://llmo.org/spec/v0.1#5-3-strict-conformance) (rule X6). Previously `llmo sign --claim <id>` could create per-claim signatures but `llmo verify` ignored them entirely; that asymmetry is closed.
- `--json` output gains a `perClaimSignatures` field carrying per-claim presence and verification status. The existing `signatureValid` field is unchanged for backward compatibility with CI consumers.
- `--require-tier strict` exits non-zero when any per-claim signature fails verification.
- Documents with no per-claim signatures pass X6 trivially, matching the spec.

### Algorithm support

- ES256, ES384, and EdDSA are all supported for both document-level and per-claim signatures, dispatched from the JWS protected header's `alg` field. The underlying JWS verification was already algorithm-generic via `jose`; the per-claim path now reuses the same dispatch.

### Schema

- Vendored `src/schema/v0.1.json` refreshed against the upstream spec (claim `type` field is now a `oneOf` with explicit core-type enum and namespaced-extension pattern per [§3.5](https://llmo.org/spec/v0.1#3-5-claim-types) and [§3.6](https://llmo.org/spec/v0.1#3-6-extension-claim-types); `identity.founded` gained a date-format pattern).

### Tests

- Nine new tests cover per-claim verification: PASS, FAIL on tampered signature, FAIL on kid not in JWKS, FAIL on malformed protected header, document and per-claim both PASS, tier downgrade when document-level passes but per-claim fails, trivial PASS when no claim has a signature, ES384 per-claim verification, EdDSA per-claim verification.
- CI matrix expanded to enforce all four combinations of Node 20 / Node 22 with Ubuntu / macOS plus a vendor drift check.

### Operational

- Branch protection enforced on `main` for the cli repo. PR plus passing CI is the only path to merging. Documented at `infrastructure/branch-protection.{json,md}`.

## 0.1.0 - 2026-04-28

Initial public release. Reference CLI for the LLMO protocol per
[v0.1.1 specification](https://llmo.org/spec/v0.1).

Replaces the `0.0.1` placeholder previously published to npm.

### Commands

- `llmo init`: scaffold an `llmo.json`. Interactive (prompted) or
  non-interactive (with flags). Refuses to overwrite an existing file
  unless `--force`.
- `llmo keygen`: generate ES256/ES384/EdDSA signing keypair. Writes
  PKCS#8 PEM (mode 0600) and appends the public JWK to a JWKS file.
- `llmo sign`: standard attached JWS per §4.3.1. Refuses to sign
  `*.signed.json` files without explicit `--in-place` or `--out`.
- `llmo verify`: tier evaluation per §5, signature verification per
  §4.3.1, freshness per §4.5. Local file or URL. Stable JSON output
  shape via `--json`.
- `llmo doctor <domain>`: end-to-end health check on a deployed
  `/.well-known/llmo.json` with Content-Type, Cache-Control, CORS,
  signature, JWKS Cache-Control, and byte-stability checks.

### Spec conformance

- RFC 8785 (JCS) canonicalization via Erdtman's reference implementation.
- RFC 7515 (JWS) signing and verification via panva's `jose`.
- RFC 7517 (JWKS) for public key distribution.
- RFC 7638 (JWK thumbprint) for default key identifiers.
- Standard attached JWS only. Detached-payload (RFC 7797, `b64: false`)
  explicitly prohibited per §4.3.1.

### Test vectors

CI verifies the CLI against the spec's reference fixtures published at
[/spec/v0.1/test-vectors](https://llmo.org/spec/v0.1/test-vectors):

- Independent JCS validation: `canonicalize(signed-strict.json - signature)`
  byte-for-byte equals `signed-strict-payload.json`.
- Strict-vector signature verification: `signed-strict.json` verifies
  against `signed-strict-key.json` per the 5-step procedure on the
  test-vectors page.
