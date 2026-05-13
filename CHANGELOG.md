# Changelog

## [Unreleased]

## [0.1.15] - 2026-05-13

Ships the eleven-phase `/llmo` skill: the wizard now offers to wire `openllmo/llmo-action@v0.1` in the publisher's GitHub repo as its final step, so future edits to `llmo.json` are auto-re-signed on push without the publisher ever pasting YAML or managing paths. No CLI behavior changes; only the bundled skill updates.

### Added

- **`skill/phases/11-auto-resign.md`** — new phase. After phase 10 (validate live), the wizard asks whether the publisher pushes their site's content to a GitHub repo. If yes, it captures the doc-path and kid from earlier phases, writes `.github/workflows/llmo.yml` to the publisher's repo (using `openllmo/llmo-action@v0.1`), sets the `LLMO_PRIVATE_KEY` secret via `gh secret set` (falling back to the browser flow if `gh` is unavailable), commits, pushes, and verifies the workflow registered. If no, the phase is skipped with the manual-re-sign fallback documented in the closing report. GitHub-only in v0.1; GitLab/CodeBerg/Bitbucket cross-platform support deferred to v0.2 of the action repo.
- **`scripts/vendor.sh`** — phase loop now enumerates `11-auto-resign` in addition to the original ten phases. Re-running `bash scripts/vendor.sh` pulls the new phase file from the configured `LLMO_SKILL_REF`.

### Changed

- **`skill/SKILL.md`** — workflow list updated from ten phases to eleven. The Phase 11 entry references the new phase file and summarizes the GitHub-only / GitHub-Copilot-included scope.
- **`skill/.vendored-from`** — re-pinned to llmo.org commit `a15ed84420da46f548b2f97658bd8e0ded217067` (merged via openllmo/llmo.org#156 minutes before this release).

### Notes

- The deploy page at `https://llmo.org/deploy/` collapsed to two real steps in the same llmo.org PR. The wizard absorbs what used to be a "paste YAML and add a secret" Step 3, so publishers never see paths or YAML during onboarding.
- No tier-evaluation, signing, verification, registration, X7-check, or schema changes. 105/105 tests pass unchanged from v0.1.14.

## [0.1.14] - 2026-05-13

Extends the bundled `/llmo` skill to **OpenAI Codex** and **GitHub Copilot** in addition to Claude Code. A single `npm install -g llmo` now installs the publisher wizard into every supported agent's per-user skill directory. The publisher's developer experience collapses to three steps: install the npm package, open whichever agent they have, type `/llmo`.

### Added

- **Dual-target postinstall in `scripts/postinstall.js`**. The default install now writes the bundled skill to both `~/.claude/skills/llmo/` (Claude Code) and `~/.agents/skills/llmo/` (the shared convention recognized by OpenAI Codex and GitHub Copilot per their respective skill docs). Trees are byte-identical at both targets; the orchestrator's `SKILL.md` and the ten phase files in `phases/` are read in-place by whichever agent the developer invokes `/llmo` from.
- **Explicit phase-loop wording in `skill/SKILL.md`**. The Workflow section now tells the agent to read each `phases/<NN>-<name>.md` file from disk before executing the phase, rather than summarizing from the SKILL.md overview. This is a no-op for Claude Code (which auto-loads phase files via skill conventions) and load-bearing for Codex's single-file orchestration model (which needs the explicit "read the referenced file" instruction to flow through the same phase recipes).

### Changed

- **`LLMO_SKILL_DIR` override semantic.** When set, the env var now overrides BOTH defaults and writes to a single target (preserving the legacy single-target test-fixture contract). Production installs that want to suppress one default should set `LLMO_SKILL_DIR` explicitly to the target they want; CI fixtures continue to use the var unchanged. Verified by manual smoke-test against a fake HOME.

### Notes

- No code changes outside `scripts/postinstall.js`, `skill/SKILL.md`, and the metadata bump in `package.json`. Tier evaluation, signing, verification, registration, the X7 KT check, and the vendored schema are byte-identical to v0.1.13.
- The dual-target write is unconditional: the postinstall does not probe for whether Codex or Copilot are installed before writing to `~/.agents/skills/llmo/`. The cost is trivial (a directory and ~10 small files), and writing unconditionally future-proofs the install against the developer adding a second agent later without re-running `npm install`.
- The `~/.agents/skills/` path is the convention documented by OpenAI Codex (`https://developers.openai.com/codex/skills`) and recognized by GitHub Copilot's customize-cloud-agent flow (`https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/add-skills`). If either ecosystem moves its skill directory in a future release, the postinstall will need an update.

## [0.1.13] - 2026-05-12

Implementer parity with llmo.org's [LIP-5](https://llmo.org/spec/lips/lip-0005/) release (Final, accepted under editor authorship privilege during the pre-announcement Goldilocks period). The CLI's vendored schema is refreshed to include the new required `category` discriminator on `disavowal.disavowed[]` entries, and the tier evaluator now binds rule S6 against the closed two-value enum (`self_statement` or `impersonation_defense`). Closes the §5.2 S6 enforcement gap deferred since v0.1.5.

### Added

- **S6 binding enforcement in `src/lib/tier.ts`** `evaluateTier()`. Every entry in a `disavowal` claim's `statement.disavowed[]` array MUST carry a `category` field whose value is `self_statement` or `impersonation_defense`. Entries missing the field or with a value outside the enum produce a Standard-tier failure with rule `disavowal entries carry category in {self_statement, impersonation_defense}` and message prefix `s6_disavowal_out_of_scope:`. Documents whose disavowal entries pass M3 schema (i.e. `category` is in the enum at the schema level) trivially pass S6 too; the in-tier check is defense-in-depth alongside the schema's closed-enum constraint.

### Changed

- **`src/schema/v0.1.json` re-vendored** from `https://llmo.org/spec/v0.1/schema.json`. `statement_disavowal.disavowed[]` items now require `category` (closed enum); other claim type shapes are unchanged. The schema's `$id` is unchanged (in-place v0.1.x patch convention per llmo.org [ADR-0006](https://llmo.org/adr/0006-version-bump-and-release-cut/)).
- **`test/tier.test.ts`** existing S4 test that constructed a disavowal claim with third-party `url` now includes a `category` field on the entry. A new `§5.2 S6 disavowal category enforcement (LIP-5)` describe block adds four tests: positive (valid categories pass), negative (no category fails), negative (out-of-enum category fails), and the no-disavowal-claim case (S6 does not fire). 105 tests total, all passing.
- **`test/verify.test.ts`** disavowal test fixtures (7 occurrences) updated with `category: "self_statement"` on the synthetic disavowed entries so the per-claim signature tests continue to construct schema-valid documents.

### Notes

- Pre-LIP-5 documents with a disavowal claim lacking `category` now fail M3 schema validation and evaluate as `tier: invalid`. This is intentional per LIP-5; pre-launch the only affected document is the steward's own at llmo.org, updated in the same PR that landed LIP-5.
- The S6 enforcement in `evaluateTier()` continues to run even when M3 fires first; this is defense-in-depth and ensures correctness for any future ajv configuration that permits the field through (e.g. an implementation that disables `additionalProperties: false` enforcement).

## [0.1.12] - 2026-05-12

Adds the consumer-side LIP-4 §3.4 **X7** check to `llmo verify`: query a conforming Key Transparency registry for entries under the document's primary_domain, verify each entry's inline-signed JWS, and check whether any thumbprint matches the publisher's deployed JWKS signing key. **Advisory in v0.1.x** — surfaced in JSON output as `ktRegistryInclusion` and in human-readable output as a labeled line, but does not downgrade tier. Tier-determining enforcement begins after LIP-4 transitions Final and its 90-day grace period elapses.

### Added

- **`src/lib/kt.ts`** — `evaluateX7()` library function implementing the consumer flow:
  1. Compute SHA-384 thumbprint (RFC 7638 + LIP-4 §3.1) of the publisher's deployed signing key.
  2. Query `GET /kt/v1/entries?domain=<domain>` on the configured registry.
  3. For each returned entry: verify the compact JWS using the inline JWK from the protected header (RFC 7515 §4.1.3 per LIP-4 §3.2), confirm `payload.jwk_thumbprint` equals SHA-384(JCS(inline JWK)), and check whether the thumbprint matches the publisher's deployed key.
  4. Return `{status: pass | fail | skip, note, entries_returned, entries_verified}`.
- **`llmo verify` flags**:
  - `--no-kt-check` skips the X7 check entirely.
  - `--registry <url>` overrides the default registry (`https://llmo.org/kt/v1`).
- **6 new tests** in `test/kt.test.ts`: PASS case, FAIL no-entries, FAIL no-match, SKIP on registry 5xx, SKIP on network error, tampered-entry rejection. 101 tests total, all passing.

### Notes

- The check runs only in URL mode (URL or bare-domain target) where the publisher's primary_domain is known. File-mode invocations skip X7 silently.
- The check runs only when the document's signing key was successfully located in the publisher's JWKS. Documents whose signature is missing, malformed, or whose kid is not in the JWKS skip X7 (the upstream X5 check has already reported the deeper issue).
- The registry query is independent of the JOSE library's `jose` package — `evaluateX7()` uses `jose`'s `compactVerify` + `calculateJwkThumbprint` directly. No new runtime dependencies.

## [0.1.11] - 2026-05-12

Adds `llmo register`, the publisher-facing CLI for submitting a Key Transparency entry per [LIP-4](https://llmo.org/spec/lips/lip-0004/). The subcommand constructs a compact JWS per LIP-4 §3.2 (inline public JWK in the protected header, SHA-384 thumbprint in the payload, RFC 7638 canonicalization), POSTs it to the configured registry endpoint, and writes the signed receipt to a local file.

### Added

- **`llmo register`**: new subcommand. Required flags: `--key <path>` (private JWK file), `--domain <primary_domain>`, `--doc-id <document_id>`. Optional flags: `--doc-url <url>` (defaults to `https://<domain>/.well-known/llmo.json`), `--registry <url>` (defaults to `https://llmo.org/kt/v1`), `--out <path>` (defaults to `./llmo-kt-receipt-<timestamp>.json`). Implementation at `src/commands/register.ts`.
- **6 new tests** under `test/register.test.ts` exercising the JWS construction, thumbprint computation, public-key derivation (with explicit assertion that no private material leaks into the inline JWK), receipt serialization, domain normalization, and error propagation when the registry returns a 4xx. 95 tests total, all passing.

### Notes

- Per LIP-4 §8.1 the subcommand is informative (not yet normative since LIP-4 is in Draft). Existing v0.1.10 consumers continue to work unchanged; the X7 strict-tier rule (LIP-4 §3.4) won't be enforced by `llmo verify` until a future release after LIP-4 transitions Final.
- The private JWK file MUST include a `d` field. Files that look like public JWKs are rejected with a clear error pointing at the input file. The subcommand never reads or transmits the `d` field beyond loading it into memory for signing; the protected header's inline JWK is built by selective whitelist (kty, crv, x, y, n, e, kid, alg, use, key_ops) so future jose JWK fields cannot accidentally exfiltrate private material through this code path.

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
