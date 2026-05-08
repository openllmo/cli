# Changelog

## [Unreleased]

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
