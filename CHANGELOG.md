# Changelog

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
