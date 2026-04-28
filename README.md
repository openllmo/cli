# llmo

Reference CLI for the [LLMO protocol](https://llmo.org/spec/v0.1).
Sign, verify, and health-check `llmo.json` documents at
`/.well-known/llmo.json`.

The protocol specification at [https://llmo.org/spec/v0.1](https://llmo.org/spec/v0.1)
is authoritative. Where this README and the spec disagree, the spec
wins and the README is the bug.

## Install

```
npm install -g llmo
```

Requires Node 20 or later.

## 60-second quickstart

Generates a key, scaffolds a document, signs it, and verifies it
end-to-end. The example uses `junglecat.example.com` (the same
fictional entity as the spec's reference test fixtures), so the
artifacts you produce match the
[reference test vectors](https://llmo.org/spec/v0.1/test-vectors)
where applicable.

```bash
# 1. Generate a signing keypair. Writes a private PEM (mode 0600) and a JWKS.
llmo keygen --alg ES256 --kid junglecat-2026-01

# 2. Scaffold a Standard-tier llmo.json with the two common claim types.
llmo init --non-interactive \
  --name "JungleCat, Inc." \
  --domain junglecat.example.com \
  --include-claims canonical_urls,official_channels \
  --validity-days 90

# 3. Sign the document in place. Standard attached JWS per §4.3.1.
llmo sign llmo.json --key ./llmo-private-junglecat-2026-01.pem \
  --kid junglecat-2026-01 --in-place

# 4. Verify locally with the just-generated JWKS.
llmo verify llmo.json --jwks ./llmo-keys.json

# 5. After deploying, health-check the live URL.
llmo doctor junglecat.example.com --require-tier strict
```

Step 4 reports `Tier: STRICT, Signature: valid`. Step 5 fetches the
deployed `https://junglecat.example.com/.well-known/llmo.json`, runs
all consumer-side checks, refetches twice with a 2-second gap to
detect CDN reformatting, and reports a checklist.

## Commands

### `llmo init`

Scaffolds an `llmo.json` document. Interactive by default; pass
`--non-interactive` plus `--name <entity>` and `--domain <fqdn>` for
unattended use. Refuses to overwrite an existing file unless `--force`
is set. Default validity window is 90 days, capped at 365.

### `llmo keygen`

Generates an ES256, ES384, or EdDSA signing keypair. Writes the
private key as a PKCS#8 PEM (mode 0600 on POSIX) and appends the
public JWK to a JWKS file. Re-running with a new `--kid` against the
same JWKS file appends rather than overwrites, supporting key
rotation per §4.2.

If `--kid` is omitted, the key identifier is computed as the RFC 7638
thumbprint of the public JWK.

### `llmo sign`

Signs a document with standard attached JWS per §4.3.1. The protected
header carries exactly `{ alg, kid }`; `b64: false` and non-empty
`crit` are prohibited. Default output is `<file>.signed.json`; use
`--in-place` to overwrite the input or `--out <path>` for a custom
location. Refuses to sign a file already named `*.signed.json`
without an explicit `--in-place` or `--out`.

`--claim <claim_id>` signs a single claim by `claim_id` rather than
the whole document.

### `llmo verify`

Verifies a document and reports its conformance tier per §5. Targets
can be a URL, a bare domain (auto-resolves to
`https://<domain>/.well-known/llmo.json`), or a local file path.

`--jwks <url-or-path>` overrides JWKS resolution. `--require-tier`
asserts a minimum tier (exits 1 if not met). `--ignore-expiry`
suppresses the expiry warning in human output but never in JSON.
`--now <ISO 8601>` injects a clock for deterministic testing.
`--json` emits a stable structured shape.

Tier and freshness are reported orthogonally per §4.5: an expired
document with a valid signature reports its evaluated tier AND
`expired: true`. The signature does not become invalid because of
expiry.

### `llmo doctor <domain>`

End-to-end health check on a deployed `/.well-known/llmo.json`.
Fetches the document, asserts HTTP 200, `Content-Type:
application/llmo+json` or `application/json`, `Cache-Control`
present, `Access-Control-Allow-Origin: *`, then runs all `verify`
checks plus the JWKS `Cache-Control: max-age <= 86400` check from
§5.3. Finally refetches twice with a 2-second gap to detect CDN
reformatting; mismatch is reported as informational.

## GitHub Actions snippet

```yaml
name: Sign llmo.json

on:
  push:
    branches: [main]
    paths: ['llmo.json']

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm install -g llmo
      - name: Sign
        env:
          PRIVATE_KEY: ${{ secrets.LLMO_PRIVATE_KEY }}
        run: |
          echo "$PRIVATE_KEY" > /tmp/private.pem
          chmod 600 /tmp/private.pem
          llmo sign llmo.json \
            --key /tmp/private.pem \
            --kid prod-2026-01 \
            --in-place
          rm /tmp/private.pem
      - uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: 'chore(llmo): re-sign llmo.json'
          file_pattern: llmo.json
```

## Security guidance

- **Private key storage.** Never commit private keys. Store as a CI
  secret or a KMS-backed value. The CLI writes private keys with mode
  0600 on POSIX and warns on Windows where that mode is not enforced.
- **Rotation.** Rotate signing keys at least annually (§4.2). Rotate
  immediately on suspected compromise. The `keygen` command appends to
  an existing JWKS rather than overwriting, so a rotated key joins
  the existing keys instead of replacing them. Retire old keys by
  removing them from the JWKS after the rotation window closes (§4.2
  recommends 90 days).
- **`kid` format.** RFC 7638 thumbprints (the `keygen` default when
  `--kid` is omitted) are content-addressed and tamper-evident:
  changing the key changes the kid. Human-readable labels
  (`prod-2026-q2`, `mobile-team-2026-01`) are also fine for
  human-managed flows where you want the kid to encode rotation
  history.
- **Sign last; serve byte-stable.** §4.3.3 requires that signed
  documents be served byte-for-byte as written. Do not let your CDN,
  framework, or pre-commit hook reformat the file after signing. If
  you cannot guarantee byte-stable serving, do not sign: an unsigned
  Layer 1 document is preferable to a signed document whose
  signatures verifiers will routinely fail to validate.

## What this tool is not

- **Not a hosted signing service.** Signing happens locally; this
  CLI never sends private keys or document content over the network.
- **Not a key management system.** Generation, storage, and rotation
  of private keys are the publisher's responsibility. Use a KMS or a
  CI secret store; do not rely on the CLI's local PEM file as your
  primary key store.
- **Not a CA.** The CLI does not certify keys, identities, or
  domains. The trust model in §4 binds claims to the publisher's
  *control of a domain and a key*, not to any external attestation.
- **Not a registry.** The CLI does not enroll publishers anywhere.
  LLMO is decentralized: each publisher self-hosts their `llmo.json`
  and JWKS at well-known paths.
- **Not a way to bypass DNS-based identity proofs.** A signed
  `llmo.json` only attests "the holder of this key, which the
  publisher serves at this domain, made these claims at this time."
  It does not establish that the publisher is *who they claim to
  be* in the world; that's downstream of DNS, registry data, and
  the consumer's own trust assessment per §4.6.

## Test vectors

The spec publishes reference test vectors at
[https://llmo.org/spec/v0.1/test-vectors](https://llmo.org/spec/v0.1/test-vectors).
The CLI's CI tests assert byte-for-byte equivalence against
`signed-strict-payload.json` (independent JCS validation) and verify
the signature on `signed-strict.json` against `signed-strict-key.json`
(strict-vector signature verification). To verify your own
implementation against these fixtures, run:

```bash
llmo verify ./signed-strict.json --jwks ./signed-strict-key.json --now 2026-06-01T00:00:00Z
```

Expected output: `Tier: STRICT, Signature: valid, Freshness: in window`.

## Versioning

This CLI tracks LLMO spec versions. The 0.1.x line implements
[v0.1.x of the specification](https://llmo.org/spec/v0.1). Patch
versions (0.1.1, 0.1.2, ...) ship editorial revisions and bug fixes
that do not change the on-disk format. Minor versions (0.2.x) align
with new minor versions of the spec.

## License

MIT. Copyright Diverse.org, Inc.

## Contributing

Issues and pull requests welcome at
[github.com/openllmo/cli](https://github.com/openllmo/cli). Spec
issues belong at the spec repo. CLI issues belong here.
