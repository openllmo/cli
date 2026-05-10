# Contributing to llmo (CLI)

The `llmo` CLI is the reference implementation of the LLMO protocol. Bug reports, fixes, and improvements are welcome.

## Before you contribute

The CLI implements the protocol specified at https://llmo.org/spec/v0.1. The CLI's behavior is constrained by the spec; changes that diverge from the spec are not accepted as CLI changes. Spec changes flow through the LIP (LLMO Improvement Proposal) process at https://llmo.org/spec/lips/lip-0001 in the `openllmo/llmo.org` repository, not here.

Use this repository for:

- Bug fixes in the CLI source.
- New CLI features that do not change the protocol.
- Performance improvements.
- Test coverage improvements.
- Documentation fixes.

## Development setup

Requirements: Node.js 20 or later, npm.

```
git clone https://github.com/openllmo/cli
cd cli
npm install
npm test
```

The CLI builds with TypeScript: `npm run build` produces `dist/cli.js`. Run the built CLI with `node dist/cli.js <command>`.

## Running tests

```
npm test
```

The test suite covers signing, verification, tier evaluation, and schema validation. The test-vector harness in the `openllmo/llmo.org` repository (`scripts/test-vectors/verify-vectors.mjs`) cross-checks the CLI against the canonical vectors. Run it locally if your change touches signature, canonicalization, or tier-evaluation paths.

## Submitting a pull request

Fork the repository. Open a PR against `main`. Reviewers expect:

- Conventional commit messages: `feat: ...`, `fix: ...`, `chore: ...`, `docs: ...`.
- DCO sign-off on every commit (`git commit -s`).
- No em dashes in code, prose, or commit messages. Use commas, parentheses, or colons.
- Tests pass locally before pushing.
- If your change touches signature or canonicalization paths, regenerate any affected test vectors and confirm the harness still passes.
- If your change touches the vendored schema (`src/schema/v0.1.json`), verify the schema-drift CI check still passes (`scripts/vendor.sh` plus the `vendor-drift` workflow).

One logical change per PR. Multiple commits per PR are fine if they represent distinct logical units.

## Decision authority

The maintainer has final merge authority for CLI changes that do not imply protocol changes. CLI changes that imply protocol changes are deferred to the LIP process at the `openllmo/llmo.org` repository.

## Developer Certificate of Origin

Every commit requires a DCO sign-off. The DCO is a lightweight alternative to a Contributor License Agreement: by signing off, you certify that you have the right to submit the contribution under the project's license. The full DCO text is at https://developercertificate.org/.

Sign off by adding a `Signed-off-by` trailer to your commit message, or by committing with `git commit -s`:

```
fix(verify): handle empty JWKS gracefully

Signed-off-by: Jane Doe <jane@example.com>
```

The name and email in the sign-off must match the commit's committer identity.

## License

The CLI is licensed under MIT (see `LICENSE`). Contributions are accepted under this license.
