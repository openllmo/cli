# Project decisions

This file records non-trivial decisions made during the v0.1.0 build that
warrant explanation beyond what code comments cover. Decisions tied to a
specific code site live there as `// Decision:` or `# Decision:` comments.
This file holds decisions that span the codebase or have no single home.

## @types/node as a dev dependency (2026-04-28)

`@types/node` is included as a dev dependency. It is a transparent
TypeScript type-definitions package, does not ship in the published
tarball (excluded by `.npmignore` since it is a transitive dev dep),
and does not affect runtime behavior.

The "exactly these, no substitutes" rule in `TASKS/cli-v0.1.0-build.md`
applies to operational/runtime dependencies; type definitions for Node's
standard library are out of scope. The alternative (`@ts-ignore`
everywhere we touch `process`, `Buffer`, `node:fs`, etc.) is strictly
worse for code quality and auditability.

## Tier evaluation on local-file inputs (2026-04-28)

URL-mode-only Strict-tier rules from §5.3 (`primary_domain` matching the
serving domain, JWKS `Cache-Control: max-age` ≤ 86400) cannot be
evaluated against local-file inputs. The CLI's tier evaluator skips
these with informational notes rather than requiring them. Local-file
inputs can therefore reach Strict tier when the document satisfies all
evaluable rules and the signature verifies against the supplied JWKS.

This is intentional: test vectors are local fixtures and must be
evaluable at Strict tier (BUILD.md test 6(a) requires this). The
alternative (capping local-file evaluation at Standard) would make the
strict-vector E2E test impossible to write.

Publishers running `llmo verify <domain>` (URL mode) get full §5.3
evaluation. Publishers running `llmo verify ./llmo.json` (local mode)
get tier-up-to-Strict-with-skipped-URL-checks. Verify output makes the
distinction explicit through the Notes section.

## Trusted Publishing setup notes (2026-04-29)

Setting up npm Trusted Publishing for the v0.1.0 release surfaced three
distinct gotchas. Each is a wall a future contributor could hit on their
own setup; capturing them here so they're a five-minute fix instead of
a multi-hour debug session.

### 1. `actions/setup-node`'s `registry-url` poisons the auth path

`actions/setup-node@v4` and `@v5` with the `registry-url:` option write
an `.npmrc` containing `_authToken=${NODE_AUTH_TOKEN}` to the runner.
With Trusted Publishing (no `NODE_AUTH_TOKEN` set), `npm publish` reads
that `.npmrc`, sees an auth-token line configured, treats it as "the
user has chosen token-based auth," resolves the empty token, and sends
an unauthenticated PUT — which the registry returns as 404 without
falling back to Trusted Publishing.

**Fix:** drop `registry-url` from `setup-node`. With no `.npmrc`
written, `npm` defaults to `https://registry.npmjs.org` and falls
through to the Trusted Publishing path. Resolved in commits `35b576f`
(initial NPM_TOKEN removal) and `2e811ad` (`registry-url` removal).

### 2. Trusted Publishing requires npm CLI v11.5.1+

Runner-bundled npm with Node 22 is 10.9.7 as of 2026-04-29. npm 10.x
has no Trusted Publishing logic at all: `--provenance` works (it uses
the OIDC token directly with sigstore for attestation), but the
publish-time auth path has no OIDC fallback. With no `.npmrc`
auth-token and no `NODE_AUTH_TOKEN`, npm 10.x exits with `ENEEDAUTH`
instead of reaching for the OIDC token.

**Fix:** upgrade npm to v11.5.1+ for the publish step. See gotcha #3
for the right way to do that.

### 3. `npm install -g npm@latest` hits the self-upgrade race

The obvious "upgrade npm before publishing" approach
(`npm install -g npm@latest`) hits npm's well-known self-upgrade race:
npm 10.x removes its own modules during the install of npm 11.x, then
crashes mid-flight with `MODULE_NOT_FOUND` for `promise-retry` as it
tries to load already-removed internals. `--force` does not help; the
issue is module-not-found, not a file conflict.

**Fix:** don't self-upgrade. Run the publish through a transient
npm@latest via `npx`, leaving the system npm untouched:

```
npx --package=npm@latest --yes -- npm publish --access public --provenance
```

The transient npm 11.x sees the inherited `ACTIONS_ID_TOKEN_REQUEST_*`
env vars and uses Trusted Publishing for auth. Resolved in commits
`96f7cf1` (initial in-place upgrade attempt that exposed the race) and
`8016764` (npx-based final fix).

### Final published state

`llmo@0.1.0` published 2026-04-29 via GitHub Actions OIDC, SLSA v1
provenance attached, no long-lived NPM_TOKEN involved. The
`published by GitHub Actions <npm-oidc-no-reply@github.com>` line on
the npm package page is the Trusted Publishing fingerprint.

## Schema vendoring uses text-level insertion (2026-04-28, updated 2026-04-29)

`scripts/vendor.sh` injects the `$comment` line into `src/schema/v0.1.json`
via text-level insertion rather than JSON parse-and-serialize. Reason:
parse-and-serialize round-trips reformat array literals (e.g.,
`"required": ["a", "b"]` becomes a multi-line list), producing a 1900+
byte diff against upstream that obscures real schema changes when
re-vendoring. Text-level insertion keeps the local file equal to upstream
plus exactly one inserted line, so future `vendor.sh` runs surface real
changes cleanly.

The vendor script is deterministic: re-running it on unchanged upstream
produces zero diffs, allowing CI to use `git diff --exit-code` after
vendoring as a real drift signal. The vendoring date is not embedded in
the file; the authoritative "when was this last vendored" answer is
`git log -1 src/schema/v0.1.json`. An earlier draft included the date in
the `$comment` line and was non-deterministic across days, defeating the
CI drift check.
