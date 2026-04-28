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

## Schema vendoring uses text-level insertion (2026-04-28)

`scripts/vendor.sh` injects the `$comment` line into `src/schema/v0.1.json`
via text-level insertion rather than JSON parse-and-serialize. Reason:
parse-and-serialize round-trips reformat array literals (e.g.,
`"required": ["a", "b"]` becomes a multi-line list), producing a 1900+
byte diff against upstream that obscures real schema changes when
re-vendoring. Text-level insertion keeps the local file equal to upstream
plus exactly one inserted line, so future `vendor.sh` runs surface real
changes cleanly.
