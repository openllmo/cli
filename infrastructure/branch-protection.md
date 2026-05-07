# Branch Protection on `main`

Documents the branch protection ruleset applied to `main` on `openllmo/cli`. The machine-recoverable source of truth is `infrastructure/branch-protection.json`; this document is the human-readable companion that explains why each rule is set the way it is.

This file mirrors the equivalent document in the sibling repository `openllmo/llmo.org` so that both repos' operational documentation has the same shape. Diverge only when the cli repo's needs genuinely differ from the spec/site repo's.

## Purpose

Branch protection makes CI rules and merge discipline mechanical rather than honor-system. The CI workflows in `.github/workflows/` (the `CI` matrix and the vendor drift check) only have effect if a misconfigured push cannot bypass them. Protection enforces the gate.

The bus-factor framing applies: rules that admins can bypass don't survive operator absence, because a future contributor reads the config and assumes admin-bypass is the convention. `enforce_admins: true` is a deliberate choice, not a default.

## Current rules

Applied 2026-05-07. Verified by `gh api repos/openllmo/cli/branches/main/protection`.

| Field | Value |
|---|---|
| `required_status_checks.strict` | `true` |
| `required_status_checks.contexts` | `["test (node 20 / macos-latest)", "test (node 20 / ubuntu-latest)", "test (node 22 / macos-latest)", "test (node 22 / ubuntu-latest)", "vendor drift check"]` |
| `enforce_admins` | `true` |
| `required_pull_request_reviews` | `null` |
| `required_signatures` | `false` |
| `allow_force_pushes` | `false` |
| `allow_deletions` | `false` |
| `required_linear_history` | `false` |
| `required_conversation_resolution` | `true` |
| `lock_branch` | `false` |
| `allow_fork_syncing` | `false` |
| `block_creations` | `false` |
| `restrictions` | `null` |

## Why each rule

### `required_status_checks.contexts` (five entries)

These are the exact check names reported by the GitHub Actions API on `pull_request` runs against this repo:

- `test (node 20 / macos-latest)` and `test (node 20 / ubuntu-latest)`: the `test` job in `.github/workflows/ci.yml` matrixed across macOS and Ubuntu on Node 20.
- `test (node 22 / macos-latest)` and `test (node 22 / ubuntu-latest)`: the same matrix on Node 22.
- `vendor drift check`: the `vendor-drift` job in `.github/workflows/ci.yml`. Re-runs `scripts/vendor.sh` and fails if `src/schema/` or `test/fixtures/` have drifted from upstream `https://llmo.org/spec/v0.1/`.

All four matrix entries are required, not just one representative. The cli runs on user machines, so it has to actually work on macOS and on Node 20 in addition to the Ubuntu/Node-22 baseline. Excluding any entry from the gate would mean "we don't care if that platform is broken at merge time; we'll find out later," which is exactly the failure mode that surfaces in launch-week support tickets. If any matrix entry is genuinely flaky enough to block legitimate merges regularly, the right response is to investigate and fix the flakiness, not to narrow the gate.

These are the names as reported by GitHub, not the workflow filenames. GitHub matches required-checks against the check name from the workflow run, not the workflow file path. Mismatched names silently fail to enforce.

### `required_status_checks.strict: true`

`strict: true` requires the PR branch to be up to date with `main` before merging. Without strict, a PR could pass CI on a stale base, then merge into a `main` that has diverged. CI green on a stale base is meaningless: the workflow could pass on the stale state and fail on the current state, and the merge happens anyway.

### `enforce_admins: true`

Rules apply to admins. The operator is currently the only admin; without `enforce_admins`, the rules apply to nobody who would actually break them. The escape hatch (temporary disable via `gh api -X DELETE`) is preserved as a deliberate, auditable action; that is materially different from an invisible always-on bypass.

### `required_pull_request_reviews: null`

PR reviews are not required. The project is currently single-operator (`spec@llmo.org`); requiring approving reviews from a second person would block all merges.

The combination of `required_pull_request_reviews: null` and required status checks means: PRs are not strictly mandated by the protection ruleset, but they are the only practical path to landing a commit, since direct pushes cannot satisfy the required checks (the checks have not run on a freshly-pushed commit).

### `required_signatures: false`

GPG-signed commits are not required. The project's authentication-of-author convention is DCO sign-off (`Signed-off-by: Name <email>` on every commit, enforced by `git commit -s`). DCO is a legal sign-off that the contributor has the right to submit the work; GPG signatures are a separate, additive concern. Requiring both adds friction without changing the legal posture of contributions.

### `allow_force_pushes: false`, `allow_deletions: false`

`main` cannot be force-pushed and cannot be deleted. Both protect against accidental loss of history. Force-push in particular invalidates anchored references: anyone who has cited a SHA on `main` (in commit messages, in npm package provenance attestations, in external references) loses their reference if `main`'s history is rewritten.

### `required_linear_history: false`

Merge commits are permitted. The cli repo currently uses squash-merge as the convention (one PR, one commit on `main`), but the protection rule doesn't force a specific merge strategy.

### `required_conversation_resolution: true`

Outstanding PR review conversations must be resolved before merge. Ensures comments aren't silently merged-around. Low cost, real value when there are reviewers.

### `lock_branch: false`

`main` accepts new commits via PR. Locking would freeze the branch entirely, which is the wrong posture for a branch that receives ongoing work.

### `allow_fork_syncing: false`

Forks cannot syncretly write to `main` via fork-sync. Defensive setting against fork-based attack vectors.

### `block_creations: false`

Branches and tags can be created normally. The protection rule is about `main`'s history, not about restricting branch creation across the repo.

### `restrictions: null`

No user/team push restrictions beyond the rules above. The required-checks gate is the primary control; there is no secondary "only these users may push" layer.

## How to restore

If GitHub loses the configuration or the UI is changed inadvertently, replay the JSON via:

```sh
gh api -X PUT repos/openllmo/cli/branches/main/protection \
  --input infrastructure/branch-protection.json
```

Verify the result:

```sh
gh api repos/openllmo/cli/branches/main/protection
```

The response is structurally different from the PUT payload (GET returns nested objects with metadata URLs; PUT takes a flat config). Compare the meaningful fields, not byte-for-byte. The "Current rules" table above is the human-readable reference for what should match.

## Disabling temporarily

If a protection rule blocks legitimate work and the right answer is to fix the workflow rather than the protection, the workflow is the thing to fix. If a protection rule blocks legitimate work and the rule itself is wrong, change `branch-protection.json` and replay. Either way: do not add `enforce_admins: false`, do not silently bypass via the UI. The point of the protection is that it cannot be bypassed silently.

To remove protection entirely (rare, e.g., for a deliberate history rewrite):

```sh
gh api -X DELETE repos/openllmo/cli/branches/main/protection
```

After the destructive operation completes, immediately replay the JSON to restore.

## Updating this document

If the ruleset changes, update both `branch-protection.json` and this file in the same commit. Drift between the two defeats the purpose: the JSON must remain replayable and accurate.
