#!/usr/bin/env bash
# Re-vendor the LLMO v0.1 schema, test-vector fixtures, and /llmo Claude
# Code skill files from llmo.org. Prints a unified diff for any vendored
# file that would change, then writes the new content. Run from anywhere;
# resolves repo root from script location.
#
# Usage: scripts/vendor.sh
# Exits 0 always. Drift is shown via stdout diffs, not exit codes; CI
# wires its own check that fails if `git diff --exit-code` after
# vendoring shows changes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
UPSTREAM="https://llmo.org/spec/v0.1"

# Resolve the skill upstream ref. Order of precedence:
#   1. LLMO_SKILL_REF env var (explicit, used by tagged releases and CI
#      verification to pin against a known SHA).
#   2. Contents of skill/.vendored-from (records the SHA used by the
#      most recent successful vendor pass; ordinary re-runs are
#      idempotent against this).
#   3. "main" (TOFU fallback; only hit on first-time vendoring before
#      .vendored-from exists).
if [[ -n "${LLMO_SKILL_REF:-}" ]]; then
  SKILL_REF="$LLMO_SKILL_REF"
elif [[ -f "$ROOT/skill/.vendored-from" ]]; then
  SKILL_REF="$(cat "$ROOT/skill/.vendored-from" | tr -d '[:space:]')"
else
  SKILL_REF="main"
fi
SKILL_UPSTREAM="https://raw.githubusercontent.com/openllmo/llmo.org/${SKILL_REF}/.claude/skills/llmo"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CHANGED=0

diff_and_replace() {
  local rel="$1"
  local staged="$2"
  local target="$ROOT/$rel"
  mkdir -p "$(dirname "$target")"
  if [[ -f "$target" ]]; then
    if ! diff -q "$target" "$staged" >/dev/null 2>&1; then
      echo "=== diff: $rel ==="
      diff -u "$target" "$staged" || true
      echo
      CHANGED=1
    fi
  else
    echo "=== new: $rel ==="
    CHANGED=1
  fi
  cp "$staged" "$target"
}

echo "Vendoring from $UPSTREAM"
echo

# Schema: fetch, then insert a $comment line right after the $schema line
# at the top. Text-level insertion preserves upstream formatting; the
# local file differs from upstream by exactly one inserted line.
curl -fsS "$UPSTREAM/schema.json" -o "$TMP/schema-upstream.json"
node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
const upstream = readFileSync(process.argv[1], 'utf8');
const commentLine = \`  \"\$comment\": \"Vendored from https://llmo.org/spec/v0.1/schema.json. Do not hand-edit. Re-vendor by running scripts/vendor.sh.\",\n\`;
const re = /^(\s*\"\\\$schema\":\s*\".*?\",?)\n/m;
const m = upstream.match(re);
if (!m) { console.error('vendor.sh: could not locate \$schema line in upstream schema'); process.exit(1); }
const idx = (m.index ?? 0) + m[0].length;
const out = upstream.slice(0, idx) + commentLine + upstream.slice(idx);
writeFileSync(process.argv[2], out);
" "$TMP/schema-upstream.json" "$TMP/schema-local.json"
diff_and_replace "src/schema/v0.1.json" "$TMP/schema-local.json"

# Fixtures: fetch verbatim, byte-for-byte from upstream.
for fix in unsigned-minimal unsigned-standard signed-strict signed-strict-key signed-strict-payload; do
  curl -fsS "$UPSTREAM/test-vectors/${fix}.json" -o "$TMP/${fix}.json"
  diff_and_replace "test/fixtures/${fix}.json" "$TMP/${fix}.json"
done

# /llmo Claude Code skill: fetch verbatim. These ship inside the npm
# package and are copied to ~/.claude/skills/llmo/ by the postinstall
# hook so `/llmo` becomes available in Claude Code immediately after
# `npm install -g llmo`.
echo
echo "Vendoring skill files from $SKILL_UPSTREAM (ref: $SKILL_REF)"
for f in SKILL.md README.md; do
  curl -fsS "$SKILL_UPSTREAM/${f}" -o "$TMP/skill-${f}"
  diff_and_replace "skill/${f}" "$TMP/skill-${f}"
done
for phase in 01-greet 02-interview 03-derive 04-review 05-verify-contacts 06-dns-corroboration 07-keygen 08-sign 09-deploy 10-validate; do
  curl -fsS "$SKILL_UPSTREAM/phases/${phase}.md" -o "$TMP/phase-${phase}.md"
  diff_and_replace "skill/phases/${phase}.md" "$TMP/phase-${phase}.md"
done

# Record the ref this vendor pass used so subsequent runs (CI drift
# checks, ordinary re-vendor) are idempotent against the same upstream
# state without needing the env var. To bump the pin: run with
# LLMO_SKILL_REF=<new-sha> and commit the diff.
echo "$SKILL_REF" > "$ROOT/skill/.vendored-from"

echo
if [[ $CHANGED -eq 0 ]]; then
  echo "Vendor complete: no changes."
else
  echo "Vendor complete: changes shown above."
fi
