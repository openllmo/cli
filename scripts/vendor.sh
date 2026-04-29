#!/usr/bin/env bash
# Re-vendor the LLMO v0.1 schema and test-vector fixtures from llmo.org.
# Prints a unified diff for any vendored file that would change, then
# writes the new content. Run from anywhere; resolves repo root from
# script location.
#
# Usage: scripts/vendor.sh
# Exits 0 always. Drift is shown via stdout diffs, not exit codes; CI
# wires its own check that fails if `git diff --exit-code` after
# vendoring shows changes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
UPSTREAM="https://llmo.org/spec/v0.1"
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

echo
if [[ $CHANGED -eq 0 ]]; then
  echo "Vendor complete: no changes."
else
  echo "Vendor complete: changes shown above."
fi
