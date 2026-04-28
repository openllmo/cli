// Independent JCS validation per the test-vectors page section "Verifying
// a JCS implementation independently". Reads signed-strict.json, strips
// the signature, canonicalizes, and compares byte-for-byte against
// signed-strict-payload.json. If the two differ, the implementation is
// not RFC 8785 conformant and JWS verification cannot be trusted.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalizeForSignature } from '../src/lib/canonicalize.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, 'fixtures');

function hex(bytes: Uint8Array, start: number, end: number): string {
  return Array.from(bytes.slice(Math.max(0, start), Math.min(bytes.length, end)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');
}

describe('independent JCS validation against signed-strict-payload.json', () => {
  it('canonicalize(signed-strict.json minus signature) equals signed-strict-payload.json byte-for-byte', () => {
    const docText = readFileSync(resolve(fixturesDir, 'signed-strict.json'), 'utf8');
    const doc = JSON.parse(docText);
    const expected = new Uint8Array(readFileSync(resolve(fixturesDir, 'signed-strict-payload.json')));
    const actual = canonicalizeForSignature(doc);

    if (actual.length !== expected.length) {
      assert.fail(
        `JCS broken: canonical bytes length differs. ` +
          `actual=${actual.length} expected=${expected.length} delta=${actual.length - expected.length}. ` +
          `Reference fixture is /spec/v0.1/test-vectors/signed-strict-payload.json. ` +
          `When JCS is broken, lengths typically differ; when JWS is broken, lengths usually match but bytes inside differ.`,
      );
    }

    for (let i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) {
        assert.fail(
          `JCS broken: bytes differ at offset ${i} (lengths match: ${actual.length} bytes each, so this is a subtle within-payload divergence, not a length mismatch). ` +
            `actual context [${Math.max(0, i - 8)}..${i + 8}]: ${hex(actual, i - 8, i + 8)}. ` +
            `expected context: ${hex(expected, i - 8, i + 8)}.`,
        );
      }
    }
  });
});
