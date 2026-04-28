// BUILD.md test 6: Clock determinism. Verifier accepts `now` per-call (via
// the runVerify opts) and library calls (via tier evaluator's now field).
//   (a) signed-strict.json is Strict on 2026-06-01.
//   (b) Same document flagged expired on 2026-10-18 while signature still
//       verifies.
//   (c) Verifier with clock outside window does not silently downgrade
//       signature validity.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { runVerify } from '../src/commands/verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, 'fixtures');

describe('clock determinism (BUILD.md test 6)', () => {
  it('(a) signed-strict.json is Strict on 2026-06-01 with vendored JWKS', async () => {
    const docPath = resolve(fixturesDir, 'signed-strict.json');
    const jwksPath = resolve(fixturesDir, 'signed-strict-key.json');
    const outcome = await runVerify(docPath, { jwks: jwksPath, now: '2026-06-01T00:00:00Z' });
    assert.equal(outcome.result.tier, 'strict');
    assert.equal(outcome.result.signatureValid, true);
    assert.equal(outcome.result.expired, false);
  });

  it('(b) signed-strict.json on 2026-10-18 is expired but signature still verifies', async () => {
    const docPath = resolve(fixturesDir, 'signed-strict.json');
    const jwksPath = resolve(fixturesDir, 'signed-strict-key.json');
    const outcome = await runVerify(docPath, { jwks: jwksPath, now: '2026-10-18T00:00:00Z' });
    assert.equal(outcome.result.expired, true, 'document beyond valid_until must be flagged expired');
    assert.equal(outcome.result.signatureValid, true, 'signature MUST still verify; expiry is orthogonal per §4.5');
  });

  it('(c) clock outside window does not silently downgrade signature validity', async () => {
    const docPath = resolve(fixturesDir, 'signed-strict.json');
    const jwksPath = resolve(fixturesDir, 'signed-strict-key.json');
    // Before valid_from
    const before = await runVerify(docPath, { jwks: jwksPath, now: '2026-04-19T00:00:00Z' });
    assert.equal(before.result.signatureValid, true, 'signature MUST verify regardless of clock position');
    assert.equal(before.result.expired, true);
    // After valid_until
    const after = await runVerify(docPath, { jwks: jwksPath, now: '2026-12-01T00:00:00Z' });
    assert.equal(after.result.signatureValid, true);
    assert.equal(after.result.expired, true);
  });

  it('rejects malformed --now values', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'llmo-clock-'));
    try {
      const docPath = join(tmp, 'doc.json');
      writeFileSync(docPath, JSON.stringify({}));
      const outcome = await runVerify(docPath, { now: 'not-a-date' });
      assert.equal(outcome.exitCode, 1);
      assert.ok(outcome.notes.some((n) => /not a valid ISO/i.test(n)));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
