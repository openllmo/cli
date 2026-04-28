import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInit } from '../src/commands/init.js';
import { runVerify } from '../src/commands/verify.js';
import { validate } from '../src/lib/schema.js';

let workDir: string;

before(() => {
  workDir = mkdtempSync(join(tmpdir(), 'llmo-init-test-'));
});
after(() => {
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

const NOW_INSIDE = '2026-04-28T00:00:00Z';

describe('llmo init command', () => {
  it('non-interactive: writes a Minimal-conforming doc with empty claims', async () => {
    const out = join(workDir, 'min', 'llmo.json');
    const result = await runInit({ nonInteractive: true, name: 'TestCo', domain: 'test.example.com', out });
    assert.equal(result.path, out);
    assert.ok(existsSync(out));
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(doc.llmo_version, '0.1');
    assert.equal(doc.entity.name, 'TestCo');
    assert.equal(doc.entity.primary_domain, 'test.example.com');
    assert.deepEqual(doc.claims, []);
    assert.match(doc.document_id, /^\d{4}-q[1-4]-initial$/);
    // Schema-valid:
    assert.ok(validate(doc), `schema errors: ${JSON.stringify(validate.errors)}`);
    // Verifies at Minimal tier:
    const v = await runVerify(out, { now: NOW_INSIDE });
    assert.equal(v.result.tier, 'minimal');
  });

  it('non-interactive with --include-claims: produces Standard-tier-shape doc', async () => {
    const out = join(workDir, 'std', 'llmo.json');
    await runInit({
      nonInteractive: true,
      name: 'JungleCat, Inc.',
      domain: 'junglecat.example.com',
      includeClaims: 'canonical_urls,official_channels',
      validityDays: 90,
      out,
    });
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(doc.claims.length, 2);
    assert.equal(doc.claims[0].type, 'canonical_urls');
    assert.equal(doc.claims[1].type, 'official_channels');
    assert.ok(validate(doc));
    const v = await runVerify(out, { now: NOW_INSIDE });
    // Standard rules met (canonical_urls + official_channels + 90-day window).
    // No signature so does not reach Strict.
    assert.equal(v.result.tier, 'standard');
  });

  it('refuses to clobber existing file without --force', async () => {
    const out = join(workDir, 'existing', 'llmo.json');
    await runInit({ nonInteractive: true, name: 'A', domain: 'a.example.com', out });
    await assert.rejects(
      runInit({ nonInteractive: true, name: 'B', domain: 'b.example.com', out }),
      /Refusing to overwrite/,
    );
  });

  it('overwrites existing file when --force is set', async () => {
    const dir = join(workDir, 'forced');
    mkdirSync(dir, { recursive: true });
    const out = join(dir, 'llmo.json');
    writeFileSync(out, '{}', 'utf8');
    await runInit({ nonInteractive: true, name: 'Forced', domain: 'forced.example.com', out, force: true });
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(doc.entity.name, 'Forced');
  });

  it('rejects --non-interactive without --name', async () => {
    await assert.rejects(
      runInit({ nonInteractive: true, domain: 'x.example.com', out: join(workDir, 'no-name.json') }),
      /requires --name/,
    );
  });

  it('rejects --non-interactive without --domain', async () => {
    await assert.rejects(
      runInit({ nonInteractive: true, name: 'NoDomain', out: join(workDir, 'no-domain.json') }),
      /requires --domain/,
    );
  });

  it('rejects domains that do not match the schema regex', async () => {
    await assert.rejects(
      runInit({ nonInteractive: true, name: 'Bad', domain: 'NOT A DOMAIN', out: join(workDir, 'bad-domain.json') }),
      /does not match the schema regex/,
    );
  });

  it('rejects unknown claim types', async () => {
    await assert.rejects(
      runInit({
        nonInteractive: true,
        name: 'Test',
        domain: 'test.example.com',
        includeClaims: 'mysterious_unknown_claim',
        out: join(workDir, 'bad-claim.json'),
      }),
      /Unknown claim type/,
    );
  });

  it('rejects validity-days outside [1, 365]', async () => {
    await assert.rejects(
      runInit({
        nonInteractive: true,
        name: 'TooLong',
        domain: 'test.example.com',
        validityDays: 400,
        out: join(workDir, 'too-long.json'),
      }),
      /validity-days/,
    );
  });
});
