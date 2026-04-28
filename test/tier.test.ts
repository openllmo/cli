import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { evaluateTier } from '../src/lib/tier.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, 'fixtures');
const CLOCK_INSIDE = new Date('2026-06-01T00:00:00Z');

function load(name: string): unknown {
  return JSON.parse(readFileSync(resolve(fixturesDir, name), 'utf8'));
}

describe('tier evaluation against vendored fixtures (clock 2026-06-01)', () => {
  it('unsigned-minimal.json -> Minimal', () => {
    const r = evaluateTier({ document: load('unsigned-minimal.json'), now: CLOCK_INSIDE });
    assert.equal(r.tier, 'minimal');
    assert.deepEqual([...r.satisfied], ['minimal']);
    assert.equal(r.expired, false);
    assert.equal(r.failures.filter((f) => f.tier === 'minimal').length, 0);
    assert.ok(r.failures.filter((f) => f.tier === 'standard').length > 0, 'should have standard rule failures');
  });

  it('unsigned-standard.json -> Standard', () => {
    const r = evaluateTier({ document: load('unsigned-standard.json'), now: CLOCK_INSIDE });
    assert.equal(r.tier, 'standard');
    assert.deepEqual([...r.satisfied], ['minimal', 'standard']);
    assert.equal(r.expired, false);
    assert.equal(r.failures.filter((f) => f.tier === 'minimal').length, 0);
    assert.equal(r.failures.filter((f) => f.tier === 'standard').length, 0);
    assert.ok(r.failures.filter((f) => f.tier === 'strict').length > 0, 'should have strict rule failures (no signature)');
  });

  it('signed-strict.json with signatureValid=true -> Strict', () => {
    const r = evaluateTier({ document: load('signed-strict.json'), now: CLOCK_INSIDE, signatureValid: true });
    assert.equal(r.tier, 'strict');
    assert.deepEqual([...r.satisfied], ['minimal', 'standard', 'strict']);
    assert.equal(r.expired, false);
    assert.equal(r.failures.length, 0);
  });

  it('signed-strict.json with signatureValid=false -> Standard (downgrade per §4.5)', () => {
    const r = evaluateTier({ document: load('signed-strict.json'), now: CLOCK_INSIDE, signatureValid: false });
    assert.equal(r.tier, 'standard', 'invalid signature must downgrade to Standard, not Invalid (§4.5)');
    assert.equal(r.expired, false);
    assert.ok(r.failures.some((f) => f.tier === 'strict' && /signature/i.test(f.message)));
  });

  it('signed-strict.json with signatureValid undefined (skipped) -> Standard with strict failure noted', () => {
    const r = evaluateTier({ document: load('signed-strict.json'), now: CLOCK_INSIDE });
    assert.equal(r.tier, 'standard');
    assert.ok(r.failures.some((f) => f.tier === 'strict' && /signature/i.test(f.message)));
  });

  it('flags expired when now > valid_until even though signature is valid', () => {
    const r = evaluateTier({
      document: load('signed-strict.json'),
      now: new Date('2026-10-18T00:00:00Z'),
      signatureValid: true,
    });
    assert.equal(r.expired, true);
    assert.equal(r.tier, 'strict', 'expiry does not change tier per §4.5');
  });

  it('flags expired when now < valid_from', () => {
    const r = evaluateTier({
      document: load('signed-strict.json'),
      now: new Date('2026-04-19T00:00:00Z'),
      signatureValid: true,
    });
    assert.equal(r.expired, true);
  });

  it('reports tier:invalid for non-object input', () => {
    const r = evaluateTier({ document: 'string', now: CLOCK_INSIDE });
    assert.equal(r.tier, 'invalid');
    assert.deepEqual([...r.satisfied], []);
  });

  it('reports tier:invalid for document missing required Minimal fields', () => {
    const r = evaluateTier({ document: { llmo_version: '0.1' }, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'invalid');
    assert.ok(r.failures.length > 0);
  });

  it('Standard fails when servingDomain mismatches primary_domain', () => {
    const doc = load('unsigned-standard.json') as { entity: { primary_domain: string } };
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE, servingDomain: 'wrong.example.com' });
    assert.equal(r.tier, 'minimal');
    assert.ok(r.failures.some((f) => f.tier === 'standard' && /serving domain/.test(f.message)));
  });

  it('Strict fails when JWKS Cache-Control max-age exceeds 86400', () => {
    const r = evaluateTier({
      document: load('signed-strict.json'),
      now: CLOCK_INSIDE,
      signatureValid: true,
      jwksCacheControlMaxAgeSeconds: 86401,
    });
    assert.equal(r.tier, 'standard', 'JWKS cache-too-long downgrades from Strict');
    assert.ok(r.failures.some((f) => f.tier === 'strict' && /max-age/.test(f.message)));
  });
});
