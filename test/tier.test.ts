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

// §5.2 S4 (URL ownership) and §5.3 X4 (canonical_urls owned-domain
// reference) enforcement, ported from validator.js. Previously emitted
// as informational notes; now a tier failure when violated.
describe('§5.2 S4 URL ownership enforcement', () => {
  function baseStandardDoc(): Record<string, unknown> {
    return {
      llmo_version: '0.1',
      document_id: 'test-s4',
      valid_from: '2026-04-20T00:00:00Z',
      valid_until: '2026-10-17T00:00:00Z',
      entity: { name: 'JungleCat, Inc.', primary_domain: 'junglecat.example.com' },
      claims: [
        {
          claim_id: 'urls-canonical',
          type: 'canonical_urls',
          statement: { homepage: 'https://junglecat.example.com/' },
        },
        {
          claim_id: 'channels-official',
          type: 'official_channels',
          statement: { email_domains: ['junglecat.example.com'] },
        },
      ],
    };
  }

  it('S4 passes when all non-third-party URLs are on the owned domain', () => {
    const doc = baseStandardDoc();
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'standard');
    assert.equal(r.failures.filter((f) => f.tier === 'standard').length, 0);
  });

  it('S4 passes for third-party-allowed fields on third-party domains', () => {
    const doc = baseStandardDoc();
    (doc.claims as Array<Record<string, unknown>>).push(
      // pointer.url: third-party-allowed
      { claim_id: 'p', type: 'pointer', statement: { url: 'https://archive.org/snapshot' } },
      // disavowal.disavowed[].url: third-party-allowed
      {
        claim_id: 'd',
        type: 'disavowal',
        statement: { disavowed: [{ url: 'https://impostor.example.net/fake' }] },
      },
      // personnel.spokespeople[].verification: third-party-allowed (e.g. github.com)
      {
        claim_id: 'spk',
        type: 'personnel',
        statement: { spokespeople: [{ name: 'CEO', verification: 'https://github.com/junglecat' }] },
      },
    );
    // official_channels.community[]: third-party-allowed
    const channels = (doc.claims as Array<Record<string, unknown>>)[1];
    (channels.statement as Record<string, unknown>).community = {
      forum: 'https://discourse.example.org/junglecat',
    };
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'standard', 'third-party-allowed fields on third-party domains must not fail S4');
    assert.equal(r.failures.filter((f) => f.tier === 'standard').length, 0);
  });

  it('S4 fails when canonical_urls.* points at a non-owned domain', () => {
    const doc = baseStandardDoc();
    const cu = (doc.claims as Array<Record<string, unknown>>)[0];
    (cu.statement as Record<string, unknown>).docs = 'https://docs.thirdparty.example.org/junglecat';
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'minimal', 'S4 violation must downgrade from Standard');
    assert.ok(
      r.failures.some(
        (f) => f.tier === 'standard' && f.section === '§5.2' && /owned domain/.test(f.rule),
      ),
      'should report a §5.2 owned-domain failure',
    );
  });

  it('S4 fails when product_facts.products[].url points at a non-owned domain', () => {
    const doc = baseStandardDoc();
    (doc.claims as Array<Record<string, unknown>>).push({
      claim_id: 'pf',
      type: 'product_facts',
      statement: { products: [{ name: 'Tracker', url: 'https://crunchbase.example.com/junglecat' }] },
    });
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'minimal');
    assert.ok(
      r.failures.some(
        (f) => f.tier === 'standard' && /owned domain/.test(f.rule) && /product_facts/.test(f.message),
      ),
    );
  });

  it('S4 fails when supersedes.superseded[].url points at a non-owned domain', () => {
    const doc = baseStandardDoc();
    (doc.claims as Array<Record<string, unknown>>).push({
      claim_id: 'sup',
      type: 'supersedes',
      statement: { superseded: [{ url: 'https://oldco.example.net/old-doc' }] },
    });
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'minimal');
    assert.ok(
      r.failures.some(
        (f) => f.tier === 'standard' && /owned domain/.test(f.rule) && /supersedes/.test(f.message),
      ),
    );
  });

  it('S4 honors aliases as owned domains and is subdomain-tolerant', () => {
    const doc = baseStandardDoc();
    (doc.entity as Record<string, unknown>).aliases = ['junglecat-alias.example.org'];
    const cu = (doc.claims as Array<Record<string, unknown>>)[0];
    (cu.statement as Record<string, unknown>).docs = 'https://docs.junglecat-alias.example.org/';
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'standard');
    assert.equal(r.failures.filter((f) => f.tier === 'standard').length, 0);
  });

  it('v0.1.8 categories: schema.org primary/secondary URIs are third-party-allowed under S4', () => {
    // Categories claim type added in v0.1.8. The primary and secondary fields
    // hold schema.org Organization subtype URIs (external standards URIs the
    // publisher attests to, not endpoints the publisher controls). collectClaimUrls
    // classifies them as third-party-allowed, matching the treatment of
    // pointer.url and the parallel logic in static/js/validator.js on llmo.org.
    const doc = baseStandardDoc();
    (doc.claims as Array<Record<string, unknown>>).push({
      claim_id: 'cat',
      type: 'categories',
      statement: {
        primary: 'https://schema.org/Restaurant',
        secondary: ['https://schema.org/CafeOrCoffeeShop'],
        naics: ['722511'],
      },
    });
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE });
    assert.equal(r.tier, 'standard', 'categories with off-domain schema.org URIs must not fail S4');
    assert.equal(
      r.failures.filter((f) => f.tier === 'standard' && /owned domain/.test(f.rule)).length,
      0,
      'no S4 ownership failure should fire on categories schema.org URIs',
    );
  });
});

describe('§5.3 X4 canonical_urls owned-domain enforcement', () => {
  function baseStrictDoc(): Record<string, unknown> {
    return {
      llmo_version: '0.1',
      document_id: 'test-x4',
      valid_from: '2026-04-20T00:00:00Z',
      valid_until: '2026-10-17T00:00:00Z',
      entity: { name: 'JungleCat, Inc.', primary_domain: 'junglecat.example.com' },
      claims: [
        {
          claim_id: 'urls-canonical',
          type: 'canonical_urls',
          statement: { homepage: 'https://junglecat.example.com/' },
        },
        {
          claim_id: 'channels-official',
          type: 'official_channels',
          statement: { email_domains: ['junglecat.example.com'] },
        },
      ],
      signature: {
        protected: 'eyJhbGciOiJFUzI1NiIsImtpZCI6Imp1bmdsZWNhdC10ZXN0LTIwMjYifQ',
        signature: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
    };
  }

  it('X4 passes when canonical_urls has at least one owned-domain URL', () => {
    const doc = baseStrictDoc();
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE, signatureValid: true });
    assert.equal(r.tier, 'strict');
  });

  it('X4 fails when canonical_urls statement is empty', () => {
    const doc = baseStrictDoc();
    const cu = (doc.claims as Array<Record<string, unknown>>)[0];
    cu.statement = {};
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE, signatureValid: true });
    assert.equal(r.tier, 'standard', 'X4 violation downgrades from Strict');
    assert.ok(
      r.failures.some(
        (f) => f.tier === 'strict' && /canonical_urls/.test(f.rule),
      ),
      'should report an X4 strict failure',
    );
  });

  it('X4 fails when all canonical_urls URLs are on third-party domains (pointer-style)', () => {
    // Simulates a doc that uses canonical_urls only as pointers to
    // off-domain hosts. S4 already fails this (canonical_urls is not
    // third-party-allowed), but X4 must also fail independently per
    // validator.js.
    const doc = baseStrictDoc();
    const cu = (doc.claims as Array<Record<string, unknown>>)[0];
    cu.statement = { homepage: 'https://thirdparty.example.org/junglecat' };
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE, signatureValid: true });
    // S4 will downgrade to minimal; the X4 failure must still be in failures[].
    assert.ok(
      r.failures.some(
        (f) => f.tier === 'strict' && /canonical_urls/.test(f.rule) && /owned-domain/.test(f.rule),
      ),
      'X4 strict failure must be reported even when S4 also fails',
    );
  });

  it('X4 honors aliases when checking canonical_urls ownership', () => {
    const doc = baseStrictDoc();
    (doc.entity as Record<string, unknown>).aliases = ['junglecat-alias.example.org'];
    const cu = (doc.claims as Array<Record<string, unknown>>)[0];
    cu.statement = { homepage: 'https://www.junglecat-alias.example.org/' };
    const r = evaluateTier({ document: doc, now: CLOCK_INSIDE, signatureValid: true });
    assert.equal(r.tier, 'strict');
    assert.equal(r.failures.filter((f) => f.tier === 'strict').length, 0);
  });
});
