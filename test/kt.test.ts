// Tests for the LIP-4 §3.4 X7 KT registry inclusion check.
// Each test mocks fetch and constructs a synthetic registry response;
// no test reaches a real registry.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
  CompactSign,
  type KeyLike,
  type JWK,
} from 'jose';
import { evaluateX7 } from '../src/lib/kt.js';

async function buildEntryJws(publisherKid: string, domain: string, docId: string) {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey as KeyLike);
  publicJwk.alg = 'ES256';
  publicJwk.use = 'sig';
  publicJwk.kid = publisherKid;
  const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha384');
  const payload = {
    domain,
    kid: publisherKid,
    jwk_thumbprint: thumbprint,
    doc_url: `https://${domain}/.well-known/llmo.json`,
    doc_id: docId,
    observed_at: '2026-05-12T20:54:52.667Z',
  };
  const compact = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({
      alg: 'ES256',
      kid: publisherKid,
      typ: 'llmo-kt-entry+jws',
      jwk: publicJwk as Record<string, unknown>,
    })
    .sign(privateKey);
  return { entryJws: compact, publicJwk, thumbprint };
}

describe('X7: KT registry inclusion (LIP-4 §3.4)', () => {
  it('PASS when an entry exists whose verified inline JWK matches the deployed key', async () => {
    const { entryJws, publicJwk } = await buildEntryJws('publisher-2026-01', 'example.com', 'doc-test-1');
    const fetchImpl = async () =>
      new Response(JSON.stringify({ domain: 'example.com', total: 1, entries: [{ entry: entryJws, entry_id: 1, log_position: 1, appended_at: '2026-05-12T20:54:53Z' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const result = await evaluateX7({
      domain: 'example.com',
      signingKey: publicJwk as JWK,
      registry: 'https://example-registry.invalid/kt/v1',
      fetchImpl: fetchImpl as typeof fetch,
    });
    assert.equal(result.status, 'pass');
    assert.equal(result.entries_returned, 1);
    assert.equal(result.entries_verified, 1);
  });

  it('FAIL with kt_uninlogged when no entries returned', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = await exportJWK(publicKey as KeyLike);
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';
    publicJwk.kid = 'unknown-publisher';
    const fetchImpl = async () =>
      new Response(JSON.stringify({ domain: 'example.com', total: 0, entries: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const result = await evaluateX7({
      domain: 'example.com',
      signingKey: publicJwk as JWK,
      registry: 'https://example-registry.invalid/kt/v1',
      fetchImpl: fetchImpl as typeof fetch,
    });
    assert.equal(result.status, 'fail');
    assert.match(result.note, /kt_uninlogged/);
    assert.equal(result.entries_returned, 0);
  });

  it('FAIL when entries exist but none match the deployed key thumbprint', async () => {
    // Build a registry entry for kidA, then probe with kidB.
    const built = await buildEntryJws('publisher-kidA', 'example.com', 'doc-a');
    const { publicKey: pubB } = await generateKeyPair('ES256', { extractable: true });
    const publicJwkB = await exportJWK(pubB as KeyLike);
    publicJwkB.alg = 'ES256';
    publicJwkB.use = 'sig';
    publicJwkB.kid = 'publisher-kidB';
    const fetchImpl = async () =>
      new Response(JSON.stringify({ domain: 'example.com', total: 1, entries: [{ entry: built.entryJws, entry_id: 1, log_position: 1, appended_at: '2026-05-12T20:54:53Z' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const result = await evaluateX7({
      domain: 'example.com',
      signingKey: publicJwkB as JWK,
      registry: 'https://example-registry.invalid/kt/v1',
      fetchImpl: fetchImpl as typeof fetch,
    });
    assert.equal(result.status, 'fail');
    assert.match(result.note, /kt_uninlogged/);
    assert.equal(result.entries_returned, 1);
    assert.equal(result.entries_verified, 1);
  });

  it('SKIP when registry returns 5xx', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = await exportJWK(publicKey as KeyLike);
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';
    publicJwk.kid = 'whatever';
    const fetchImpl = async () => new Response('upstream down', { status: 502 });
    const result = await evaluateX7({
      domain: 'example.com',
      signingKey: publicJwk as JWK,
      registry: 'https://example-registry.invalid/kt/v1',
      fetchImpl: fetchImpl as typeof fetch,
    });
    assert.equal(result.status, 'skip');
    assert.match(result.note, /HTTP 502/);
  });

  it('SKIP when fetch throws (network error)', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = await exportJWK(publicKey as KeyLike);
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';
    publicJwk.kid = 'whatever';
    const fetchImpl = async () => {
      throw new Error('ENETUNREACH');
    };
    const result = await evaluateX7({
      domain: 'example.com',
      signingKey: publicJwk as JWK,
      registry: 'https://example-registry.invalid/kt/v1',
      fetchImpl: fetchImpl as typeof fetch,
    });
    assert.equal(result.status, 'skip');
    assert.match(result.note, /unreachable/);
  });

  it('rejects entries whose inline JWK thumbprint does not match the payload thumbprint', async () => {
    // Build a valid JWS, then tamper with the payload's jwk_thumbprint.
    const { entryJws, publicJwk } = await buildEntryJws('publisher-2026-01', 'example.com', 'doc-test-tamper');
    const [headerB64, , sigB64] = entryJws.split('.');
    const tamperedPayload = {
      domain: 'example.com',
      kid: 'publisher-2026-01',
      jwk_thumbprint: 'TAMPERED-NOT-A-REAL-THUMBPRINT-EVER',
      doc_url: 'https://example.com/.well-known/llmo.json',
      doc_id: 'doc-test-tamper',
      observed_at: '2026-05-12T20:54:52.667Z',
    };
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(tamperedPayload)).toString('base64url');
    const tamperedJws = `${headerB64}.${tamperedPayloadB64}.${sigB64}`;
    const fetchImpl = async () =>
      new Response(JSON.stringify({ domain: 'example.com', total: 1, entries: [{ entry: tamperedJws }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const result = await evaluateX7({
      domain: 'example.com',
      signingKey: publicJwk as JWK,
      registry: 'https://example-registry.invalid/kt/v1',
      fetchImpl: fetchImpl as typeof fetch,
    });
    assert.equal(result.status, 'fail', 'tampered entry should not produce PASS');
    assert.equal(result.entries_verified, 0, 'tampered entry should not be counted as verified');
  });
});
