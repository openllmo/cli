// Tests for src/lib/jws.ts. Covers:
//   - sign + verify round-trip with a freshly generated keypair
//   - protected header asserts only { alg, kid }
//   - tamper detection: modifying the payload after signing fails verify
//   - §4.3.1 input gates: b64:false rejected, non-empty crit rejected
//   - strict-vector signature verification: signed-strict.json against
//     signed-strict-key.json, mirroring the 5-step procedure from
//     /spec/v0.1/test-vectors

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { sign, verify, type SupportedAlg } from '../src/lib/jws.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, 'fixtures');

function decodeProtected(protectedB64: string): Record<string, unknown> {
  const json = Buffer.from(protectedB64, 'base64url').toString('utf8');
  return JSON.parse(json);
}

function encodeProtected(header: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(header)).toString('base64url');
}

function sampleDoc() {
  return {
    llmo_version: '0.1',
    entity: { name: 'TestCo', primary_domain: 'test.example.com' },
    claims: [],
    valid_from: '2026-04-01T00:00:00Z',
    valid_until: '2026-07-01T00:00:00Z',
    document_id: 'test-jws-001',
  };
}

describe('JWS sign + verify round-trip', () => {
  for (const alg of ['ES256', 'ES384', 'EdDSA'] as SupportedAlg[]) {
    it(`round-trips with ${alg}`, async () => {
      const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
      const doc = sampleDoc();
      const sig = await sign({ target: doc, alg, kid: `kid-${alg}`, privateKey });
      assert.ok(sig.protected, 'protected header present');
      assert.ok(sig.signature, 'signature present');
      const result = await verify({ target: doc, signature: sig, publicKey });
      assert.equal(result.protectedHeader.alg, alg);
      assert.equal(result.protectedHeader.kid, `kid-${alg}`);
    });
  }

  it('protected header contains exactly alg and kid', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const sig = await sign({ target: sampleDoc(), alg: 'ES256', kid: 'k', privateKey });
    const header = decodeProtected(sig.protected);
    assert.deepEqual(Object.keys(header).sort(), ['alg', 'kid']);
    assert.ok(!('b64' in header));
    assert.ok(!('crit' in header));
  });

  it('verify fails when payload is tampered after signing', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const doc = sampleDoc();
    const sig = await sign({ target: doc, alg: 'ES256', kid: 'k', privateKey });
    const tampered = { ...doc, document_id: 'mutated' };
    await assert.rejects(verify({ target: tampered, signature: sig, publicKey }), /verification failed/);
  });
});

describe('§4.3.1 input gates', () => {
  it('rejects b64:false in protected header without performing crypto', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const headerWithB64 = { alg: 'ES256', kid: 'k', b64: false };
    const sig = { protected: encodeProtected(headerWithB64), signature: 'AAAA' };
    await assert.rejects(verify({ target: sampleDoc(), signature: sig, publicKey }), /b64/);
  });

  it('rejects non-empty crit in protected header without performing crypto', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const headerWithCrit = { alg: 'ES256', kid: 'k', crit: ['custom'] };
    const sig = { protected: encodeProtected(headerWithCrit), signature: 'AAAA' };
    await assert.rejects(verify({ target: sampleDoc(), signature: sig, publicKey }), /crit/);
  });

  it('rejects missing alg', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const headerNoAlg = { kid: 'k' };
    const sig = { protected: encodeProtected(headerNoAlg), signature: 'AAAA' };
    await assert.rejects(verify({ target: sampleDoc(), signature: sig, publicKey }), /alg/);
  });

  it('rejects missing kid', async () => {
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const headerNoKid = { alg: 'ES256' };
    const sig = { protected: encodeProtected(headerNoKid), signature: 'AAAA' };
    await assert.rejects(verify({ target: sampleDoc(), signature: sig, publicKey }), /kid/);
  });
});

describe('strict-vector signature verification (5-step procedure)', () => {
  it('verifies signed-strict.json against signed-strict-key.json', async () => {
    // Step 1: fetch the JWKS (here: vendored fixture).
    const jwks = JSON.parse(readFileSync(resolve(fixturesDir, 'signed-strict-key.json'), 'utf8'));
    assert.ok(Array.isArray(jwks.keys) && jwks.keys.length === 1, 'expected a JWKS with exactly one key');
    const jwk = jwks.keys[0];

    // Step 2: locate the key by matching the kid in the JWS protected header
    //         to the kid in the JWKS entry.
    const doc = JSON.parse(readFileSync(resolve(fixturesDir, 'signed-strict.json'), 'utf8'));
    const protectedHeader = decodeProtected(doc.signature.protected);
    assert.equal(
      protectedHeader.kid,
      'i4X5wAhXf9tuf5rnzCIRcE9RhKc-QDFCIbVbgnEBfeU',
      'kid in JWS protected header should match expected fixture kid',
    );
    assert.equal(jwk.kid, protectedHeader.kid, 'JWKS kid should match JWS header kid');

    // Steps 3, 4, 5: strip signature, canonicalize, verify. (verify() does
    // all three internally; canonicalize is called by verify() on the
    // target with signature stripped.)
    const result = await verify({
      target: doc,
      signature: doc.signature,
      publicKey: jwk,
    });
    assert.equal(result.protectedHeader.alg, 'ES256');
    assert.equal(result.protectedHeader.kid, 'i4X5wAhXf9tuf5rnzCIRcE9RhKc-QDFCIbVbgnEBfeU');
  });

  it('fails verification when the signature byte is mutated', async () => {
    const jwks = JSON.parse(readFileSync(resolve(fixturesDir, 'signed-strict-key.json'), 'utf8'));
    const doc = JSON.parse(readFileSync(resolve(fixturesDir, 'signed-strict.json'), 'utf8'));
    // Flip a middle character of the base64url signature. (Avoid the LAST
    // character: for a 64-byte ECDSA signature the trailing base64url char
    // encodes 2 real bits + 4 padding-zero bits, so an A/B swap there can
    // decode identically and not change the underlying bytes.)
    const original = doc.signature.signature as string;
    const midIdx = Math.floor(original.length / 2);
    const mid = original[midIdx];
    const replacement = mid === 'A' ? 'B' : 'A';
    const mutated = original.slice(0, midIdx) + replacement + original.slice(midIdx + 1);
    await assert.rejects(
      verify({
        target: doc,
        signature: { protected: doc.signature.protected, signature: mutated },
        publicKey: jwks.keys[0],
      }),
      /verification failed/,
    );
  });

  // Quiet the unused-import warning in CI lint mode.
  void exportJWK;
});
