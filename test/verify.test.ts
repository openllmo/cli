// CLI-command-level tests for `llmo verify`. Covers BUILD.md tests 7-11:
//   7. Tampering detection
//   8. Schema rejection
//   9. Header tampering rejection (b64:false, non-empty crit)
//  10. Tier downgrade on bad signature (per §4.5)
//  11. JWKS rotation (multi-key JWKS, key removal failure)

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateKeyPair,
  exportJWK,
  exportPKCS8,
  calculateJwkThumbprint,
  type KeyLike,
} from 'jose';
import { runSign } from '../src/commands/sign.js';
import { runVerify } from '../src/commands/verify.js';
import { sign } from '../src/lib/jws.js';

let workDir: string;

const CLOCK_INSIDE = '2026-06-01T00:00:00Z';

function strictDoc(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    llmo_version: '0.1',
    entity: { name: 'TestCo', primary_domain: 'test.example.com' },
    claims: [
      { type: 'canonical_urls', statement: { homepage: 'https://test.example.com/' } },
      { type: 'official_channels', statement: { email_domains: ['test.example.com'] } },
    ],
    valid_from: '2026-04-01T00:00:00Z',
    valid_until: '2026-06-30T00:00:00Z',
    document_id: 'verify-test-001',
    ...overrides,
  };
}

before(() => {
  workDir = mkdtempSync(join(tmpdir(), 'llmo-verify-test-'));
});
after(() => {
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

async function makeKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey as KeyLike);
  const kid = await calculateJwkThumbprint(jwk);
  jwk.alg = 'ES256';
  jwk.use = 'sig';
  jwk.kid = kid;
  const pem = await exportPKCS8(privateKey as KeyLike);
  return { jwk, kid, pem };
}

describe('verify: tampering detection (BUILD.md test 7)', () => {
  it('verify reports signatureValid:false when payload is mutated after signing', async () => {
    const { jwk, kid, pem } = await makeKey();
    const doc = strictDoc();
    const docPath = join(workDir, 'tamper-doc.json');
    const pemPath = join(workDir, 'tamper-key.pem');
    const jwksPath = join(workDir, 'tamper-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    // Mutate document_id (preserves schema validity, breaks signature).
    const signed = JSON.parse(readFileSync(docPath, 'utf8'));
    signed.document_id = 'mutated';
    writeFileSync(docPath, JSON.stringify(signed));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    assert.equal(outcome.result.signatureValid, false);
    assert.equal(outcome.result.tier, 'standard', 'bad signature should NOT block Standard tier per §4.5');
  });
});

describe('verify: schema rejection (BUILD.md test 8)', () => {
  it('reports tier:invalid and schemaErrors when document violates required fields', async () => {
    const docPath = join(workDir, 'bad-schema.json');
    writeFileSync(docPath, JSON.stringify({ llmo_version: '0.2' })); // wrong version, missing fields
    const outcome = await runVerify(docPath, { now: CLOCK_INSIDE });
    assert.equal(outcome.result.tier, 'invalid');
    assert.ok(outcome.result.schemaErrors.length > 0);
    assert.equal(outcome.exitCode, 1);
  });

  it('reports specific schema error for malformed primary_domain', async () => {
    const docPath = join(workDir, 'bad-domain.json');
    const doc = strictDoc({ entity: { name: 'X', primary_domain: 'NOT A DOMAIN' } });
    writeFileSync(docPath, JSON.stringify(doc));
    const outcome = await runVerify(docPath, { now: CLOCK_INSIDE });
    assert.equal(outcome.result.tier, 'invalid');
    assert.ok(outcome.result.schemaErrors.some((e) => /primary_domain/.test(e.path) || /pattern/.test(e.keyword)));
  });
});

describe('verify: §4.3.1 header tampering rejection (BUILD.md test 9)', () => {
  it('rejects a document whose protected header asserts b64:false', async () => {
    const { jwk, kid, pem } = await makeKey();
    const doc = strictDoc();
    const docPath = join(workDir, 'b64-doc.json');
    const pemPath = join(workDir, 'b64-key.pem');
    const jwksPath = join(workDir, 'b64-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    // Replace the protected header with one asserting b64:false but keep the
    // signature bytes. §4.3.1 must reject before any crypto.
    const signed = JSON.parse(readFileSync(docPath, 'utf8'));
    const tamperedHeader = { alg: 'ES256', kid, b64: false };
    signed.signature.protected = Buffer.from(JSON.stringify(tamperedHeader)).toString('base64url');
    writeFileSync(docPath, JSON.stringify(signed));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    assert.equal(outcome.result.signatureValid, false, 'b64:false must cause signature failure');
    // Tier should downgrade per §4.5.
    assert.equal(outcome.result.tier, 'standard');
  });

  it('rejects a document whose protected header has non-empty crit', async () => {
    const { jwk, kid, pem } = await makeKey();
    const doc = strictDoc();
    const docPath = join(workDir, 'crit-doc.json');
    const pemPath = join(workDir, 'crit-key.pem');
    const jwksPath = join(workDir, 'crit-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    const signed = JSON.parse(readFileSync(docPath, 'utf8'));
    const tamperedHeader = { alg: 'ES256', kid, crit: ['custom'] };
    signed.signature.protected = Buffer.from(JSON.stringify(tamperedHeader)).toString('base64url');
    writeFileSync(docPath, JSON.stringify(signed));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    assert.equal(outcome.result.signatureValid, false);
  });
});

describe('verify: tier downgrade on bad signature (BUILD.md test 10)', () => {
  it('reports tier:standard, signatureValid:false for a Strict-shape doc with broken signature', async () => {
    const { jwk, kid, pem } = await makeKey();
    const doc = strictDoc();
    const docPath = join(workDir, 'downgrade-doc.json');
    const pemPath = join(workDir, 'downgrade-key.pem');
    const jwksPath = join(workDir, 'downgrade-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    // Corrupt the signature by flipping a middle base64url character.
    // (The LAST char of a base64url-encoded 64-byte ECDSA signature only
    // carries 2 real bits + 4 padding bits, so 'A'/'B' substitution there
    // can decode identically. Mutate the middle to guarantee a real-byte
    // change.)
    const signed = JSON.parse(readFileSync(docPath, 'utf8'));
    const sigStr = signed.signature.signature as string;
    const midIdx = Math.floor(sigStr.length / 2);
    const mid = sigStr[midIdx];
    signed.signature.signature = sigStr.slice(0, midIdx) + (mid === 'A' ? 'B' : 'A') + sigStr.slice(midIdx + 1);
    writeFileSync(docPath, JSON.stringify(signed));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    assert.equal(outcome.result.tier, 'standard', 'invalid signature must NOT yield tier:invalid (§4.5)');
    assert.equal(outcome.result.signatureValid, false);
    assert.deepEqual([...outcome.result.satisfied], ['minimal', 'standard']);
  });
});

describe('verify: JWKS rotation (BUILD.md test 11)', () => {
  it('two keys in JWKS and two docs signed by different kids each verify; removing the matching key fails', async () => {
    const a = await makeKey();
    const b = await makeKey();

    // Manual JWKS containing both public JWKs.
    const jwksBoth = { keys: [a.jwk, b.jwk] };
    const jwksAOnly = { keys: [a.jwk] };
    const jwksPathBoth = join(workDir, 'rotation-jwks-both.json');
    const jwksPathAOnly = join(workDir, 'rotation-jwks-a-only.json');
    writeFileSync(jwksPathBoth, JSON.stringify(jwksBoth));
    writeFileSync(jwksPathAOnly, JSON.stringify(jwksAOnly));

    const docA = strictDoc({ document_id: 'rotation-A' });
    const docB = strictDoc({ document_id: 'rotation-B' });
    const docAPath = join(workDir, 'rotation-doc-a.json');
    const docBPath = join(workDir, 'rotation-doc-b.json');
    const pemAPath = join(workDir, 'rotation-key-a.pem');
    const pemBPath = join(workDir, 'rotation-key-b.pem');
    writeFileSync(docAPath, JSON.stringify(docA));
    writeFileSync(docBPath, JSON.stringify(docB));
    writeFileSync(pemAPath, a.pem);
    writeFileSync(pemBPath, b.pem);

    await runSign(docAPath, { key: pemAPath, kid: a.kid, alg: 'ES256', inPlace: true });
    await runSign(docBPath, { key: pemBPath, kid: b.kid, alg: 'ES256', inPlace: true });

    // Both verify against the multi-key JWKS.
    const outA = await runVerify(docAPath, { jwks: jwksPathBoth, now: CLOCK_INSIDE });
    const outB = await runVerify(docBPath, { jwks: jwksPathBoth, now: CLOCK_INSIDE });
    assert.equal(outA.result.signatureValid, true);
    assert.equal(outA.result.kidMatched, true);
    assert.equal(outB.result.signatureValid, true);
    assert.equal(outB.result.kidMatched, true);

    // Remove key B from JWKS: doc B should fail with a clear no-kid-match error.
    const outBAfterRemoval = await runVerify(docBPath, { jwks: jwksPathAOnly, now: CLOCK_INSIDE });
    assert.equal(outBAfterRemoval.result.signatureValid, false);
    assert.equal(outBAfterRemoval.result.kidMatched, false);
    assert.ok(outBAfterRemoval.notes.some((n) => /no kid match/i.test(n)));
  });
});

describe('verify: tier requirement and exit code', () => {
  it('exits 0 when --require-tier minimal is met', async () => {
    const { jwk, kid, pem } = await makeKey();
    const doc = strictDoc();
    const docPath = join(workDir, 'rt-min.json');
    const pemPath = join(workDir, 'rt-min.pem');
    const jwksPath = join(workDir, 'rt-min-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });
    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE, requireTier: 'minimal' });
    assert.equal(outcome.exitCode, 0);
  });

  it('exits 1 when --require-tier strict is set but signature invalid', async () => {
    const { jwk, kid, pem } = await makeKey();
    const doc = strictDoc();
    const docPath = join(workDir, 'rt-strict.json');
    const pemPath = join(workDir, 'rt-strict.pem');
    const jwksPath = join(workDir, 'rt-strict-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    const signed = JSON.parse(readFileSync(docPath, 'utf8'));
    const sigStr = signed.signature.signature as string;
    const midIdx = Math.floor(sigStr.length / 2);
    const mid = sigStr[midIdx];
    signed.signature.signature = sigStr.slice(0, midIdx) + (mid === 'A' ? 'B' : 'A') + sigStr.slice(midIdx + 1);
    writeFileSync(docPath, JSON.stringify(signed));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE, requireTier: 'strict' });
    assert.equal(outcome.exitCode, 1);
  });
});

// ============================================================================
// Per-claim signature verification (commit D, v0.1.5 X6)
// ============================================================================

async function makeKeyForAlg(alg: 'ES256' | 'ES384' | 'EdDSA') {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = await exportJWK(publicKey as KeyLike);
  const kid = await calculateJwkThumbprint(jwk);
  jwk.alg = alg;
  jwk.use = 'sig';
  jwk.kid = kid;
  const pem = await exportPKCS8(privateKey as KeyLike);
  return { jwk, kid, pem, privateKey: privateKey as KeyLike };
}

async function signClaim(
  claim: Record<string, unknown>,
  privateKey: KeyLike,
  kid: string,
  alg: 'ES256' | 'ES384' | 'EdDSA' = 'ES256',
): Promise<Record<string, unknown>> {
  const sig = await sign({ target: claim, alg, kid, privateKey });
  return { ...claim, signature: sig };
}

const STRICT_BASE_CLAIMS = [
  { type: 'canonical_urls', statement: { homepage: 'https://test.example.com/' } },
  { type: 'official_channels', statement: { email_domains: ['test.example.com'] } },
];

describe('verify: per-claim signature verification (commit D, X6 per §5.3)', () => {
  it('verifies a per-claim signature when valid (X6 PASS)', async () => {
    const { jwk, kid, privateKey } = await makeKeyForAlg('ES256');
    const baseClaim = { claim_id: 'test-disavowal', type: 'disavowal', statement: { disavowed: [{ what: 'test', detail: 'd' }] } };
    const signedClaim = await signClaim(baseClaim, privateKey, kid, 'ES256');
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-pass.json');
    const jwksPath = join(workDir, 'pcs-pass-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const disavowal = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'test-disavowal');
    assert.ok(disavowal, 'test-disavowal entry should exist in perClaimSignatures');
    assert.equal(disavowal!.presence, 'present');
    assert.equal(disavowal!.verification, 'verified');
    assert.equal(disavowal!.kid, kid);
  });

  it('reports failed when per-claim signature is tampered (X6 FAIL)', async () => {
    const { jwk, kid, privateKey } = await makeKeyForAlg('ES256');
    const baseClaim = { claim_id: 'test-disavowal', type: 'disavowal', statement: { disavowed: [{ what: 'test', detail: 'd' }] } };
    const signedClaim = await signClaim(baseClaim, privateKey, kid, 'ES256');
    // Mutate the claim payload after signing.
    (signedClaim.statement as { disavowed: Array<{ what: string }> }).disavowed[0].what = 'mutated';
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-fail-tamper.json');
    const jwksPath = join(workDir, 'pcs-fail-tamper-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const disavowal = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'test-disavowal');
    assert.ok(disavowal);
    assert.equal(disavowal!.verification, 'failed');
    assert.ok(disavowal!.error, 'error should be populated for failed verification');
  });

  it('reports failed when per-claim kid not in JWKS', async () => {
    const keyA = await makeKeyForAlg('ES256');
    const keyB = await makeKeyForAlg('ES256');
    const baseClaim = { claim_id: 'orphan-kid', type: 'disavowal', statement: { disavowed: [{ what: 'x', detail: 'd' }] } };
    // Sign with key A, but JWKS only contains key B.
    const signedClaim = await signClaim(baseClaim, keyA.privateKey, keyA.kid, 'ES256');
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-fail-kid.json');
    const jwksPath = join(workDir, 'pcs-fail-kid-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(jwksPath, JSON.stringify({ keys: [keyB.jwk] }));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const orphan = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'orphan-kid');
    assert.ok(orphan);
    assert.equal(orphan!.verification, 'failed');
    assert.ok(orphan!.error && orphan!.error.includes(keyA.kid), 'error should mention the orphan kid');
  });

  it('reports failed when per-claim protected header malformed', async () => {
    const { jwk } = await makeKeyForAlg('ES256');
    const signedClaim = {
      claim_id: 'bad-header',
      type: 'disavowal',
      statement: { disavowed: [{ what: 'x', detail: 'd' }] },
      signature: {
        // Decodes to bytes but not to valid JSON.
        protected: 'bm90LWpzb24',
        signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    };
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-fail-header.json');
    const jwksPath = join(workDir, 'pcs-fail-header-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const bad = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'bad-header');
    assert.ok(bad);
    assert.equal(bad!.verification, 'failed');
  });

  it('handles document-level + per-claim both pass', async () => {
    const { jwk, kid, pem, privateKey } = await makeKeyForAlg('ES256');
    const baseClaim = { claim_id: 'test-disavowal', type: 'disavowal', statement: { disavowed: [{ what: 'x', detail: 'd' }] } };
    const signedClaim = await signClaim(baseClaim, privateKey, kid, 'ES256');
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-both-pass.json');
    const pemPath = join(workDir, 'pcs-both-pass.pem');
    const jwksPath = join(workDir, 'pcs-both-pass-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    assert.equal(outcome.result.signatureValid, true);
    const disavowal = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'test-disavowal');
    assert.ok(disavowal);
    assert.equal(disavowal!.verification, 'verified');
    assert.equal(outcome.result.tier, 'strict', 'both signatures pass should yield strict tier');
  });

  it('reports tier downgrade when document-level passes but per-claim fails', async () => {
    const keyA = await makeKeyForAlg('ES256');
    const keyB = await makeKeyForAlg('ES256');
    const baseClaim = { claim_id: 'wrong-key-claim', type: 'disavowal', statement: { disavowed: [{ what: 'x', detail: 'd' }] } };
    // Sign claim with key B, but JWKS contains only key A (which signs the document).
    const signedClaim = await signClaim(baseClaim, keyB.privateKey, keyB.kid, 'ES256');
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-mixed.json');
    const pemPath = join(workDir, 'pcs-mixed.pem');
    const jwksPath = join(workDir, 'pcs-mixed-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, keyA.pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [keyA.jwk] }));
    await runSign(docPath, { key: pemPath, kid: keyA.kid, alg: 'ES256', inPlace: true });

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    assert.equal(outcome.result.signatureValid, true, 'document-level signature should verify against key A');
    const wrongKeyClaim = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'wrong-key-claim');
    assert.ok(wrongKeyClaim);
    assert.equal(wrongKeyClaim!.verification, 'failed');
    assert.equal(outcome.result.tier, 'standard', 'X6 failure should downgrade strict to standard');
  });

  it('passes X6 trivially when no claim has a signature', async () => {
    const { jwk, kid, pem } = await makeKeyForAlg('ES256');
    const doc = strictDoc();
    const docPath = join(workDir, 'pcs-trivial.json');
    const pemPath = join(workDir, 'pcs-trivial.pem');
    const jwksPath = join(workDir, 'pcs-trivial-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(pemPath, pem);
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));
    await runSign(docPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const allAbsent = outcome.result.perClaimSignatures.every(
      (p) => p.presence === 'absent' && p.verification === null,
    );
    assert.ok(allAbsent, 'all claims should have presence:absent, verification:null');
    assert.equal(outcome.result.tier, 'strict', 'no per-claim signatures should pass X6 trivially');
  });

  it('verifies ES384 per-claim signature', async () => {
    const { jwk, kid, privateKey } = await makeKeyForAlg('ES384');
    const baseClaim = { claim_id: 'es384-claim', type: 'disavowal', statement: { disavowed: [{ what: 'x', detail: 'd' }] } };
    const signedClaim = await signClaim(baseClaim, privateKey, kid, 'ES384');
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-es384.json');
    const jwksPath = join(workDir, 'pcs-es384-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const es384 = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'es384-claim');
    assert.ok(es384);
    assert.equal(es384!.verification, 'verified', 'ES384 per-claim signature should verify (CLI supports all three §4.2 algs)');
  });

  it('verifies EdDSA per-claim signature', async () => {
    const { jwk, kid, privateKey } = await makeKeyForAlg('EdDSA');
    const baseClaim = { claim_id: 'eddsa-claim', type: 'disavowal', statement: { disavowed: [{ what: 'x', detail: 'd' }] } };
    const signedClaim = await signClaim(baseClaim, privateKey, kid, 'EdDSA');
    const doc = strictDoc({ claims: [...STRICT_BASE_CLAIMS, signedClaim] });
    const docPath = join(workDir, 'pcs-eddsa.json');
    const jwksPath = join(workDir, 'pcs-eddsa-jwks.json');
    writeFileSync(docPath, JSON.stringify(doc));
    writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }));

    const outcome = await runVerify(docPath, { jwks: jwksPath, now: CLOCK_INSIDE });
    const eddsa = outcome.result.perClaimSignatures.find((p) => p.claim_id === 'eddsa-claim');
    assert.ok(eddsa);
    assert.equal(eddsa!.verification, 'verified', 'EdDSA per-claim signature should verify (CLI supports all three §4.2 algs)');
  });
});
