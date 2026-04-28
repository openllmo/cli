// CLI-command-level tests for `llmo sign`. Exercises runSign() which is
// the same code path the action handler invokes, but lets us assert on
// return values and inspect on-disk artifacts without spawning a process.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPair, exportPKCS8, exportJWK, calculateJwkThumbprint, type KeyLike } from 'jose';
import { runSign } from '../src/commands/sign.js';

let workDir: string;
let pemPath: string;
let kid: string;
let publicJwk: Awaited<ReturnType<typeof exportJWK>>;

before(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'llmo-sign-test-'));
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  publicJwk = await exportJWK(publicKey as KeyLike);
  kid = await calculateJwkThumbprint(publicJwk);
  publicJwk.alg = 'ES256';
  publicJwk.use = 'sig';
  publicJwk.kid = kid;
  pemPath = join(workDir, `llmo-private-${kid}.pem`);
  writeFileSync(pemPath, await exportPKCS8(privateKey as KeyLike));
});

after(() => {
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

function sampleDoc() {
  return {
    llmo_version: '0.1',
    entity: { name: 'TestCo', primary_domain: 'test.example.com' },
    claims: [
      { type: 'canonical_urls', statement: { homepage: 'https://test.example.com/' } },
      { type: 'official_channels', statement: { email_domains: ['test.example.com'] } },
    ],
    valid_from: '2026-04-01T00:00:00Z',
    valid_until: '2026-06-30T00:00:00Z',
    document_id: 'sign-test-001',
  };
}

describe('llmo sign command', () => {
  it('writes <file>.signed.json by default and reattaches signature in on-disk shape', async () => {
    const inPath = join(workDir, 'doc-default.json');
    writeFileSync(inPath, JSON.stringify(sampleDoc()));
    const out = await runSign(inPath, { key: pemPath, kid, alg: 'ES256' });
    assert.equal(out, `${inPath}.signed.json`);
    assert.ok(existsSync(out));
    const signed = JSON.parse(readFileSync(out, 'utf8'));
    assert.ok(signed.signature, 'signed output must have a signature field');
    assert.equal(typeof signed.signature.protected, 'string');
    assert.equal(typeof signed.signature.signature, 'string');
  });

  it('writes to --out path when provided', async () => {
    const inPath = join(workDir, 'doc-out.json');
    const outPath = join(workDir, 'custom-output.json');
    writeFileSync(inPath, JSON.stringify(sampleDoc()));
    const out = await runSign(inPath, { key: pemPath, kid, alg: 'ES256', out: outPath });
    assert.equal(out, outPath);
    assert.ok(existsSync(outPath));
  });

  it('overwrites the input file when --in-place is set', async () => {
    const inPath = join(workDir, 'doc-inplace.json');
    writeFileSync(inPath, JSON.stringify(sampleDoc()));
    const out = await runSign(inPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });
    assert.equal(out, inPath);
    const signed = JSON.parse(readFileSync(inPath, 'utf8'));
    assert.ok(signed.signature);
  });

  it('refuses to operate on *.signed.json without --in-place or --out', async () => {
    const inPath = join(workDir, 'already.signed.json');
    writeFileSync(inPath, JSON.stringify(sampleDoc()));
    await assert.rejects(
      runSign(inPath, { key: pemPath, kid, alg: 'ES256' }),
      /Refusing to write/,
    );
  });

  it('strips and replaces an existing signature on re-sign', async () => {
    const inPath = join(workDir, 'doc-resign.json');
    writeFileSync(inPath, JSON.stringify(sampleDoc()));
    await runSign(inPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });
    const firstSigned = JSON.parse(readFileSync(inPath, 'utf8'));
    const firstSignature = firstSigned.signature.signature;

    // Mutate document_id so canonical bytes change, then re-sign.
    firstSigned.document_id = 'sign-test-001-v2';
    writeFileSync(inPath, JSON.stringify(firstSigned));
    await runSign(inPath, { key: pemPath, kid, alg: 'ES256', inPlace: true });
    const secondSigned = JSON.parse(readFileSync(inPath, 'utf8'));
    assert.notEqual(secondSigned.signature.signature, firstSignature, 're-sign should produce a new signature');
  });

  it('rejects schema-invalid documents with a SchemaError', async () => {
    const inPath = join(workDir, 'doc-bad.json');
    writeFileSync(inPath, JSON.stringify({ llmo_version: '0.2' })); // missing all required fields
    await assert.rejects(runSign(inPath, { key: pemPath, kid, alg: 'ES256' }), /schema/);
  });

  it('signs a single claim by claim_id when --claim is provided', async () => {
    const doc = sampleDoc();
    doc.claims[0] = { ...doc.claims[0], claim_id: 'claim-A' } as unknown as typeof doc.claims[0];
    const inPath = join(workDir, 'doc-claim.json');
    writeFileSync(inPath, JSON.stringify(doc));
    const out = await runSign(inPath, { key: pemPath, kid, alg: 'ES256', inPlace: true, claim: 'claim-A' });
    assert.equal(out, inPath);
    const signed = JSON.parse(readFileSync(inPath, 'utf8'));
    assert.ok(signed.claims[0].signature, 'targeted claim should have a signature field');
    assert.ok(!signed.signature, 'document-level signature should NOT be added when --claim is used');
  });

  // Quiet unused-import warning if @types/node strictness changes.
  void publicJwk;
});
