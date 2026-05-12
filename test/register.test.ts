// CLI-command-level tests for `llmo register`. Exercises runRegister()
// against a mocked fetch (we don't hit a real KT registry from tests),
// asserts the constructed JWS structure matches LIP-4 §3.2, and that
// the registry-side validation logic mirrored locally would accept it.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
  compactVerify,
  type KeyLike,
} from 'jose';
import { runRegister } from '../src/commands/register.js';

let workDir: string;
let keyPath: string;
let kid: string;
let publicJwk: Awaited<ReturnType<typeof exportJWK>>;
let mockedFetch: typeof fetch;
let originalFetch: typeof fetch;
let lastCapturedBody: string | null;
let lastCapturedHeaders: Headers | null;
let nextMockResponse: { status: number; body: object } = {
  status: 201,
  body: {
    entry_id: 1,
    log_position: 1,
    appended_at: '2026-05-12T20:30:00Z',
    receipt: 'eyJhbGciOi...mock-receipt-jws',
  },
};

before(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'llmo-register-test-'));

  const { publicKey, privateKey } = await generateKeyPair('ES384', { extractable: true });
  publicJwk = await exportJWK(publicKey as KeyLike);
  kid = await calculateJwkThumbprint(publicJwk, 'sha384');
  publicJwk.alg = 'ES384';
  publicJwk.use = 'sig';
  publicJwk.kid = kid;

  const privateJwk = await exportJWK(privateKey as KeyLike);
  privateJwk.alg = 'ES384';
  privateJwk.use = 'sig';
  privateJwk.kid = kid;

  keyPath = join(workDir, 'test-publisher-private.jwk');
  writeFileSync(keyPath, JSON.stringify(privateJwk, null, 2));

  originalFetch = globalThis.fetch;
  mockedFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    lastCapturedBody = typeof init?.body === 'string' ? init.body : null;
    lastCapturedHeaders = new Headers(init?.headers ?? {});
    return new Response(JSON.stringify(nextMockResponse.body), {
      status: nextMockResponse.status,
      headers: { 'content-type': 'application/json' },
    });
  };
  globalThis.fetch = mockedFetch;
});

after(() => {
  globalThis.fetch = originalFetch;
  if (workDir && existsSync(workDir)) {
    rmSync(workDir, { recursive: true, force: true });
  }
});

describe('register: JWS construction (LIP-4 §3.2)', () => {
  it('constructs a compact JWS that verifies against the inline jwk', async () => {
    nextMockResponse = {
      status: 201,
      body: { entry_id: 42, log_position: 42, appended_at: '2026-05-12T20:30:00Z', receipt: 'mock' },
    };
    const outPath = join(workDir, 'receipt-1.json');
    await runRegister({
      key: keyPath,
      domain: 'example.com',
      docId: 'doc-test-1',
      registry: 'https://example-registry.invalid/kt/v1',
      out: outPath,
    });

    assert.ok(lastCapturedBody, 'fetch was not called');
    const segments = lastCapturedBody.split('.');
    assert.equal(segments.length, 3, 'compact JWS has three segments');

    const protectedHeader = JSON.parse(Buffer.from(segments[0], 'base64url').toString());
    assert.equal(protectedHeader.alg, 'ES384');
    assert.equal(protectedHeader.kid, kid);
    assert.equal(protectedHeader.typ, 'llmo-kt-entry+jws');
    assert.ok(protectedHeader.jwk, 'inline jwk in protected header');

    const inlineJwk = protectedHeader.jwk;
    assert.equal(inlineJwk.kty, 'EC');
    assert.equal(inlineJwk.crv, 'P-384');
    assert.equal(inlineJwk.x, publicJwk.x);
    assert.equal(inlineJwk.y, publicJwk.y);
    assert.equal(inlineJwk.d, undefined, 'no private material leaked into inline jwk');

    const { payload } = await compactVerify(lastCapturedBody, inlineJwk);
    const decoded = JSON.parse(new TextDecoder().decode(payload));
    assert.equal(decoded.domain, 'example.com');
    assert.equal(decoded.kid, kid);
    assert.equal(decoded.doc_url, 'https://example.com/.well-known/llmo.json');
    assert.equal(decoded.doc_id, 'doc-test-1');
    assert.match(decoded.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);

    const expectedThumbprint = await calculateJwkThumbprint(inlineJwk, 'sha384');
    assert.equal(decoded.jwk_thumbprint, expectedThumbprint);
  });

  it('sends Content-Type: application/jose+json', async () => {
    nextMockResponse = {
      status: 201,
      body: { entry_id: 2, log_position: 2, appended_at: '2026-05-12T20:31:00Z', receipt: 'mock' },
    };
    await runRegister({
      key: keyPath,
      domain: 'example.com',
      docId: 'doc-test-2',
      registry: 'https://example-registry.invalid/kt/v1',
      out: join(workDir, 'receipt-2.json'),
    });
    assert.equal(lastCapturedHeaders?.get('content-type'), 'application/jose+json');
  });

  it('writes the receipt to disk', async () => {
    nextMockResponse = {
      status: 201,
      body: { entry_id: 3, log_position: 3, appended_at: '2026-05-12T20:32:00Z', receipt: 'mock-receipt-jws-string' },
    };
    const outPath = join(workDir, 'receipt-3.json');
    await runRegister({
      key: keyPath,
      domain: 'example.com',
      docId: 'doc-test-3',
      registry: 'https://example-registry.invalid/kt/v1',
      out: outPath,
    });
    assert.ok(existsSync(outPath), 'receipt file was written');
    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(written.entry_id, 3);
    assert.equal(written.receipt, 'mock-receipt-jws-string');
  });

  it('uses default doc_url when not provided', async () => {
    nextMockResponse = {
      status: 201,
      body: { entry_id: 4, log_position: 4, appended_at: '2026-05-12T20:33:00Z', receipt: 'mock' },
    };
    await runRegister({
      key: keyPath,
      domain: 'TEST.EXAMPLE.com',
      docId: 'doc-test-4',
      registry: 'https://example-registry.invalid/kt/v1',
      out: join(workDir, 'receipt-4.json'),
    });
    const segments = lastCapturedBody!.split('.');
    const decoded = JSON.parse(Buffer.from(segments[1], 'base64url').toString());
    assert.equal(decoded.domain, 'test.example.com', 'domain lowercased');
    assert.equal(decoded.doc_url, 'https://test.example.com/.well-known/llmo.json');
  });

  it('rejects a public-only JWK (no d field)', async () => {
    const publicOnlyPath = join(workDir, 'public-only.jwk');
    writeFileSync(publicOnlyPath, JSON.stringify(publicJwk, null, 2));
    await assert.rejects(
      runRegister({
        key: publicOnlyPath,
        domain: 'example.com',
        docId: 'doc-test-5',
        registry: 'https://example-registry.invalid/kt/v1',
        out: join(workDir, 'receipt-5.json'),
      }),
      /has no 'd' field/
    );
  });

  it('propagates a registry error response', async () => {
    nextMockResponse = {
      status: 400,
      body: { error: 'thumbprint_mismatch', detail: 'payload.jwk_thumbprint does not match' },
    };
    await assert.rejects(
      runRegister({
        key: keyPath,
        domain: 'example.com',
        docId: 'doc-test-6',
        registry: 'https://example-registry.invalid/kt/v1',
        out: join(workDir, 'receipt-6.json'),
      }),
      /registry returned 400/
    );
  });
});
