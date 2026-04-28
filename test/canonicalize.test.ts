import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalizeForSignature } from '../src/lib/canonicalize.js';

describe('canonicalizeForSignature', () => {
  it('produces byte-identical output regardless of top-level key order', () => {
    const a = { z: 1, a: { y: 2, x: 3 } };
    const b = { a: { x: 3, y: 2 }, z: 1 };
    const ca = canonicalizeForSignature(a);
    const cb = canonicalizeForSignature(b);
    assert.deepEqual(Array.from(ca), Array.from(cb));
  });

  it('produces byte-identical output regardless of nested key order', () => {
    const a = { entity: { name: 'X', primary_domain: 'x.example.com', aliases: ['b.com', 'a.com'] } };
    const b = { entity: { aliases: ['b.com', 'a.com'], primary_domain: 'x.example.com', name: 'X' } };
    assert.deepEqual(Array.from(canonicalizeForSignature(a)), Array.from(canonicalizeForSignature(b)));
  });

  it('preserves array element order (JCS does not sort arrays)', () => {
    const a = canonicalizeForSignature({ list: [3, 1, 2] });
    const b = canonicalizeForSignature({ list: [1, 2, 3] });
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it('strips top-level signature field before canonicalization', () => {
    const withSig = { entity: { name: 'X' }, signature: { protected: 'abc', signature: 'xyz' } };
    const withoutSig = { entity: { name: 'X' } };
    assert.deepEqual(
      Array.from(canonicalizeForSignature(withSig)),
      Array.from(canonicalizeForSignature(withoutSig)),
    );
  });

  it('does not mutate the input', () => {
    const input = { entity: { name: 'X' }, signature: { foo: 1 } };
    const before = JSON.stringify(input);
    canonicalizeForSignature(input);
    assert.equal(JSON.stringify(input), before);
  });

  it('does not strip nested signature fields (only top-level)', () => {
    // Per §4.3 a claim's inner signature is the per-claim JWS; canonicalize is
    // called per target object, so when canonicalizing a claim the caller
    // passes the claim, not the wrapping document.
    const a = canonicalizeForSignature({ claims: [{ type: 'x', statement: {}, signature: { foo: 1 } }] });
    const b = canonicalizeForSignature({ claims: [{ type: 'x', statement: {}, signature: { foo: 2 } }] });
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it('returns Uint8Array of UTF-8 bytes', () => {
    const result = canonicalizeForSignature({ name: 'hello' });
    assert.ok(result instanceof Uint8Array);
    assert.equal(new TextDecoder().decode(result), '{"name":"hello"}');
  });

  it('encodes non-ASCII characters as UTF-8', () => {
    const result = canonicalizeForSignature({ name: 'café' });
    const decoded = new TextDecoder().decode(result);
    assert.equal(decoded, '{"name":"café"}');
    // 'café' as UTF-8: 'c'=0x63, 'a'=0x61, 'f'=0x66, 'é'=0xc3 0xa9
    assert.ok(result.includes(0xc3));
    assert.ok(result.includes(0xa9));
  });

  it('rejects non-object inputs', () => {
    assert.throws(() => canonicalizeForSignature(null), /JSON object/);
    assert.throws(() => canonicalizeForSignature('string'), /JSON object/);
    assert.throws(() => canonicalizeForSignature([1, 2, 3]), /JSON object/);
    assert.throws(() => canonicalizeForSignature(42), /JSON object/);
  });
});
