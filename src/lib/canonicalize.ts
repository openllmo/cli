// Thin wrapper around Erdtman's RFC 8785 (JCS) canonicalize implementation.
// Strips the on-disk `signature` field from a deep clone of the input
// before canonicalizing, so the result is the bytes that LLMO §4.3.2
// specifies as the JWS signing payload.
//
// Decision: deep-clone via JSON round-trip. Reason: llmo.json documents
// are JSON-pure (RFC 8259 values only); structuredClone would also work
// but JSON round-trip is faster and rules out any non-JSON contamination
// before canonicalize() ever sees the input.

// canonicalize is a CJS module whose `module.exports = function`. TypeScript's
// NodeNext resolver sees the bundled .d.ts as a default export but binds the
// import to the module namespace at the type level, which is not callable.
// Use a namespace import and read .default explicitly.
import * as canonicalizeNs from 'canonicalize';
import { JcsError } from './errors.js';

const canonicalize = canonicalizeNs.default as unknown as (input: unknown) => string | undefined;

/**
 * Canonicalize the JCS payload bytes for a target object (document or
 * claim) per LLMO §4.3.1 and §4.3.2. The input's `signature` field, if
 * present at the top level, is removed before canonicalization. The
 * input is not mutated.
 *
 * Returns the canonical JSON serialization as UTF-8 bytes.
 */
export function canonicalizeForSignature(target: unknown): Uint8Array {
  if (target === null || typeof target !== 'object' || Array.isArray(target)) {
    throw new JcsError(
      `canonicalizeForSignature requires a JSON object; got ${target === null ? 'null' : Array.isArray(target) ? 'array' : typeof target}`,
    );
  }
  const clone = JSON.parse(JSON.stringify(target)) as Record<string, unknown>;
  if ('signature' in clone) {
    delete clone.signature;
  }
  const canonical = canonicalize(clone);
  if (typeof canonical !== 'string') {
    throw new JcsError('canonicalize() returned a non-string value; cannot encode as UTF-8 bytes');
  }
  return new TextEncoder().encode(canonical);
}
