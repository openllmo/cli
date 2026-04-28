// JWS signing and verification primitives for LLMO §4.3.1.
// All cryptographic operations route through `jose`; this module never
// reaches into node:crypto directly.
//
// Decision: standard attached JWS only. Reason: §4.3.1 prohibits
// detached-payload mode (RFC 7797). Sign asserts the produced protected
// header has only { alg, kid }; verify rejects b64:false and non-empty
// crit before delegating to jose.flattenedVerify.

import {
  FlattenedSign,
  flattenedVerify,
  importJWK,
  importPKCS8,
  type FlattenedJWSInput,
  type JWK,
  type KeyLike,
} from 'jose';
import { canonicalizeForSignature } from './canonicalize.js';
import { JwsError } from './errors.js';

export type SupportedAlg = 'ES256' | 'ES384' | 'EdDSA';
export const SUPPORTED_ALGS: readonly SupportedAlg[] = ['ES256', 'ES384', 'EdDSA'] as const;

export interface DocumentSignature {
  protected: string;
  signature: string;
}

export interface SignArgs {
  target: object;
  alg: SupportedAlg;
  kid: string;
  privateKey: KeyLike | Uint8Array;
}

export interface SignFromPemArgs {
  target: object;
  alg: SupportedAlg;
  kid: string;
  privateKeyPem: string;
}

/**
 * Sign a target object (document or claim) per §4.3.1.
 * Returns the on-disk signature shape: { protected, signature }.
 */
export async function sign(args: SignArgs): Promise<DocumentSignature> {
  if (!SUPPORTED_ALGS.includes(args.alg)) {
    throw new JwsError(`Unsupported alg: ${String(args.alg)}. Allowed: ${SUPPORTED_ALGS.join(', ')}.`, '§4.2');
  }
  const payload = canonicalizeForSignature(args.target);
  const flattened = await new FlattenedSign(payload)
    .setProtectedHeader({ alg: args.alg, kid: args.kid })
    .sign(args.privateKey);

  // Assert: protected header carries exactly { alg, kid } per §4.3.1.
  if (!flattened.protected) {
    throw new JwsError('jose produced a flattened JWS with no protected header');
  }
  const headerJson = new TextDecoder().decode(base64urlDecode(flattened.protected));
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(headerJson) as Record<string, unknown>;
  } catch (cause) {
    throw new JwsError('produced protected header is not valid JSON', '§4.3.1', { cause });
  }
  const keys = Object.keys(header).sort();
  if (keys.length !== 2 || keys[0] !== 'alg' || keys[1] !== 'kid') {
    throw new JwsError(
      `protected header must contain exactly alg and kid per §4.3.1; got ${JSON.stringify(keys)}`,
      '§4.3.1',
    );
  }

  return { protected: flattened.protected, signature: flattened.signature };
}

export async function signFromPem(args: SignFromPemArgs): Promise<DocumentSignature> {
  const key = await importPKCS8(args.privateKeyPem, args.alg);
  return sign({ target: args.target, alg: args.alg, kid: args.kid, privateKey: key });
}

export interface VerifyArgs {
  target: object;
  signature: DocumentSignature;
  publicKey: KeyLike | JWK;
  expectedAlg?: SupportedAlg;
}

export interface VerifyResult {
  protectedHeader: Record<string, unknown>;
  payload: Uint8Array;
}

/**
 * Verify a target object's attached JWS per §4.3.1. Rejects b64:false and
 * non-empty crit before delegating to jose.flattenedVerify.
 *
 * Re-canonicalizes the target (with `signature` stripped) to reconstruct
 * the JWS payload bytes.
 */
export async function verify(args: VerifyArgs): Promise<VerifyResult> {
  // §4.3.1 input gates: parse the protected header and reject prohibited
  // forms before any cryptographic work.
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(args.signature.protected))) as Record<string, unknown>;
  } catch (cause) {
    throw new JwsError('signature.protected is not valid base64url JSON', '§4.3.1', { cause });
  }
  if ('b64' in header) {
    throw new JwsError(
      'JWS protected header asserts b64; detached-payload mode (RFC 7797) is prohibited per §4.3.1',
      '§4.3.1',
    );
  }
  if ('crit' in header) {
    const crit = header.crit;
    if (Array.isArray(crit) && crit.length > 0) {
      throw new JwsError(
        `JWS protected header has non-empty crit parameter; v0.1 prohibits this per §4.3.1`,
        '§4.3.1',
      );
    }
  }
  if (typeof header.alg !== 'string') {
    throw new JwsError('JWS protected header missing required alg', '§4.3.1');
  }
  if (typeof header.kid !== 'string') {
    throw new JwsError('JWS protected header missing required kid', '§4.3.1');
  }
  if (args.expectedAlg && header.alg !== args.expectedAlg) {
    throw new JwsError(`alg mismatch: header=${header.alg} expected=${args.expectedAlg}`, '§4.3.1');
  }

  const payload = canonicalizeForSignature(args.target);
  const jws: FlattenedJWSInput = {
    protected: args.signature.protected,
    payload: base64urlEncode(payload),
    signature: args.signature.signature,
  };

  // Resolve key: JWK gets imported, CryptoKey/KeyObject pass through.
  const isJwk = isJWK(args.publicKey);
  const key = isJwk ? await importJWK(args.publicKey as JWK, header.alg) : (args.publicKey as KeyLike);

  try {
    const result = await flattenedVerify(jws, key);
    return { protectedHeader: header, payload: result.payload };
  } catch (cause) {
    throw new JwsError('signature verification failed', '§4.3.1', { cause });
  }
}

function isJWK(k: unknown): k is JWK {
  return typeof k === 'object' && k !== null && 'kty' in k;
}

function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function base64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}
