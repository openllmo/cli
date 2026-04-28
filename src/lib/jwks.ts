// JWKS fetch + parse helpers. Used by `verify` and `doctor`.
//
// Decision: parses the Cache-Control max-age directive when present so
// callers can pass it into tier evaluation per §5.3. Failure to parse
// leaves max-age undefined (the tier evaluator treats undefined as
// "URL-mode-only rule not evaluated", which is the correct posture for
// a local-file --jwks input).

import type { JWK } from 'jose';
import { JwksError } from './errors.js';

export interface Jwks {
  keys: JWK[];
}

export interface FetchJwksResult {
  jwks: Jwks;
  cacheControlMaxAgeSeconds?: number;
}

export async function fetchJwks(url: string): Promise<FetchJwksResult> {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) {
    throw new JwksError(`JWKS fetch failed: ${response.status} ${response.statusText} for ${url}`, '§4.2');
  }
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new JwksError(`JWKS at ${url} is not valid JSON`, '§4.2', { cause });
  }
  if (!isJwksShape(parsed)) {
    throw new JwksError(`JWKS at ${url} is malformed: missing 'keys' array`, '§4.2');
  }
  const cacheControl = response.headers.get('cache-control');
  const cacheControlMaxAgeSeconds = cacheControl ? parseMaxAge(cacheControl) : undefined;
  return { jwks: parsed, cacheControlMaxAgeSeconds };
}

export function parseJwksFromText(text: string): Jwks {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new JwksError('JWKS is not valid JSON', '§4.2', { cause });
  }
  if (!isJwksShape(parsed)) {
    throw new JwksError(`JWKS is malformed: missing 'keys' array`, '§4.2');
  }
  return parsed;
}

export function findKeyByKid(jwks: Jwks, kid: string): JWK | undefined {
  return jwks.keys.find((k) => k.kid === kid);
}

function isJwksShape(o: unknown): o is Jwks {
  return typeof o === 'object' && o !== null && Array.isArray((o as { keys?: unknown }).keys);
}

function parseMaxAge(cacheControl: string): number | undefined {
  // Look for max-age=NNNN, case-insensitive, allow whitespace.
  const m = cacheControl.match(/(?:^|,\s*)max-age\s*=\s*(\d+)/i);
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : undefined;
}
