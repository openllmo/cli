// LLMO Key Transparency registry consumer (LIP-4 §3.4 X7 check).
//
// Advisory in v0.1.x: the check returns a status but does not on its
// own downgrade tier. The verify command surfaces the result in the
// JSON output and the human-readable report; tier-determining
// enforcement begins after LIP-4 transitions Final AND the 90-day
// grace period documented in LIP-4 §5 elapses.

import {
  calculateJwkThumbprint,
  compactVerify,
  importJWK,
  type JWK,
  type KeyLike,
} from 'jose';

export type X7Status = 'pass' | 'fail' | 'skip';

export interface X7Result {
  status: X7Status;
  note: string;
  entries_returned?: number;
  entries_verified?: number;
}

export interface EvaluateX7Input {
  /** the publisher's primary_domain to query the registry for */
  domain: string;
  /** the public JWK of the document's signing key (from the JWKS) */
  signingKey: JWK;
  /** base URL of the registry (e.g., https://llmo.org/kt/v1) */
  registry: string;
  /** optional fetch implementation, primarily for testing */
  fetchImpl?: typeof fetch;
}

const ENTRY_TYP = 'llmo-kt-entry+jws';

export async function evaluateX7(input: EvaluateX7Input): Promise<X7Result> {
  const fetchImpl = input.fetchImpl ?? fetch;

  // 1. Compute the publisher's signing-key thumbprint.
  let docThumbprint: string;
  try {
    docThumbprint = await calculateJwkThumbprint(input.signingKey, 'sha384');
  } catch (err) {
    return {
      status: 'skip',
      note: `cannot compute publisher JWK thumbprint: ${(err as Error).message}`,
    };
  }

  // 2. Query the registry for entries under the publisher's domain.
  const base = input.registry.replace(/\/+$/, '');
  const url = `${base}/entries?domain=${encodeURIComponent(input.domain)}`;
  let resp: Response;
  try {
    resp = await fetchImpl(url);
  } catch (err) {
    return {
      status: 'skip',
      note: `KT registry unreachable (transient): ${(err as Error).message}`,
    };
  }
  if (!resp.ok) {
    return {
      status: 'skip',
      note: `KT registry returned HTTP ${resp.status}`,
    };
  }
  let body: unknown;
  try {
    body = await resp.json();
  } catch {
    return { status: 'skip', note: 'KT registry response is not valid JSON' };
  }
  const entries = isEntriesShape(body) ? body.entries : [];

  if (entries.length === 0) {
    return {
      status: 'fail',
      note: `kt_uninlogged: no KT entries returned for domain ${input.domain}`,
      entries_returned: 0,
      entries_verified: 0,
    };
  }

  // 3. For each entry: verify the inline-signed JWS, confirm the
  //    inline-JWK thumbprint matches the payload's claimed thumbprint,
  //    check whether the thumbprint equals the doc's thumbprint.
  let entriesVerified = 0;
  let matched = false;
  for (const entry of entries) {
    const entryJws = entry?.entry;
    if (typeof entryJws !== 'string') continue;
    const result = await verifyOneEntry(entryJws);
    if (!result.ok) continue;
    entriesVerified += 1;
    if (result.payload?.jwk_thumbprint === docThumbprint) {
      matched = true;
      break;
    }
  }

  if (matched) {
    return {
      status: 'pass',
      note: 'publisher signing key registered in KT log; entry JWS verifies against inline JWK and thumbprint matches deployed JWKS',
      entries_returned: entries.length,
      entries_verified: entriesVerified,
    };
  }
  return {
    status: 'fail',
    note: `kt_uninlogged: ${entries.length} entries returned for ${input.domain}, ${entriesVerified} verified by signature, none match the deployed JWKS key thumbprint`,
    entries_returned: entries.length,
    entries_verified: entriesVerified,
  };
}

interface EntriesResponse {
  entries: Array<{ entry?: string } | undefined>;
}

function isEntriesShape(body: unknown): body is EntriesResponse {
  return (
    typeof body === 'object' &&
    body !== null &&
    'entries' in body &&
    Array.isArray((body as { entries: unknown }).entries)
  );
}

interface EntryPayload {
  domain: string;
  kid: string;
  jwk_thumbprint: string;
  doc_url: string;
  doc_id: string;
  observed_at: string;
}

async function verifyOneEntry(
  entryJws: string
): Promise<{ ok: boolean; payload?: EntryPayload }> {
  try {
    const { payload, protectedHeader } = await compactVerify(
      entryJws,
      async (header): Promise<KeyLike | Uint8Array> => {
        if (!header.jwk) throw new Error('entry has no inline jwk');
        if (!header.alg) throw new Error('entry has no alg');
        return (await importJWK(header.jwk as JWK, header.alg)) as KeyLike | Uint8Array;
      }
    );
    if (protectedHeader.typ !== ENTRY_TYP) return { ok: false };
    const inlineJwk = protectedHeader.jwk as JWK | undefined;
    if (!inlineJwk) return { ok: false };
    const computedThumbprint = await calculateJwkThumbprint(inlineJwk, 'sha384');
    const decoded = JSON.parse(new TextDecoder().decode(payload)) as EntryPayload;
    if (decoded.jwk_thumbprint !== computedThumbprint) return { ok: false };
    return { ok: true, payload: decoded };
  } catch {
    return { ok: false };
  }
}
