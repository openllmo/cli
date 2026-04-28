// Tier evaluation per LLMO §5. Pure function: takes a parsed document
// plus optional URL-mode-only context (serving domain, signature
// validity, JWKS cache-max-age) and returns the satisfied tier with
// per-rule failure detail. The CLI layer is responsible for collecting
// the URL-mode context before calling this.
//
// Decision: tier and freshness are reported orthogonally per §4.5. An
// expired document with a valid signature reports its evaluated tier
// AND expired:true; the signature does not become invalid because of
// expiry.
//
// Decision: an invalid signature on a document that meets Standard
// rules reports tier:standard with strict failures populated, not
// tier:invalid. This implements the §4.5 downgrade-not-poisoning rule.

export type Tier = 'invalid' | 'minimal' | 'standard' | 'strict';
export type SatisfiedTier = Exclude<Tier, 'invalid'>;

export interface TierFailure {
  tier: SatisfiedTier;
  rule: string;
  section: string;
  message: string;
}

export interface TierInput {
  document: unknown;
  now: Date;
  servingDomain?: string;
  signatureValid?: boolean;
  jwksCacheControlMaxAgeSeconds?: number;
}

export interface TierResult {
  tier: Tier;
  satisfied: ReadonlyArray<SatisfiedTier>;
  expired: boolean;
  failures: ReadonlyArray<TierFailure>;
  notes: ReadonlyArray<string>;
}

const MS_PER_DAY = 86_400_000;

export function evaluateTier(input: TierInput): TierResult {
  const failures: TierFailure[] = [];
  const notes: string[] = [];

  if (typeof input.document !== 'object' || input.document === null || Array.isArray(input.document)) {
    return {
      tier: 'invalid',
      satisfied: [],
      expired: false,
      failures: [{ tier: 'minimal', rule: 'document is JSON object', section: '§3.1', message: 'document is not a JSON object' }],
      notes,
    };
  }
  const doc = input.document as Record<string, unknown>;

  // §5.1 Minimal
  const validFrom = parseDate(doc.valid_from);
  const validUntil = parseDate(doc.valid_until);
  if (!validFrom) {
    failures.push({ tier: 'minimal', rule: 'valid_from parses', section: '§3.3', message: 'valid_from missing or not a valid RFC 3339 timestamp' });
  }
  if (!validUntil) {
    failures.push({ tier: 'minimal', rule: 'valid_until parses', section: '§3.3', message: 'valid_until missing or not a valid RFC 3339 timestamp' });
  }
  if (validFrom && validUntil) {
    if (validFrom.getTime() >= validUntil.getTime()) {
      failures.push({ tier: 'minimal', rule: 'valid_from precedes valid_until', section: '§5.1', message: 'valid_from must precede valid_until' });
    }
    const days = (validUntil.getTime() - validFrom.getTime()) / MS_PER_DAY;
    if (days > 365) {
      failures.push({ tier: 'minimal', rule: 'window <= 365 days', section: '§5.1', message: `validity window is ${days.toFixed(1)} days; must be <= 365` });
    }
  }
  if (doc.llmo_version !== '0.1') {
    failures.push({ tier: 'minimal', rule: 'llmo_version is "0.1"', section: '§3.1', message: `llmo_version must be "0.1", got ${JSON.stringify(doc.llmo_version)}` });
  }
  const claims = doc.claims;
  if (!Array.isArray(claims)) {
    failures.push({ tier: 'minimal', rule: 'claims is array', section: '§3.1', message: 'claims must be present and be an array' });
  } else {
    claims.forEach((claim, i) => {
      const c = claim as Record<string, unknown> | null;
      if (typeof c !== 'object' || c === null) {
        failures.push({ tier: 'minimal', rule: 'claim is object', section: '§5.1', message: `claims[${i}] is not an object` });
        return;
      }
      if (typeof c.type !== 'string') {
        failures.push({ tier: 'minimal', rule: 'claim has type', section: '§5.1', message: `claims[${i}] missing type` });
      }
      if (typeof c.statement !== 'object' || c.statement === null) {
        failures.push({ tier: 'minimal', rule: 'claim has statement', section: '§5.1', message: `claims[${i}] missing statement` });
      }
    });
  }

  // §5.2 Standard
  if (Array.isArray(claims)) {
    const types = (claims as Array<Record<string, unknown>>).map((c) => c?.type);
    if (!types.includes('canonical_urls')) {
      failures.push({ tier: 'standard', rule: 'has canonical_urls claim', section: '§5.2', message: 'document must contain at least one canonical_urls claim' });
    }
    if (!types.includes('official_channels')) {
      failures.push({ tier: 'standard', rule: 'has official_channels claim', section: '§5.2', message: 'document must contain at least one official_channels claim' });
    }
  }
  if (validFrom && validUntil) {
    const days = (validUntil.getTime() - validFrom.getTime()) / MS_PER_DAY;
    if (days > 180) {
      failures.push({ tier: 'standard', rule: 'window <= 180 days', section: '§5.2', message: `validity window is ${days.toFixed(1)} days; must be <= 180` });
    }
  }
  if (input.servingDomain) {
    const entity = doc.entity as Record<string, unknown> | undefined;
    const primaryDomain = entity?.primary_domain;
    if (typeof primaryDomain === 'string' && primaryDomain !== input.servingDomain) {
      failures.push({
        tier: 'standard',
        rule: 'primary_domain matches serving domain',
        section: '§5.2',
        message: `entity.primary_domain (${primaryDomain}) does not match serving domain (${input.servingDomain})`,
      });
    }
  } else {
    notes.push('§5.2 primary_domain match not evaluated: no serving domain provided (informational; not applicable to local-file inputs)');
  }
  notes.push('§5.2 URL-scope rule (URLs resolve to primary_domain or aliases) not evaluated in v0.1.0; informational');

  // §5.3 Strict
  const docHasSignature = typeof doc.signature === 'object' && doc.signature !== null;
  if (!docHasSignature) {
    failures.push({ tier: 'strict', rule: 'has document-level signature', section: '§5.3', message: 'document has no top-level signature field' });
  } else if (input.signatureValid === undefined) {
    failures.push({ tier: 'strict', rule: 'signature valid', section: '§5.3', message: 'signature was present but not verified by caller' });
    notes.push('§5.3 signature validity not evaluated: caller passed signatureValid=undefined');
  } else if (input.signatureValid === false) {
    failures.push({ tier: 'strict', rule: 'signature valid', section: '§5.3', message: 'JWS signature did not verify' });
  }
  if (input.jwksCacheControlMaxAgeSeconds !== undefined) {
    if (input.jwksCacheControlMaxAgeSeconds > 86400) {
      failures.push({
        tier: 'strict',
        rule: 'JWKS cache-control max-age <= 86400',
        section: '§5.3',
        message: `JWKS Cache-Control max-age is ${input.jwksCacheControlMaxAgeSeconds}s; must be <= 86400`,
      });
    }
  } else {
    notes.push('§5.3 JWKS Cache-Control max-age not evaluated (URL-mode-only)');
  }
  notes.push('§5.3 URL-claims-domain-ownership rule (canonical_urls reference required) not evaluated in v0.1.0; informational');

  // Aggregate
  const minimalFailures = failures.filter((f) => f.tier === 'minimal');
  const standardFailures = failures.filter((f) => f.tier === 'standard');
  const strictFailures = failures.filter((f) => f.tier === 'strict');

  const meetsMinimal = minimalFailures.length === 0;
  const meetsStandard = meetsMinimal && standardFailures.length === 0;
  const meetsStrict = meetsStandard && strictFailures.length === 0;

  const satisfied: SatisfiedTier[] = [];
  let tier: Tier = 'invalid';
  if (meetsMinimal) {
    satisfied.push('minimal');
    tier = 'minimal';
  }
  if (meetsStandard) {
    satisfied.push('standard');
    tier = 'standard';
  }
  if (meetsStrict) {
    satisfied.push('strict');
    tier = 'strict';
  }

  // Freshness (orthogonal to tier)
  let expired = false;
  if (validFrom && validUntil) {
    const t = input.now.getTime();
    if (t < validFrom.getTime() || t > validUntil.getTime()) expired = true;
  }

  return { tier, satisfied, expired, failures, notes };
}

function parseDate(v: unknown): Date | null {
  if (typeof v !== 'string') return null;
  const d = new Date(v);
  if (isNaN(d.getTime())) return null;
  return d;
}
