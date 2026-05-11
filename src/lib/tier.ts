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
  perClaimSignaturesValid?: boolean;
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

  // §5.2 S4: every claim URL resolves to an owned domain or is on the
  // spec's third-party-allowed field list. Ports validator.js
  // collectClaimUrls + owned-domain check to TS. Third-party-allowed
  // fields per §5.2 S4: pointer.url, disavowal.disavowed[].url,
  // official_channels.community[].url, personnel.spokespeople[].verification.
  const owned = ownedDomainSet(doc);
  if (Array.isArray(claims)) {
    const s4Issues: string[] = [];
    (claims as Array<Record<string, unknown>>).forEach((claim, i) => {
      if (typeof claim !== 'object' || claim === null) return;
      const type = typeof claim.type === 'string' ? claim.type : '';
      collectClaimUrls(claim).forEach((u) => {
        if (u.thirdPartyAllowed) return;
        let host: string;
        try {
          host = new URL(u.url).hostname.toLowerCase();
        } catch {
          s4Issues.push(`claim[${i}] (${type}): ${u.url} is not a parseable URL`);
          return;
        }
        const ok = owned.some((d) => subdomainOrEqual(host, d));
        if (!ok) {
          s4Issues.push(
            `claim[${i}] (${type}): ${u.url} resolves to ${host}, not in owned set {${owned.join(', ') || 'empty'}}`,
          );
        }
      });
    });
    if (s4Issues.length > 0) {
      failures.push({
        tier: 'standard',
        rule: 'all claim URLs resolve to owned domain or are third-party pointers',
        section: '§5.2',
        message: s4Issues.join('; '),
      });
    }
  }

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
  if (input.perClaimSignaturesValid === false) {
    failures.push({
      tier: 'strict',
      rule: 'all per-claim signatures verify',
      section: '§5.3',
      message: 'one or more per-claim JWS signatures did not verify (X6)',
    });
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

  // §5.3 X4: at least one canonical_urls claim must have at least one
  // URL on the entity's owned-domain set. Ports validator.js X4 to TS.
  if (Array.isArray(claims)) {
    const cuClaims = (claims as Array<Record<string, unknown>>).filter((c) => c?.type === 'canonical_urls');
    let x4ok = false;
    for (const c of cuClaims) {
      if (x4ok) break;
      const st = (typeof c.statement === 'object' && c.statement !== null ? c.statement : {}) as Record<string, unknown>;
      for (const k of Object.keys(st)) {
        const v = st[k];
        if (!isUriLike(v)) continue;
        let host: string;
        try {
          host = new URL(v as string).hostname.toLowerCase();
        } catch {
          continue;
        }
        if (owned.some((d) => subdomainOrEqual(host, d))) {
          x4ok = true;
          break;
        }
      }
    }
    if (!x4ok) {
      failures.push({
        tier: 'strict',
        rule: 'canonical_urls claim has owned-domain URL',
        section: '§5.3',
        message: 'no canonical_urls URL matches primary_domain or aliases',
      });
    }
  }

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

// URL ownership helpers, ported from static/js/validator.js (§5.2 S4,
// §5.3 X4). Match the validator's semantics exactly: lowercase, with a
// subdomain-tolerant comparison via subdomainOrEqual.

interface ClaimUrl {
  url: string;
  thirdPartyAllowed: boolean;
}

function isUriLike(s: unknown): s is string {
  if (typeof s !== 'string') return false;
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function subdomainOrEqual(host: string, owned: string): boolean {
  return host === owned || host.endsWith('.' + owned);
}

function ownedDomainSet(doc: Record<string, unknown>): string[] {
  const entity = (typeof doc.entity === 'object' && doc.entity !== null ? doc.entity : {}) as Record<string, unknown>;
  const primary = entity.primary_domain;
  const aliases = Array.isArray(entity.aliases) ? entity.aliases : [];
  return [primary, ...aliases]
    .filter((d): d is string => typeof d === 'string')
    .map((d) => d.toLowerCase());
}

// Mirrors validator.js collectClaimUrls. Third-party-allowed flags
// follow §5.2 S4: pointer.url, disavowal.disavowed[].url,
// official_channels.community[].url, personnel.spokespeople[].verification.
// All other URL-typed claim fields must resolve to an owned domain.
function collectClaimUrls(claim: Record<string, unknown>): ClaimUrl[] {
  const urls: ClaimUrl[] = [];
  const t = claim.type;
  const s = claim.statement;
  if (typeof s !== 'object' || s === null) return urls;
  const stmt = s as Record<string, unknown>;
  const push = (u: unknown, tpa: boolean): void => {
    if (isUriLike(u)) urls.push({ url: u, thirdPartyAllowed: tpa });
  };
  if (t === 'canonical_urls') {
    Object.keys(stmt).forEach((k) => push(stmt[k], false));
  } else if (t === 'official_channels') {
    if (typeof stmt.community === 'object' && stmt.community !== null) {
      const community = stmt.community as Record<string, unknown>;
      Object.keys(community).forEach((k) => push(community[k], true));
    }
  } else if (t === 'product_facts') {
    if (Array.isArray(stmt.products)) {
      stmt.products.forEach((p) => {
        if (typeof p === 'object' && p !== null && 'url' in p) push((p as Record<string, unknown>).url, false);
      });
    }
  } else if (t === 'personnel') {
    if (Array.isArray(stmt.spokespeople)) {
      stmt.spokespeople.forEach((sp) => {
        if (typeof sp === 'object' && sp !== null && 'verification' in sp) {
          push((sp as Record<string, unknown>).verification, true);
        }
      });
    }
  } else if (t === 'disavowal') {
    if (Array.isArray(stmt.disavowed)) {
      stmt.disavowed.forEach((d) => {
        if (typeof d === 'object' && d !== null && 'url' in d) push((d as Record<string, unknown>).url, true);
      });
    }
  } else if (t === 'supersedes') {
    if (Array.isArray(stmt.superseded)) {
      stmt.superseded.forEach((x) => {
        if (typeof x === 'object' && x !== null && 'url' in x) push((x as Record<string, unknown>).url, false);
      });
    }
  } else if (t === 'pointer') {
    if ('url' in stmt) push(stmt.url, true);
  } else if (t === 'categories') {
    // v0.1.8: schema.org Organization subtype URIs in primary + secondary.
    // These are type identifiers (external standards URIs), not endpoints the
    // publisher controls; classify as third-party-allowed for S4. Matches the
    // treatment in static/js/validator.js on llmo.org.
    if ('primary' in stmt) push(stmt.primary, true);
    if (Array.isArray(stmt.secondary)) {
      stmt.secondary.forEach((u) => push(u, true));
    }
  }
  // v0.1.8 contact_points, locations, hours, attributes, operational_status
  // have no URL-typed fields S4 evaluates. Their content (email addresses,
  // postal addresses, coordinates, time strings, attribute values) is not
  // collected here.
  return urls;
}
