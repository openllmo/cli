import { Command } from 'commander';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { JWK } from 'jose';
import { schema as schemaJson, validate, formatErrors } from '../lib/schema.js';
import { verify as verifyJws, type DocumentSignature } from '../lib/jws.js';
import { evaluateTier, type Tier, type TierFailure } from '../lib/tier.js';
import { fetchJwks, parseJwksFromText, findKeyByKid, type Jwks } from '../lib/jwks.js';
import { LlmoError, type SchemaIssue } from '../lib/errors.js';

interface VerifyOpts {
  jwks?: string;
  requireTier?: string;
  ignoreExpiry?: boolean;
  json?: boolean;
  now?: string;
}

export interface PerClaimSignatureResult {
  index: number;
  claim_id: string | null;
  type: string | null;
  presence: 'present' | 'absent';
  verification: 'verified' | 'failed' | 'unverified' | null;
  error?: string;
  kid?: string;
}

export interface VerifyJsonResult {
  tier: Tier;
  satisfied: ReadonlyArray<Tier>;
  signatureValid: boolean | null;
  perClaimSignatures: PerClaimSignatureResult[];
  expired: boolean;
  schemaErrors: SchemaIssue[];
  tierFailures: TierFailure[];
  jwksResolved: boolean;
  kidMatched: boolean;
  corsHeaderPresent?: boolean;
}

export interface VerifyOutcome {
  exitCode: number;
  result: VerifyJsonResult;
  notes: string[];
}

const PRIMARY_DOMAIN_PATTERN = extractPrimaryDomainPattern();

export function verifyCommand(): Command {
  return new Command('verify')
    .description('Verify an llmo.json document and report its conformance tier')
    .argument('<target>', 'URL, bare domain (auto-resolves to https://<domain>/.well-known/llmo.json), or local file path')
    .option('--jwks <url-or-path>', 'override JWKS resolution: URL or local file path')
    .option('--require-tier <tier>', 'fail if tier requirement not met: minimal | standard | strict')
    .option('--ignore-expiry', 'suppress expiry flag in human output (JSON output always reports it)')
    .option('--json', 'emit structured JSON output instead of human-readable text')
    .option('--now <iso8601>', 'override current time as RFC 3339 / ISO 8601 timestamp')
    .action(async (target: string, opts: VerifyOpts) => {
      const outcome = await runVerify(target, opts);
      if (opts.json) {
        process.stdout.write(JSON.stringify(outcome.result, null, 2) + '\n');
      } else {
        printHuman(outcome, opts);
      }
      process.exit(outcome.exitCode);
    });
}

export async function runVerify(target: string, opts: VerifyOpts): Promise<VerifyOutcome> {
  const now = opts.now ? new Date(opts.now) : new Date();
  if (isNaN(now.getTime())) {
    return failHard(1, `--now is not a valid ISO 8601 timestamp: ${opts.now}`);
  }
  if (opts.requireTier && !['minimal', 'standard', 'strict'].includes(opts.requireTier)) {
    return failHard(1, `--require-tier must be one of: minimal, standard, strict (got '${opts.requireTier}')`);
  }

  // Resolve target.
  let docText: string;
  let servingDomain: string | undefined;
  let corsHeaderPresent: boolean | undefined;
  try {
    if (target.startsWith('https://') || target.startsWith('http://')) {
      const url = new URL(target);
      const fetched = await fetchDoc(url.toString());
      docText = fetched.body;
      servingDomain = url.hostname;
      corsHeaderPresent = fetched.corsAllowAll;
    } else if (PRIMARY_DOMAIN_PATTERN.test(target) && !existsSync(target)) {
      const url = `https://${target}/.well-known/llmo.json`;
      const fetched = await fetchDoc(url);
      docText = fetched.body;
      servingDomain = target;
      corsHeaderPresent = fetched.corsAllowAll;
    } else {
      docText = readFileSync(resolve(target), 'utf8');
    }
  } catch (e) {
    return failHard(2, `infrastructure failure: ${(e as Error).message}`);
  }

  // Parse.
  let doc: Record<string, unknown>;
  try {
    const parsed = JSON.parse(docText);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return failHard(1, 'document is not a JSON object');
    }
    doc = parsed;
  } catch (e) {
    return failHard(1, `target is not valid JSON: ${(e as Error).message}`);
  }

  // Schema validation.
  const schemaOk = validate(doc);
  const schemaErrors = schemaOk ? [] : formatErrors(validate.errors);

  // Signature verification (document-level and per-claim).
  let signatureValid: boolean | null = null;
  let jwksResolved = false;
  let kidMatched = false;
  let jwksMaxAge: number | undefined;
  let signatureError: string | undefined;

  // JWKS fetch is hoisted: needed if EITHER the document or any claim has a signature.
  const docHasSig = typeof doc.signature === 'object' && doc.signature !== null;
  const claimsArray: unknown[] = Array.isArray(doc.claims) ? (doc.claims as unknown[]) : [];
  const anyClaimHasSig = claimsArray.some((c) => {
    if (!c || typeof c !== 'object') return false;
    const sig = (c as { signature?: unknown }).signature;
    return typeof sig === 'object' && sig !== null;
  });
  const anySig = docHasSig || anyClaimHasSig;

  let jwks: Jwks | null = null;
  if (anySig) {
    try {
      if (opts.jwks) {
        if (opts.jwks.startsWith('http://') || opts.jwks.startsWith('https://')) {
          const fetched = await fetchJwks(opts.jwks);
          jwks = fetched.jwks;
          jwksMaxAge = fetched.cacheControlMaxAgeSeconds;
        } else {
          jwks = parseJwksFromText(readFileSync(resolve(opts.jwks), 'utf8'));
        }
      } else if (servingDomain) {
        const fetched = await fetchJwks(`https://${servingDomain}/.well-known/llmo-keys.json`);
        jwks = fetched.jwks;
        jwksMaxAge = fetched.cacheControlMaxAgeSeconds;
      }
    } catch (e) {
      signatureError = `JWKS fetch failed: ${(e as Error).message}`;
    }
  }

  // Document-level verification.
  if (docHasSig) {
    const sig = doc.signature as DocumentSignature;
    if (jwks) {
      jwksResolved = true;
      let kid: string | undefined;
      try {
        const headerJson = Buffer.from(sig.protected, 'base64url').toString('utf8');
        kid = JSON.parse(headerJson).kid as string;
      } catch {
        signatureValid = false;
        signatureError = 'protected header is not valid base64url JSON';
      }
      if (kid) {
        const matchingJwk: JWK | undefined = findKeyByKid(jwks, kid);
        if (matchingJwk) {
          kidMatched = true;
          try {
            await verifyJws({ target: doc, signature: sig, publicKey: matchingJwk });
            signatureValid = true;
          } catch (e) {
            signatureValid = false;
            signatureError = (e as Error).message;
          }
        } else {
          signatureValid = false;
          signatureError = `no kid match: protected header kid='${kid}' not found in JWKS (kids present: ${jwks.keys.map((k) => k.kid).join(', ')})`;
        }
      }
    } else if (!signatureError) {
      // No JWKS source available: signature presence noted but not verified.
      signatureError = 'no JWKS source available (--jwks not provided and no serving domain to derive one from)';
    }
  }

  // Per-claim verification (X6 per spec §5.3).
  const perClaimSignatures: PerClaimSignatureResult[] = [];
  let perClaimSignaturesValid: boolean | undefined = undefined;

  if (claimsArray.length > 0) {
    let anyFailed = false;
    let anyChecked = false;

    for (let i = 0; i < claimsArray.length; i++) {
      const claim = claimsArray[i];
      if (!claim || typeof claim !== 'object') {
        perClaimSignatures.push({
          index: i,
          claim_id: null,
          type: null,
          presence: 'absent',
          verification: null,
        });
        continue;
      }

      const claimObj = claim as Record<string, unknown>;
      const claimSig = claimObj.signature;
      const claimId = typeof claimObj.claim_id === 'string' ? claimObj.claim_id : null;
      const claimType = typeof claimObj.type === 'string' ? claimObj.type : null;

      if (!claimSig || typeof claimSig !== 'object') {
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'absent',
          verification: null,
        });
        continue;
      }

      // Per-claim signature is present.
      if (!jwks) {
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'present',
          verification: 'unverified',
          error: 'JWKS not available',
        });
        continue;
      }

      const sig = claimSig as DocumentSignature;
      let kid: string | undefined;
      try {
        const headerJson = Buffer.from(sig.protected, 'base64url').toString('utf8');
        const parsed = JSON.parse(headerJson) as { kid?: unknown };
        kid = typeof parsed.kid === 'string' ? parsed.kid : undefined;
      } catch {
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'present',
          verification: 'failed',
          error: 'protected header decode failed',
        });
        anyFailed = true;
        anyChecked = true;
        continue;
      }

      if (!kid) {
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'present',
          verification: 'failed',
          error: 'protected header missing kid',
        });
        anyFailed = true;
        anyChecked = true;
        continue;
      }

      const matchingJwk: JWK | undefined = findKeyByKid(jwks, kid);
      if (!matchingJwk) {
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'present',
          verification: 'failed',
          error: `kid '${kid}' not in JWKS`,
        });
        anyFailed = true;
        anyChecked = true;
        continue;
      }

      try {
        await verifyJws({ target: claim, signature: sig, publicKey: matchingJwk });
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'present',
          verification: 'verified',
          kid,
        });
        anyChecked = true;
      } catch (e) {
        perClaimSignatures.push({
          index: i,
          claim_id: claimId,
          type: claimType,
          presence: 'present',
          verification: 'failed',
          error: (e as Error).message,
          kid,
        });
        anyFailed = true;
        anyChecked = true;
      }
    }

    if (anyChecked) {
      perClaimSignaturesValid = !anyFailed;
    }
    // If anyChecked is false (no claim had a verifiable signature), perClaimSignaturesValid stays undefined.
  }

  // Tier evaluation.
  const tierResult = evaluateTier({
    document: doc,
    now,
    servingDomain,
    signatureValid: signatureValid === null ? undefined : signatureValid,
    perClaimSignaturesValid,
    jwksCacheControlMaxAgeSeconds: jwksMaxAge,
  });

  // Final tier: invalid if schema invalid, else from tier result.
  let finalTier: Tier = tierResult.tier;
  if (!schemaOk) {
    finalTier = 'invalid';
  }

  const result: VerifyJsonResult = {
    tier: finalTier,
    satisfied: schemaOk ? tierResult.satisfied : [],
    signatureValid,
    perClaimSignatures,
    expired: tierResult.expired,
    schemaErrors,
    tierFailures: [...tierResult.failures],
    jwksResolved,
    kidMatched,
  };
  if (corsHeaderPresent !== undefined) {
    result.corsHeaderPresent = corsHeaderPresent;
  }

  // Exit code.
  let exitCode = 0;
  if (!schemaOk) {
    exitCode = 1;
  } else if (opts.requireTier) {
    const required = opts.requireTier as Tier;
    if (!tierResult.satisfied.includes(required as Exclude<Tier, 'invalid'>)) {
      exitCode = 1;
    }
  }
  if ((signatureValid === false || perClaimSignaturesValid === false) && opts.requireTier === 'strict') {
    exitCode = 1;
  }

  const notes: string[] = [...tierResult.notes];
  if (signatureError) notes.push(`signature: ${signatureError}`);

  return { exitCode, result, notes };
}

interface FetchDocResult {
  body: string;
  corsAllowAll: boolean;
}

async function fetchDoc(url: string): Promise<FetchDocResult> {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) {
    throw new Error(`document fetch failed: ${response.status} ${response.statusText} for ${url}`);
  }
  const body = await response.text();
  const cors = response.headers.get('access-control-allow-origin');
  return { body, corsAllowAll: cors === '*' };
}

function failHard(exitCode: number, message: string): VerifyOutcome {
  return {
    exitCode,
    result: {
      tier: 'invalid',
      satisfied: [],
      signatureValid: null,
      perClaimSignatures: [],
      expired: false,
      schemaErrors: [],
      tierFailures: [],
      jwksResolved: false,
      kidMatched: false,
    },
    notes: [message],
  };
}

function extractPrimaryDomainPattern(): RegExp {
  // Pull the regex out of the vendored schema rather than duplicating it.
  const s = schemaJson as { $defs: { entity: { properties: { primary_domain: { pattern: string } } } } };
  return new RegExp(s.$defs.entity.properties.primary_domain.pattern);
}

function printHuman(outcome: VerifyOutcome, opts: VerifyOpts): void {
  const { result, notes } = outcome;
  const isTty = process.stdout.isTTY;
  const colour = (s: string, c: string): string => (isTty ? `\x1b[${c}m${s}\x1b[0m` : s);
  const tierColour = (t: Tier): string => {
    if (t === 'strict') return '32';
    if (t === 'standard') return '36';
    if (t === 'minimal') return '33';
    return '31';
  };

  process.stdout.write(`Tier: ${colour(result.tier.toUpperCase(), tierColour(result.tier))}\n`);
  if (result.satisfied.length > 0) {
    process.stdout.write(`Satisfied: ${result.satisfied.join(', ')}\n`);
  }
  if (result.signatureValid === true) {
    process.stdout.write(`Signature: ${colour('valid', '32')}\n`);
  } else if (result.signatureValid === false) {
    process.stdout.write(`Signature: ${colour('INVALID', '31')}\n`);
  } else if (typeof result.signatureValid === 'boolean') {
    // never (TypeScript exhaustiveness placeholder)
  } else {
    process.stdout.write('Signature: not present or not evaluated\n');
  }

  // Per-claim signatures.
  const perClaim = result.perClaimSignatures || [];
  const claimsWithSigs = perClaim.filter((pc) => pc.presence === 'present');
  if (claimsWithSigs.length === 0) {
    if (perClaim.length > 0) {
      process.stdout.write(`Per-claim signatures: none present\n`);
    }
    // If perClaim is empty (no claims at all), print nothing.
  } else {
    process.stdout.write(`Per-claim signatures:\n`);
    for (const pc of claimsWithSigs) {
      const lbl = pc.claim_id ? `"${pc.claim_id}"` : `index ${pc.index}`;
      let statusStr: string;
      if (pc.verification === 'verified') {
        statusStr = colour('verified', '32') + (pc.kid ? `, kid=${pc.kid}` : '');
      } else if (pc.verification === 'failed') {
        statusStr = colour('INVALID', '31') + (pc.error ? `, ${pc.error}` : '');
      } else if (pc.verification === 'unverified') {
        statusStr = colour('unverified', '33') + (pc.error ? `, ${pc.error}` : '');
      } else {
        statusStr = 'not evaluated';
      }
      process.stdout.write(`  claim ${lbl} (${pc.type ?? 'unknown'}): ${statusStr}\n`);
    }
  }

  if (!opts.ignoreExpiry || opts.json) {
    if (result.expired) {
      process.stdout.write(`Freshness: ${colour('EXPIRED', '31')}\n`);
    } else {
      process.stdout.write(`Freshness: in window\n`);
    }
  }
  if (result.schemaErrors.length > 0) {
    process.stdout.write('\nSchema errors:\n');
    for (const e of result.schemaErrors) {
      process.stdout.write(`  ${e.path} (${e.keyword}): ${e.message}\n`);
    }
  }
  if (result.tierFailures.length > 0) {
    process.stdout.write('\nTier rule failures:\n');
    for (const f of result.tierFailures) {
      process.stdout.write(`  [${f.tier}] ${f.section} ${f.rule}: ${f.message}\n`);
    }
  }
  if (notes.length > 0) {
    process.stdout.write('\nNotes:\n');
    for (const n of notes) process.stdout.write(`  ${n}\n`);
  }
  if (outcome.exitCode !== 0) {
    process.stdout.write(`\nExit: ${outcome.exitCode}\n`);
  }

  // Quiet unused warning when no exhaustiveness needed.
  void LlmoError;
}
