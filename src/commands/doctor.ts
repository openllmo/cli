import { Command } from 'commander';
import { runVerify, type VerifyJsonResult } from './verify.js';

export interface DoctorOpts {
  requireTier?: string;
  json?: boolean;
  now?: string;
  // Test-only knobs. Default values produce the documented two-2s-apart
  // refetch behavior; tests override to skip the wait.
  byteStabilityIntervalMs?: number;
  byteStabilityFetches?: number;
}

export interface DoctorCheck {
  name: string;
  pass: boolean;
  section: string;
  message?: string;
  informational?: boolean;
}

export interface DoctorResult {
  domain: string;
  documentUrl: string;
  jwksUrl: string;
  checks: DoctorCheck[];
  verify: VerifyJsonResult | null;
  byteStability: 'stable' | 'mismatch' | 'not-evaluated';
  exitCode: number;
}

export function doctorCommand(): Command {
  return new Command('doctor')
    .description('End-to-end health check on a deployed /.well-known/llmo.json')
    .argument('<domain>', 'domain to check (e.g., example.com)')
    .option('--require-tier <tier>', 'fail if tier requirement not met: minimal | standard | strict')
    .option('--json', 'emit structured JSON output')
    .option('--now <iso8601>', 'override current time as RFC 3339 / ISO 8601 timestamp')
    .action(async (domain: string, opts: DoctorOpts) => {
      const result = await runDoctor(domain, opts);
      if (opts.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else {
        printHuman(result);
      }
      process.exit(result.exitCode);
    });
}

export async function runDoctor(domain: string, opts: DoctorOpts): Promise<DoctorResult> {
  const documentUrl = `https://${domain}/.well-known/llmo.json`;
  const jwksUrl = `https://${domain}/.well-known/llmo-keys.json`;
  const checks: DoctorCheck[] = [];
  let exitCode = 0;
  let byteStability: 'stable' | 'mismatch' | 'not-evaluated' = 'not-evaluated';
  let verifyResult: VerifyJsonResult | null = null;

  // 1. First fetch + headers.
  let firstBody: string | null = null;
  try {
    const response = await fetch(documentUrl, { redirect: 'follow' });
    firstBody = await response.text();
    checks.push({
      name: 'HTTP 200 on /.well-known/llmo.json',
      pass: response.ok,
      section: '§2.1',
      message: `${response.status} ${response.statusText}`,
    });
    if (!response.ok) {
      return { domain, documentUrl, jwksUrl, checks, verify: null, byteStability, exitCode: 2 };
    }
    const ct = response.headers.get('content-type') ?? '';
    checks.push({
      name: 'Content-Type is application/llmo+json or application/json',
      pass: /^application\/(llmo\+)?json/i.test(ct),
      section: '§2.2',
      message: `Content-Type: ${ct || '(missing)'}`,
    });
    const cc = response.headers.get('cache-control');
    checks.push({
      name: 'Cache-Control header present',
      pass: !!cc,
      section: '§2.4',
      message: `Cache-Control: ${cc ?? '(missing)'}`,
    });
    const cors = response.headers.get('access-control-allow-origin');
    checks.push({
      name: 'Access-Control-Allow-Origin: *',
      pass: cors === '*',
      section: '§2.3',
      message: `Access-Control-Allow-Origin: ${cors ?? '(missing)'}`,
      informational: true,
    });
  } catch (e) {
    checks.push({
      name: 'HTTP 200 on /.well-known/llmo.json',
      pass: false,
      section: '§2.1',
      message: `fetch failed: ${(e as Error).message}`,
    });
    return { domain, documentUrl, jwksUrl, checks, verify: null, byteStability, exitCode: 2 };
  }

  // 2. Verify (composes schema, JWKS fetch, signature check, tier evaluation).
  try {
    const outcome = await runVerify(documentUrl, {
      requireTier: opts.requireTier,
      now: opts.now,
    });
    verifyResult = outcome.result;
    checks.push({
      name: 'Schema valid',
      pass: outcome.result.schemaErrors.length === 0,
      section: '§3',
      message:
        outcome.result.schemaErrors.length === 0
          ? 'OK'
          : `${outcome.result.schemaErrors.length} schema errors`,
    });
    checks.push({
      name: `Tier reached: ${outcome.result.tier}`,
      pass: outcome.result.tier !== 'invalid',
      section: '§5',
      message: `Satisfied: ${outcome.result.satisfied.join(', ') || '(none)'}`,
    });
    if (outcome.result.signatureValid !== null) {
      checks.push({
        name: 'Signature valid',
        pass: outcome.result.signatureValid === true,
        section: '§4.3.1',
      });
    }
    checks.push({
      name: 'Document not expired',
      pass: !outcome.result.expired,
      section: '§4.5',
    });
    if (outcome.exitCode > exitCode) exitCode = outcome.exitCode;
  } catch (e) {
    checks.push({ name: 'Verify completed', pass: false, section: '§4', message: (e as Error).message });
    exitCode = 2;
  }

  // 3. Byte-stability check: refetch with delay; informational only.
  const intervalMs = opts.byteStabilityIntervalMs ?? 2000;
  const totalFetches = opts.byteStabilityFetches ?? 3;
  if (firstBody !== null && totalFetches >= 2) {
    try {
      const bodies: string[] = [firstBody];
      for (let i = 1; i < totalFetches; i++) {
        if (intervalMs > 0) await sleep(intervalMs);
        const response = await fetch(documentUrl, { redirect: 'follow' });
        bodies.push(await response.text());
      }
      const allSame = bodies.every((b) => b === bodies[0]);
      byteStability = allSame ? 'stable' : 'mismatch';
      checks.push({
        name: `Byte-stable across ${totalFetches} fetches (>=${intervalMs}ms apart)`,
        pass: allSame,
        section: '§4.3.3',
        message: allSame
          ? `${bodies[0].length} bytes consistent across all fetches`
          : `byte mismatch: lengths ${bodies.map((b) => b.length).join(', ')}. May be benign cache propagation; persistent mismatch across multiple doctor invocations indicates a CDN reformatting bug.`,
        informational: true,
      });
    } catch (e) {
      checks.push({
        name: 'Byte-stability check',
        pass: false,
        section: '§4.3.3',
        message: `byte-stability check failed: ${(e as Error).message}`,
        informational: true,
      });
    }
  }

  return { domain, documentUrl, jwksUrl, checks, verify: verifyResult, byteStability, exitCode };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function printHuman(result: DoctorResult): void {
  const isTty = process.stdout.isTTY;
  const colour = (s: string, c: string): string => (isTty ? `\x1b[${c}m${s}\x1b[0m` : s);
  process.stdout.write(`Doctor report: ${result.domain}\n`);
  process.stdout.write(`  Document: ${result.documentUrl}\n`);
  process.stdout.write(`  JWKS:     ${result.jwksUrl}\n\n`);
  for (const c of result.checks) {
    const mark = c.pass ? colour('[ok]', '32') : colour(c.informational ? '[note]' : '[fail]', c.informational ? '33' : '31');
    process.stdout.write(`${mark} ${c.section} ${c.name}`);
    if (c.message) process.stdout.write(`\n        ${c.message}`);
    process.stdout.write('\n');
  }
  process.stdout.write(`\nByte stability: ${result.byteStability}\n`);
  process.stdout.write(`Exit: ${result.exitCode}\n`);
}
