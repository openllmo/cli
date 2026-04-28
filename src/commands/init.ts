import { Command } from 'commander';
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { input, checkbox, number } from '@inquirer/prompts';
import { schema as schemaJson } from '../lib/schema.js';
import { LlmoError } from '../lib/errors.js';

export interface InitOpts {
  nonInteractive?: boolean;
  name?: string;
  domain?: string;
  includeClaims?: string;
  validityDays?: number;
  force?: boolean;
  out?: string;
}

export interface InitResult {
  path: string;
  document: Record<string, unknown>;
}

const PRIMARY_DOMAIN_PATTERN = (() => {
  const s = schemaJson as { $defs: { entity: { properties: { primary_domain: { pattern: string } } } } };
  return new RegExp(s.$defs.entity.properties.primary_domain.pattern);
})();

const DEFAULT_VALIDITY_DAYS = 90;
const MAX_VALIDITY_DAYS = 365;

// Decision: only support stubbing simple claim types in init. Reason:
// disavowal/supersedes have minItems:1 so empty stubs would fail schema;
// pointer requires concrete url/scope. Users who want those types add
// them by hand after init.
const STUB_CLAIM_TYPES = ['canonical_urls', 'official_channels', 'product_facts', 'personnel', 'identity'] as const;

export function initCommand(): Command {
  return new Command('init')
    .description(
      'Scaffold an llmo.json document. Interactive by default; pass --non-interactive plus required flags for unattended use.',
    )
    .option('--non-interactive', 'skip prompts; require --name and --domain')
    .option('--name <name>', 'entity name')
    .option('--domain <fqdn>', 'primary domain')
    .option(
      '--include-claims <list>',
      `comma-separated claim types to scaffold; supported: ${STUB_CLAIM_TYPES.join(', ')}`,
    )
    .option(
      '--validity-days <days>',
      `validity window in days (default ${DEFAULT_VALIDITY_DAYS}, max ${MAX_VALIDITY_DAYS})`,
      (v) => parseInt(v, 10),
    )
    .option('--force', 'overwrite existing output file without confirmation')
    .option('--out <path>', 'output file path', './llmo.json')
    .action(async (opts: InitOpts) => {
      try {
        const result = await runInit(opts);
        process.stdout.write(`Wrote ${result.path}\n`);
      } catch (e) {
        if (e instanceof LlmoError) {
          process.stderr.write(`error (${e.section ?? 'general'}): ${e.message}\n`);
        } else {
          process.stderr.write(`error: ${(e as Error).message}\n`);
        }
        process.exit(1);
      }
    });
}

export async function runInit(opts: InitOpts): Promise<InitResult> {
  const outPath = resolve(opts.out ?? './llmo.json');

  if (existsSync(outPath) && !opts.force) {
    throw new LlmoError(
      `Refusing to overwrite existing file at ${outPath}. Pass --force to overwrite, or --out <path> for a different location.`,
      '§3.1',
    );
  }

  let name: string;
  let domain: string;
  let claimTypes: string[];
  let validityDays: number;

  if (opts.nonInteractive) {
    if (!opts.name || opts.name.trim() === '') {
      throw new LlmoError('--non-interactive requires --name <entity>', '§3.2');
    }
    if (!opts.domain) {
      throw new LlmoError('--non-interactive requires --domain <fqdn>', '§3.2');
    }
    name = opts.name.trim();
    domain = opts.domain;
    claimTypes = opts.includeClaims
      ? opts.includeClaims.split(',').map((s) => s.trim()).filter(Boolean)
      : [];
    validityDays = opts.validityDays ?? DEFAULT_VALIDITY_DAYS;
  } else {
    name = (await input({
      message: 'Entity name',
      validate: (v: string) => (v.trim().length > 0 ? true : 'Name is required'),
    })).trim();
    domain = await input({
      message: 'Primary domain (e.g., example.com)',
      validate: (v: string) =>
        PRIMARY_DOMAIN_PATTERN.test(v) ? true : 'Must match the schema regex for entity.primary_domain',
    });
    claimTypes = await checkbox({
      message: 'Claim types to scaffold (none = Minimal tier output)',
      choices: STUB_CLAIM_TYPES.map((c) => ({ name: c, value: c })),
    });
    const days = await number({
      message: `Validity window in days (max ${MAX_VALIDITY_DAYS})`,
      default: DEFAULT_VALIDITY_DAYS,
      min: 1,
      max: MAX_VALIDITY_DAYS,
    });
    validityDays = days ?? DEFAULT_VALIDITY_DAYS;
  }

  if (!PRIMARY_DOMAIN_PATTERN.test(domain)) {
    throw new LlmoError(
      `Domain '${domain}' does not match the schema regex for entity.primary_domain (§3.2)`,
      '§3.2',
    );
  }
  if (!Number.isFinite(validityDays) || validityDays < 1 || validityDays > MAX_VALIDITY_DAYS) {
    throw new LlmoError(
      `--validity-days must be between 1 and ${MAX_VALIDITY_DAYS}; got ${validityDays}`,
      '§5.1',
    );
  }
  for (const c of claimTypes) {
    if (!(STUB_CLAIM_TYPES as readonly string[]).includes(c)) {
      throw new LlmoError(
        `Unknown claim type '${c}'. Supported in init: ${STUB_CLAIM_TYPES.join(', ')}.`,
        '§3.5',
      );
    }
  }

  const now = new Date();
  const validUntil = new Date(now.getTime() + validityDays * 86_400_000);
  const claims = claimTypes.map((type) => buildClaimStub(type, domain));

  const doc: Record<string, unknown> = {
    llmo_version: '0.1',
    entity: { name, primary_domain: domain },
    claims,
    valid_from: formatRFC3339Seconds(now),
    valid_until: formatRFC3339Seconds(validUntil),
    document_id: `${now.getUTCFullYear()}-q${quarter(now)}-initial`,
  };

  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n');
  return { path: outPath, document: doc };
}

function buildClaimStub(type: string, domain: string): Record<string, unknown> {
  switch (type) {
    case 'canonical_urls':
      return { type, statement: { homepage: `https://${domain}/` } };
    case 'official_channels':
      return { type, statement: { email_domains: [domain] } };
    case 'product_facts':
      return { type, statement: { products: [] } };
    case 'personnel':
      return { type, statement: { spokespeople: [] } };
    case 'identity':
      return { type, statement: {} };
    default:
      throw new LlmoError(`Unknown claim type: ${type}`, '§3.5');
  }
}

function formatRFC3339Seconds(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function quarter(d: Date): number {
  return Math.floor(d.getUTCMonth() / 3) + 1;
}
