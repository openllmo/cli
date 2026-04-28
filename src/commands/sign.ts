import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { signFromPem, type SupportedAlg, SUPPORTED_ALGS, type DocumentSignature } from '../lib/jws.js';
import { validate, formatErrors } from '../lib/schema.js';
import { LlmoError, SchemaError } from '../lib/errors.js';

interface SignOpts {
  key: string;
  kid: string;
  alg: string;
  inPlace?: boolean;
  out?: string;
  claim?: string;
}

export function signCommand(): Command {
  return new Command('sign')
    .description('Sign an llmo.json document or single claim with a standard attached JWS per §4.3.1')
    .argument('<file>', 'path to llmo.json (or any document conforming to the v0.1 schema)')
    .requiredOption('--key <path>', 'path to PKCS#8 PEM private key')
    .requiredOption('--kid <kid>', 'key identifier; must match the public JWK in the JWKS')
    .option('--alg <alg>', 'signing algorithm: ES256, ES384, or EdDSA', 'ES256')
    .option('--in-place', 'overwrite the input file with the signed output')
    .option('--out <path>', 'write signed output to this path')
    .option('--claim <claim_id>', 'sign a single claim (matched by claim_id) instead of the whole document')
    .action(async (file: string, opts: SignOpts) => {
      try {
        const out = await runSign(file, opts);
        process.stdout.write(`Wrote signed document: ${out}\n\n`);
        process.stdout.write(
          'Sign last. Serve byte-stable. Do not let your CDN, framework, or pre-commit hook reformat this file after signing.\n',
        );
      } catch (e) {
        printError(e);
        process.exit(1);
      }
    });
}

export async function runSign(file: string, opts: SignOpts): Promise<string> {
  if (!(SUPPORTED_ALGS as readonly string[]).includes(opts.alg)) {
    throw new LlmoError(`Unsupported alg: ${opts.alg}. Allowed: ${SUPPORTED_ALGS.join(', ')}.`, '§4.3');
  }
  const alg = opts.alg as SupportedAlg;

  // Resolve output path. Refuse to write a *.signed.json.signed.json by default.
  const inputPath = resolve(file);
  let outputPath: string;
  if (opts.out) {
    outputPath = resolve(opts.out);
  } else if (opts.inPlace) {
    outputPath = inputPath;
  } else if (/\.signed\.json$/.test(file)) {
    throw new LlmoError(
      `Refusing to write '${file}.signed.json'. Use --in-place to overwrite, or --out <path> to specify.`,
      '§4.3.3',
    );
  } else {
    outputPath = `${inputPath}.signed.json`;
  }

  // Read and parse JSON.
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch (cause) {
    throw new LlmoError(`Failed to parse ${inputPath} as JSON`, '§3.1', { cause });
  }

  // Validate against schema (allErrors so all are reported).
  const ok = validate(doc);
  if (!ok) {
    throw new SchemaError('document does not conform to the v0.1 schema', formatErrors(validate.errors));
  }

  // Read PEM key from disk.
  let pem: string;
  try {
    pem = readFileSync(resolve(opts.key), 'utf8');
  } catch (cause) {
    throw new LlmoError(`Failed to read private key from ${opts.key}`, '§4.2', { cause });
  }

  // Sign target: a specific claim (by claim_id) or the whole document.
  if (opts.claim) {
    if (!Array.isArray(doc.claims)) {
      throw new LlmoError(`document has no claims array; cannot sign claim '${opts.claim}'`, '§3.4');
    }
    const claims = doc.claims as Array<Record<string, unknown>>;
    const idx = claims.findIndex((c) => c.claim_id === opts.claim);
    if (idx === -1) {
      throw new LlmoError(`No claim found with claim_id='${opts.claim}'`, '§3.4');
    }
    const claim = claims[idx];
    delete claim.signature;
    const sig: DocumentSignature = await signFromPem({ target: claim, alg, kid: opts.kid, privateKeyPem: pem });
    claim.signature = sig;
  } else {
    delete doc.signature;
    const sig: DocumentSignature = await signFromPem({ target: doc, alg, kid: opts.kid, privateKeyPem: pem });
    doc.signature = sig;
  }

  // Always write a single trailing newline.
  writeFileSync(outputPath, JSON.stringify(doc, null, 2) + '\n');
  return outputPath;
}

function printError(e: unknown): void {
  if (e instanceof SchemaError) {
    process.stderr.write(`error (${e.section}): schema validation failed\n`);
    for (const issue of e.issues) {
      process.stderr.write(`  ${issue.path} (${issue.keyword}): ${issue.message}\n`);
    }
  } else if (e instanceof LlmoError) {
    process.stderr.write(`error (${e.section ?? 'general'}): ${e.message}\n`);
  } else {
    process.stderr.write(`error: ${(e as Error).message}\n`);
  }
}
