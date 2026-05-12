// `llmo register`: submit a Key Transparency entry per LIP-4.
//
// The registered entry is a compact JWS signed by the publisher's
// private key, with the public JWK inline in the protected header
// (RFC 7515 §4.1.3). The entry's payload binds the publisher's
// domain, kid, JWK thumbprint (SHA-384 per RFC 7638), the document
// URL, the document_id of the signed document, and the publisher's
// local observation timestamp.
//
// The registry validates the JWS server-side and returns a signed
// receipt JWS. The CLI writes the receipt to a local file.
//
// Spec: https://llmo.org/spec/lips/lip-0004/ and the implementer
// API contract at https://llmo.org/spec/v0.1/kt-registry-endpoints/.

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { CompactSign, calculateJwkThumbprint, importJWK, type JWK } from 'jose';
import { LlmoError } from '../lib/errors.js';

interface RegisterOpts {
  key: string;
  domain: string;
  docUrl?: string;
  docId: string;
  registry: string;
  out?: string;
}

interface Receipt {
  entry_id: number;
  log_position: number;
  appended_at: string;
  receipt: string;
}

const SUPPORTED_ALGS = new Set(['ES256', 'ES384', 'EdDSA']);
const ENTRY_TYP = 'llmo-kt-entry+jws';

export function registerCommand(): Command {
  return new Command('register')
    .description('Register the current signing key in the LLMO Key Transparency registry per LIP-4')
    .requiredOption('--key <path>', 'path to private JWK file (JSON with kty/crv/x/y/d/kid/alg fields)')
    .requiredOption('--domain <domain>', 'publisher primary_domain (e.g. example.com)')
    .requiredOption('--doc-id <id>', 'document_id of the current signed llmo.json')
    .option('--doc-url <url>', 'URL of the deployed llmo.json (default: https://<domain>/.well-known/llmo.json)')
    .option('--registry <url>', 'KT registry base URL', 'https://llmo.org/kt/v1')
    .option('--out <path>', 'write the receipt to this path (default: ./llmo-kt-receipt-<timestamp>.json)')
    .action(async (opts: RegisterOpts) => {
      try {
        const result = await runRegister(opts);
        process.stdout.write(`Registered.\n`);
        process.stdout.write(`  entry_id:     ${result.entry_id}\n`);
        process.stdout.write(`  log_position: ${result.log_position}\n`);
        process.stdout.write(`  appended_at:  ${result.appended_at}\n`);
        process.stdout.write(`  receipt:      ${result.outPath}\n`);
      } catch (err) {
        if (err instanceof LlmoError) {
          process.stderr.write(`llmo register: ${err.message}\n`);
        } else if (err instanceof Error) {
          process.stderr.write(`llmo register: ${err.message}\n`);
        } else {
          process.stderr.write(`llmo register: ${String(err)}\n`);
        }
        process.exitCode = 1;
      }
    });
}

export async function runRegister(opts: RegisterOpts): Promise<Receipt & { outPath: string }> {
  // 1. Read and validate the private JWK file.
  const privateJwk = readPrivateJwk(opts.key);

  const { kid, alg } = extractKidAndAlg(privateJwk);

  // 2. Derive the public JWK by stripping private parameters.
  const publicJwk = derivePublicJwk(privateJwk);

  // 3. Compute the SHA-384 JWK Thumbprint of the public key per
  //    RFC 7638 §3 (which permits any digest; LIP-4 §3.1 selects
  //    SHA-384 for ~128-bit post-quantum collision resistance).
  const jwk_thumbprint = await calculateJwkThumbprint(publicJwk, 'sha384');

  // 4. Build the entry payload.
  const domain = opts.domain.toLowerCase().trim();
  const docUrl = opts.docUrl ?? `https://${domain}/.well-known/llmo.json`;
  const observedAt = new Date().toISOString();
  const payload = {
    domain,
    kid,
    jwk_thumbprint,
    doc_url: docUrl,
    doc_id: opts.docId,
    observed_at: observedAt,
  };

  // 5. Sign the entry. The protected header carries the public JWK
  //    inline so the entry is self-contained (LIP-4 §3.2).
  const privateKey = await importJWK(privateJwk, alg);
  const compactJws = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({
      alg,
      kid,
      typ: ENTRY_TYP,
      jwk: publicJwk,
    })
    .sign(privateKey);

  // 6. POST to the registry.
  const registryBase = opts.registry.replace(/\/+$/, '');
  const endpoint = `${registryBase}/entries`;
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/jose+json' },
      body: compactJws,
    });
  } catch (err) {
    throw new LlmoError(`registry unreachable at ${endpoint}: ${(err as Error).message}`);
  }

  if (!response.ok) {
    const body = await response.text();
    throw new LlmoError(`registry returned ${response.status}: ${body}`);
  }

  const receipt = (await response.json()) as Receipt;

  // 7. Write the receipt to disk.
  const safeTimestamp = observedAt.replace(/[:.]/g, '-');
  const outPath = opts.out
    ? resolve(opts.out)
    : resolve(`./llmo-kt-receipt-${safeTimestamp}.json`);
  writeFileSync(outPath, JSON.stringify(receipt, null, 2) + '\n', 'utf8');

  return { ...receipt, outPath };
}

function readPrivateJwk(path: string): JWK {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    throw new LlmoError(`could not read private JWK at ${path}: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new LlmoError(`private JWK at ${path} is not valid JSON: ${(err as Error).message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new LlmoError(`private JWK at ${path} is not a JSON object`);
  }
  const jwk = parsed as JWK;
  if (typeof jwk.kty !== 'string') {
    throw new LlmoError(`private JWK at ${path} missing required member 'kty'`);
  }
  if (jwk.d === undefined) {
    throw new LlmoError(`JWK at ${path} has no 'd' field; this command requires a *private* JWK with private-key material. The file appears to be a public JWK.`);
  }
  return jwk;
}

function extractKidAndAlg(jwk: JWK): { kid: string; alg: 'ES256' | 'ES384' | 'EdDSA' } {
  if (typeof jwk.kid !== 'string' || jwk.kid.length === 0) {
    throw new LlmoError(`private JWK has no 'kid' field; assign one before registering`);
  }
  if (typeof jwk.alg !== 'string') {
    throw new LlmoError(`private JWK has no 'alg' field; expected ES256, ES384, or EdDSA`);
  }
  if (!SUPPORTED_ALGS.has(jwk.alg)) {
    throw new LlmoError(`unsupported alg '${jwk.alg}'; supported: ES256, ES384, EdDSA`);
  }
  return { kid: jwk.kid, alg: jwk.alg as 'ES256' | 'ES384' | 'EdDSA' };
}

function derivePublicJwk(privateJwk: JWK): JWK {
  // Build the public JWK by selectively copying public-key parameters
  // from the input. Per RFC 7515 §4.1.3, the JWK header carries only
  // the public key. Whitelist (not blacklist) so any future jose JWK
  // field cannot accidentally leak private material through this code.
  const publicJwk: JWK = { kty: privateJwk.kty };
  if (privateJwk.crv !== undefined) publicJwk.crv = privateJwk.crv;
  if (privateJwk.x !== undefined) publicJwk.x = privateJwk.x;
  if (privateJwk.y !== undefined) publicJwk.y = privateJwk.y;
  if (privateJwk.n !== undefined) publicJwk.n = privateJwk.n;
  if (privateJwk.e !== undefined) publicJwk.e = privateJwk.e;
  if (privateJwk.kid !== undefined) publicJwk.kid = privateJwk.kid;
  if (privateJwk.alg !== undefined) publicJwk.alg = privateJwk.alg;
  if (privateJwk.use !== undefined) publicJwk.use = privateJwk.use;
  if (privateJwk.key_ops !== undefined) publicJwk.key_ops = privateJwk.key_ops;
  return publicJwk;
}
