import { Command } from 'commander';
import { generateKeyPair, exportPKCS8, exportJWK, calculateJwkThumbprint, type KeyLike } from 'jose';
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { JwksError, LlmoError } from '../lib/errors.js';
import { SUPPORTED_ALGS, type SupportedAlg } from '../lib/jws.js';

interface KeygenOpts {
  alg: string;
  kid?: string;
  outDir: string;
  jwksPath: string;
}

interface JwksFile {
  keys: Array<Record<string, unknown>>;
}

export function keygenCommand(): Command {
  return new Command('keygen')
    .description('Generate a signing keypair and append the public JWK to a JWKS file')
    .option('--alg <alg>', 'signing algorithm: ES256, ES384, or EdDSA', 'ES256')
    .option('--kid <kid>', 'key identifier; if omitted, computed as RFC 7638 thumbprint of the public key')
    .option('--out-dir <dir>', 'directory to write the private key PEM file into', '.')
    .option('--jwks-path <path>', 'JWKS file to append to (created if missing)', './llmo-keys.json')
    .action(async (opts: KeygenOpts) => {
      try {
        await runKeygen(opts);
      } catch (e) {
        printError(e);
        process.exit(1);
      }
    });
}

export async function runKeygen(opts: KeygenOpts): Promise<{ kid: string; privatePath: string; jwksPath: string }> {
  if (!isSupportedAlg(opts.alg)) {
    throw new LlmoError(
      `Unsupported alg: ${opts.alg}. Allowed: ${SUPPORTED_ALGS.join(', ')} per §4.3 (with §4.2 key shape).`,
      '§4.3',
    );
  }
  const alg = opts.alg as SupportedAlg;

  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = await exportJWK(publicKey as KeyLike);
  const kid = opts.kid ?? (await calculateJwkThumbprint(publicJwk));

  publicJwk.alg = alg;
  publicJwk.use = 'sig';
  publicJwk.kid = kid;

  // Write private key PEM (mode 0600).
  const privatePem = await exportPKCS8(privateKey as KeyLike);
  const privatePath = resolve(opts.outDir, `llmo-private-${kid}.pem`);
  mkdirSync(dirname(privatePath), { recursive: true });
  writeFileSync(privatePath, privatePem);
  try {
    chmodSync(privatePath, 0o600);
  } catch (e) {
    if (process.platform === 'win32') {
      process.stderr.write(
        'warning: POSIX file permissions are not enforced on Windows; private key file mode could not be set to 0600.\n',
      );
    } else {
      throw new LlmoError(`Failed to set 0600 permissions on ${privatePath}: ${(e as Error).message}`, '§4.2', { cause: e });
    }
  }

  // Append (do not overwrite) to JWKS.
  const jwksPath = resolve(opts.jwksPath);
  let jwks: JwksFile;
  if (existsSync(jwksPath)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(jwksPath, 'utf8'));
    } catch (cause) {
      throw new JwksError(`Existing JWKS at ${jwksPath} is not valid JSON`, '§4.2', { cause });
    }
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !Array.isArray((parsed as { keys?: unknown }).keys)
    ) {
      throw new JwksError(`Existing JWKS at ${jwksPath} is malformed: missing 'keys' array`, '§4.2');
    }
    jwks = parsed as JwksFile;
    if (jwks.keys.some((k) => k.kid === kid)) {
      throw new JwksError(
        `Existing JWKS at ${jwksPath} already contains a key with kid='${kid}'. Pick a different --kid or remove the existing entry.`,
        '§4.2',
      );
    }
  } else {
    jwks = { keys: [] };
    mkdirSync(dirname(jwksPath), { recursive: true });
  }
  jwks.keys.push(publicJwk as unknown as Record<string, unknown>);
  writeFileSync(jwksPath, JSON.stringify(jwks, null, 2) + '\n');

  // Stdout in the order BUILD.md specifies.
  process.stdout.write(`Private key: ${privatePath}\n`);
  process.stdout.write('  MUST NOT be committed. Store in CI secret or KMS; rotate annually per §4.2.\n');
  process.stdout.write('\n');
  process.stdout.write(`JWKS: ${jwksPath}\n`);
  process.stdout.write(
    '  Deploy to https://<your-domain>/.well-known/llmo-keys.json with Cache-Control: max-age=86400 per §5.3.\n',
  );
  process.stdout.write('\n');
  process.stdout.write(`${kid}\n`);

  return { kid, privatePath, jwksPath };
}

function isSupportedAlg(s: string): s is SupportedAlg {
  return (SUPPORTED_ALGS as readonly string[]).includes(s);
}

function printError(e: unknown): void {
  if (e instanceof LlmoError) {
    process.stderr.write(`error (${e.section ?? 'general'}): ${e.message}\n`);
  } else {
    process.stderr.write(`error: ${(e as Error).message}\n`);
  }
}
