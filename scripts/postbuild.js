#!/usr/bin/env node
// Postbuild step: copies the vendored schema into dist/ so that the
// production schema loader at dist/lib/schema.js can reach it via
// '../schema/v0.1.json' (matching the dev path src/lib -> src/schema).
// Also chmods dist/cli.js to be executable. chmod is skipped on Windows
// where POSIX permissions are not enforced.

import { cpSync, chmodSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const src = resolve(root, 'src/schema');
const dest = resolve(root, 'dist/schema');
const cli = resolve(root, 'dist/cli.js');

cpSync(src, dest, { recursive: true });
console.log(`postbuild: copied ${src} -> ${dest}`);

if (existsSync(cli)) {
  try {
    chmodSync(cli, 0o755);
    console.log(`postbuild: chmod 0755 ${cli}`);
  } catch (e) {
    if (process.platform === 'win32') {
      console.warn(`postbuild: skipped chmod on Windows`);
    } else {
      throw e;
    }
  }
} else {
  console.warn(`postbuild: ${cli} not found; tsc may have failed or the entry point moved`);
  process.exit(1);
}
