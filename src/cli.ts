#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { Command } from 'commander';
import { initCommand } from './commands/init.js';
import { keygenCommand } from './commands/keygen.js';
import { signCommand } from './commands/sign.js';
import { verifyCommand } from './commands/verify.js';
import { doctorCommand } from './commands/doctor.js';
import { registerCommand } from './commands/register.js';

// Single source of truth for the CLI version. package.json sits one level
// above this file in both layouts: src/cli.ts -> ../package.json (dev/test
// via tsx) and dist/cli.js -> ../package.json (published; npm always packs
// package.json at the package root). Matches the runtime-fs pattern used
// in src/lib/schema.ts for the vendored schema.
const here = dirname(fileURLToPath(import.meta.url));
const pkgPath = resolve(here, '../package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version: string };

const program = new Command();

program
  .name('llmo')
  .description('Reference CLI for the LLMO protocol. Sign and verify llmo.json documents per https://llmo.org/spec/v0.1')
  .version(pkg.version);

program.addCommand(initCommand());
program.addCommand(keygenCommand());
program.addCommand(signCommand());
program.addCommand(verifyCommand());
program.addCommand(doctorCommand());
program.addCommand(registerCommand());

await program.parseAsync(process.argv);
