#!/usr/bin/env node
// Postinstall: copy the bundled /llmo Claude Code skill from the npm
// package into ~/.claude/skills/llmo/ so that typing `/llmo` inside
// Claude Code triggers the publisher wizard without any extra setup.
//
// Idempotent on subsequent installs (overwrites with the version that
// shipped with this CLI release). Non-fatal: any error is logged as a
// warning and the install proceeds. The target directory can be
// overridden via the LLMO_SKILL_DIR env var for testing.

import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, '..', 'skill');
const target = process.env.LLMO_SKILL_DIR || resolve(homedir(), '.claude', 'skills', 'llmo');

try {
  if (!existsSync(source)) {
    // Skill files aren't bundled in this install (e.g. dev checkout
    // before `scripts/vendor.sh` ran). Quietly skip.
    process.exit(0);
  }

  mkdirSync(target, { recursive: true });
  cpSync(source, target, { recursive: true });

  console.log(`llmo: /llmo Claude Code skill installed at ${target}`);
  console.log(`llmo: open Claude Code and type /llmo to start the publish wizard.`);
} catch (err) {
  console.warn(`llmo: skill install skipped (${err && err.message ? err.message : err})`);
  process.exit(0);
}
