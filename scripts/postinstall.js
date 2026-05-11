#!/usr/bin/env node
// Postinstall: copy the bundled /llmo Claude Code skill from the npm
// package into ~/.claude/skills/llmo/ so that typing `/llmo` inside
// Claude Code triggers the publisher wizard without any extra setup.
//
// Hardening (v0.1.10, per the 2026-05-11 security review):
//   - cpSync runs with `dereference: false` + `verbatimSymlinks: false`,
//     and the source tree is walked pre-copy to reject any symlink in
//     `skill/`. This closes the class where a symlink shipped in the
//     vendored skill would dereference at install time and expose a
//     file from outside the install path.
//   - LLMO_SKILL_DIR is normalized via `resolve()` and asserted to be
//     under HOME (or the explicit LLMO_ALLOW_OUT_OF_HOME=1 escape
//     hatch for CI tests). Closes the class where a transitive
//     postinstall could set LLMO_SKILL_DIR to a privileged path and
//     redirect our writes there.
//   - Refuses to run under root unless LLMO_ALLOW_ROOT_INSTALL=1, so
//     `sudo npm install -g llmo` does not write skill files into the
//     root user's home directory by surprise. End users running
//     unprivileged installs are unaffected.
//
// Idempotent on subsequent installs (overwrites with the version that
// shipped with this CLI release). Non-fatal: any error is logged as a
// warning and the install proceeds.

import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, '..', 'skill');
const home = homedir();
const defaultTarget = resolve(home, '.claude', 'skills', 'llmo');

function normalizeAndConfine(raw) {
  const absolute = resolve(raw);
  if (absolute === defaultTarget) return absolute;
  const homePrefix = home.endsWith(sep) ? home : home + sep;
  if (absolute === home || absolute.startsWith(homePrefix)) return absolute;
  if (process.env.LLMO_ALLOW_OUT_OF_HOME === '1') return absolute;
  throw new Error(
    `LLMO_SKILL_DIR='${raw}' resolves to '${absolute}' which is not under HOME ('${home}'); ` +
    `set LLMO_ALLOW_OUT_OF_HOME=1 to override (intended only for CI test fixtures).`
  );
}

function rejectSymlinks(dir) {
  for (const entry of readdirSync(dir)) {
    const full = resolve(dir, entry);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) {
      throw new Error(`refusing to install: ${full} is a symlink (vendored skill must be regular files only)`);
    }
    if (st.isDirectory()) rejectSymlinks(full);
  }
}

try {
  if (!existsSync(source)) {
    // Skill files aren't bundled in this install (e.g. dev checkout
    // before `scripts/vendor.sh` ran). Quietly skip.
    process.exit(0);
  }

  const isRoot = typeof process.geteuid === 'function' && process.geteuid() === 0;
  if (isRoot && process.env.LLMO_ALLOW_ROOT_INSTALL !== '1') {
    console.warn(
      `llmo: refusing postinstall under root (uid 0); set LLMO_ALLOW_ROOT_INSTALL=1 to override. ` +
      `Skill files were NOT copied. To install the skill for a regular user later, run as that user: ` +
      `npm install -g llmo`
    );
    process.exit(0);
  }

  const target = process.env.LLMO_SKILL_DIR
    ? normalizeAndConfine(process.env.LLMO_SKILL_DIR)
    : defaultTarget;

  rejectSymlinks(source);

  mkdirSync(target, { recursive: true });
  cpSync(source, target, {
    recursive: true,
    dereference: false,
    verbatimSymlinks: false,
    errorOnExist: false,
    force: true,
  });

  console.log(`llmo: /llmo Claude Code skill installed at ${target}`);
  console.log(`llmo: open Claude Code and type /llmo to start the publish wizard.`);
} catch (err) {
  console.warn(`llmo: skill install skipped (${err && err.message ? err.message : err})`);
  process.exit(0);
}
