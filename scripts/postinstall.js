#!/usr/bin/env node
// Postinstall: copy the bundled /llmo skill from the npm package into the
// per-user skill directories of every supported agent so that typing `/llmo`
// inside the agent triggers the publisher wizard without any extra setup.
//
// Default targets (v0.1.14):
//   - ~/.claude/skills/llmo/   — Claude Code
//   - ~/.agents/skills/llmo/   — OpenAI Codex and GitHub Copilot (shared
//                                ~/.agents convention per their respective
//                                skill docs)
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
//   - LLMO_SKILL_DIR, when set, overrides BOTH defaults and writes to
//     a single target (preserves the legacy single-target test fixture
//     contract). To suppress writes to one default in production, set
//     LLMO_SKILL_DIR explicitly.
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
const claudeTarget = resolve(home, '.claude', 'skills', 'llmo');
const agentsTarget = resolve(home, '.agents', 'skills', 'llmo');
const defaultTargets = [
  { path: claudeTarget, label: 'Claude Code' },
  { path: agentsTarget, label: 'Codex, GitHub Copilot' },
];

function normalizeAndConfine(raw) {
  const absolute = resolve(raw);
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

function installTo(target) {
  mkdirSync(target, { recursive: true });
  cpSync(source, target, {
    recursive: true,
    dereference: false,
    verbatimSymlinks: false,
    errorOnExist: false,
    force: true,
  });
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

  rejectSymlinks(source);

  const targets = process.env.LLMO_SKILL_DIR
    ? [{ path: normalizeAndConfine(process.env.LLMO_SKILL_DIR), label: 'override' }]
    : defaultTargets;

  for (const { path, label } of targets) {
    installTo(path);
    console.log(`llmo: /llmo skill installed at ${path} (${label})`);
  }
  console.log(`llmo: open your agent (Claude Code, Codex, or GitHub Copilot) and type /llmo to start the publish wizard.`);
} catch (err) {
  console.warn(`llmo: skill install skipped (${err && err.message ? err.message : err})`);
  process.exit(0);
}
