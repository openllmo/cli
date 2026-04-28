import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { validate, formatErrors } from '../src/lib/schema.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, 'fixtures');

function load(name: string): unknown {
  return JSON.parse(readFileSync(resolve(fixturesDir, name), 'utf8'));
}

describe('schema validation', () => {
  it('accepts unsigned-minimal.json', () => {
    const ok = validate(load('unsigned-minimal.json'));
    assert.ok(ok, `expected valid; errors: ${JSON.stringify(formatErrors(validate.errors))}`);
  });

  it('accepts unsigned-standard.json', () => {
    const ok = validate(load('unsigned-standard.json'));
    assert.ok(ok, `expected valid; errors: ${JSON.stringify(formatErrors(validate.errors))}`);
  });

  it('accepts signed-strict.json', () => {
    const ok = validate(load('signed-strict.json'));
    assert.ok(ok, `expected valid; errors: ${JSON.stringify(formatErrors(validate.errors))}`);
  });

  it('rejects empty object: reports all required fields missing', () => {
    const ok = validate({});
    assert.equal(ok, false);
    const issues = formatErrors(validate.errors);
    // Schema requires: llmo_version, entity, claims, valid_from, valid_until, document_id (six fields).
    const requiredKeyword = issues.filter((i) => i.keyword === 'required');
    assert.ok(requiredKeyword.length >= 5, `expected multiple required-field errors; got ${requiredKeyword.length}: ${JSON.stringify(issues)}`);
  });

  it('rejects wrong llmo_version constant', () => {
    const doc = {
      llmo_version: '0.2',
      entity: { name: 'X', primary_domain: 'x.example.com' },
      claims: [],
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: '2026-04-01T00:00:00Z',
      document_id: 'x',
    };
    const ok = validate(doc);
    assert.equal(ok, false);
    const issues = formatErrors(validate.errors);
    assert.ok(issues.some((i) => i.path === '/llmo_version'), `expected /llmo_version error; got ${JSON.stringify(issues)}`);
  });

  it('rejects malformed primary_domain that does not match the regex', () => {
    const doc = {
      llmo_version: '0.1',
      entity: { name: 'X', primary_domain: 'NOT A DOMAIN' },
      claims: [],
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: '2026-04-01T00:00:00Z',
      document_id: 'x',
    };
    const ok = validate(doc);
    assert.equal(ok, false);
    const issues = formatErrors(validate.errors);
    assert.ok(issues.some((i) => /primary_domain/.test(i.path) || /pattern/.test(i.keyword)));
  });

  it('rejects malformed valid_from (not a date-time)', () => {
    const doc = {
      llmo_version: '0.1',
      entity: { name: 'X', primary_domain: 'x.example.com' },
      claims: [],
      valid_from: 'tomorrow',
      valid_until: '2026-04-01T00:00:00Z',
      document_id: 'x',
    };
    const ok = validate(doc);
    assert.equal(ok, false);
  });

  it('formatErrors maps AJV errors into stable shape', () => {
    validate({});
    const issues = formatErrors(validate.errors);
    for (const i of issues) {
      assert.equal(typeof i.path, 'string');
      assert.equal(typeof i.message, 'string');
      assert.equal(typeof i.keyword, 'string');
    }
  });
});
