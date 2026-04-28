// AJV setup for JSON Schema draft 2020-12 validation of llmo.json
// documents against the vendored v0.1 schema.
//
// Decision: allErrors=true. Reason: BUILD.md sign-flow step 2 requires
// reporting all schema errors at once, not just the first.
//
// Decision: strict=true. Reason: catches schema drift early. The vendored
// schema is the only one this validator ever sees, and we want noisy
// failure if its shape changes in a way AJV does not recognize.
//
// Decision: validateFormats=true with ajv-formats. Reason: the schema
// uses date-time and uri formats; without ajv-formats those resolve to
// no-op assertions and silently let bad input through.

// ajv 8 and ajv-formats are CJS packages; under NodeNext + esModuleInterop the
// default-import shape isn't callable/constructable at the type level. Use the
// named export for Ajv2020, and a namespace + .default cast for ajv-formats.
import { Ajv2020 } from 'ajv/dist/2020.js';
import * as ajvFormatsNs from 'ajv-formats';

const addFormats = ajvFormatsNs.default as unknown as (ajv: Ajv2020) => Ajv2020;
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import type { ErrorObject, ValidateFunction } from 'ajv';
import { type SchemaIssue } from './errors.js';

const here = dirname(fileURLToPath(import.meta.url));
// The schema lives at src/schema/v0.1.json relative to source, and is
// copied into dist/schema/v0.1.json by the build script. In both layouts,
// the relative path from this file to the schema is "../schema/v0.1.json".
const schemaPath = resolve(here, '../schema/v0.1.json');

export const schema: object = JSON.parse(readFileSync(schemaPath, 'utf8'));

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: true,
});
addFormats(ajv);

export const validate: ValidateFunction = ajv.compile(schema);

export function formatErrors(errors: ErrorObject[] | null | undefined): SchemaIssue[] {
  if (!errors || errors.length === 0) return [];
  return errors.map((e) => ({
    path: e.instancePath || '/',
    message: e.message ?? 'unknown error',
    keyword: e.keyword,
  }));
}
