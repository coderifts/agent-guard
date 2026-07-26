/**
 * Post-build: write the per-directory package.json "type" markers so each dist tree is
 * unambiguously the right module system on EVERY supported Node (engines: >=18), independent of
 * Node's ESM syntax-detection (which only exists on Node >= 22.7):
 *
 *   dist/esm/package.json = {"type":"module"}     -> .js files under dist/esm are ES modules
 *   dist/cjs/package.json = {"type":"commonjs"}   -> .js files under dist/cjs are CommonJS
 *
 * The root package.json has no top-level "type", so without these markers Node 18/20 would treat
 * dist/esm/*.js as CommonJS and throw SyntaxError on `export`. Uses only node:fs — no deps.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const markers = [
  ['dist/esm', '{"type":"module"}'],
  ['dist/cjs', '{"type":"commonjs"}'],
];

for (const [dir, contents] of markers) {
  const abs = join(root, dir);
  mkdirSync(abs, { recursive: true });
  writeFileSync(join(abs, 'package.json'), contents + '\n');
  console.log(`wrote ${dir}/package.json ${contents}`);
}
