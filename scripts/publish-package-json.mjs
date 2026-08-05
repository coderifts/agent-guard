#!/usr/bin/env node
/**
 * prepack / postpack helper: published package.json must not advertise
 * scripts that require files omitted by "files" (test/, tsconfig*.json, src/).
 *
 * npm does not support publishConfig.scripts — the published package.json is a
 * copy of the repo package.json unless rewritten at pack time.
 *
 * Usage:
 *   node scripts/publish-package-json.mjs strip   # prepack: write install-safe scripts
 *   node scripts/publish-package-json.mjs restore # postpack: restore from .bak
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkgPath = path.join(root, 'package.json');
const bakPath = path.join(root, 'package.json.publish-bak');

const mode = process.argv[2];
if (mode !== 'strip' && mode !== 'restore') {
  console.error('usage: node scripts/publish-package-json.mjs <strip|restore>');
  process.exit(2);
}

if (mode === 'restore') {
  if (!fs.existsSync(bakPath)) {
    console.error('publish-package-json: no package.json.publish-bak — nothing to restore');
    process.exit(1);
  }
  fs.copyFileSync(bakPath, pkgPath);
  fs.unlinkSync(bakPath);
  console.log('publish-package-json: restored package.json from publish-bak');
  process.exit(0);
}

// strip
const raw = fs.readFileSync(pkgPath, 'utf8');
fs.writeFileSync(bakPath, raw);
const pkg = JSON.parse(raw);

// Dev scripts stay in the repo (via restore). Published install only gets an
// honest message if someone runs npm test from node_modules.
pkg.scripts = {
  test:
    'node -e "console.error(\'@coderifts/agent-guard: tests and TypeScript configs are not shipped in the published package. Clone https://github.com/coderifts/agent-guard and run npm test from the repository.\'); process.exit(1)"',
};

fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
console.log('publish-package-json: stripped package.json for pack (dev scripts in publish-bak)');
