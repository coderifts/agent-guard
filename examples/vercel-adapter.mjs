/**
 * Vercel AI SDK tool adapter example (roadmap 129).
 *
 * NOT shipped in the npm tarball (see examples/README.md). Shows the 5–10 line
 * ergonomic: raw tools + client + operation → generateText tools record matching
 * v4 tool({ description, parameters, execute }) — WITHOUT importing `ai` in this
 * package (host owns the framework dependency).
 *
 * Run offline (no network, no `ai` install):
 *   npm run build && node examples/vercel-adapter.mjs
 *   node --test test/vercel-adapter.test.js
 *
 * Honesty: composition_assurance is passed through as the core reports it
 * (may still have inescapable_runtime:false). The adapter converts shape +
 * binds guarded execute only.
 *
 * 6/D: only the guarded/protected tools appear in the tools record. A host
 * that also registers raw tools outside that table is outside the adapter's protection.
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const distCjs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cjs');

const { withCodeRiftsVercel } = require(path.join(distCjs, 'index.js'));
if (typeof withCodeRiftsVercel !== 'function') {
  throw new Error('examples/vercel-adapter: build dist first (npm run build)');
}

// ── 5–10 line host wiring ─────────────────────────────────────────────────────

/** Stub client — real hosts pass the CodeRifts SDK client. */
const client = { preflight: async () => ({}) };

const rawTools = [
  {
    name: 'edit_file',
    description: 'Edit a file at path with old/new content',
    mutationClass: 'mutating',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        old_string: { type: 'string' },
        new_string: { type: 'string' },
      },
      required: ['path', 'old_string', 'new_string'],
    },
    execute: async () => 'edited',
  },
  {
    name: 'read_file',
    description: 'Read a file',
    mutationClass: 'readonly',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
    execute: async () => 'contents',
  },
];

// One call: raw tools + client + operation → Vercel tools record + honest assurance.
const {
  tools,                 // generateText tools record { [name]: { description?, parameters, execute } }
  protected_tools,       // guarded tools (same set)
  registry_report,       // registry's own truth
  composition_assurance, // product-level (narrower) — do NOT flatten away
  receipt_thread,        // composition cursor — not product-truth chain evidence
} = withCodeRiftsVercel({
  tools: rawTools,
  client,
  operation: 'merge', // REQUIRED — no default
});

// Host wires into Vercel AI SDK (HOST owns these imports — not this package):
//
//   import { generateText } from 'ai';
//   const result = await generateText({ model, tools, prompt });
//
// Never re-register rawTools into generateText — only `tools` / protected_tools.

// ── Demo print (offline, no `ai` package) ─────────────────────────────────────

function main() {
  console.log('Vercel AI SDK tools record (dependency-free plain objects):');
  for (const [name, t] of Object.entries(tools)) {
    console.log(JSON.stringify({
      name,
      description: t.description,
      parameters: t.parameters,
      execute: typeof t.execute,
    }, null, 2));
  }
  console.log('\ncomposition_assurance (untouched; may still be incomplete):');
  console.log(JSON.stringify(composition_assurance, null, 2));
  console.log('\nregistry_report.coverage:', registry_report.coverage);
  console.log('registry_report.claim.inescapable_runtime:', registry_report.claim.inescapable_runtime);
  console.log('composition_assurance.inescapable_runtime:', composition_assurance.inescapable_runtime);
  console.log('protected_tools names (guarded only):', protected_tools.map((t) => t.name));
  console.log('receipt_thread.enabled:', receipt_thread.enabled);
  console.log('\nOK — Vercel adapter descriptors only; no `ai` dependency; assurance not upgraded.');
}

// Export for tests (same symbols the demo uses).
export {
  withCodeRiftsVercel,
  client,
  rawTools,
  tools,
  protected_tools,
  registry_report,
  composition_assurance,
  receipt_thread,
  main,
};

if (import.meta.url === pathToFileURLIfMain()) {
  main();
}

function pathToFileURLIfMain() {
  const { pathToFileURL } = require('node:url');
  return process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : '';
}
