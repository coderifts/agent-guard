/**
 * Google Gemini function-calling adapter example (ID632 slice 4).
 *
 * NOT shipped in the npm tarball (see examples/README.md). Shows the 5–10 line
 * ergonomic: raw tools + client + operation → Gemini-ready tools (functionDeclarations
 * wrapper), without hand-wiring the registry. Same pattern as openai-adapter.mjs.
 *
 * Run offline (no network, no Gemini key):
 *   npm run build && node examples/gemini-adapter.mjs
 *   node --test test/gemini-adapter.test.js
 *
 * Honesty: composition_assurance is passed through as the core reports it
 * (may still have inescapable_runtime:false). The adapter converts tool SHAPE only.
 *
 * 6/D: only the guarded/protected tools appear under functionDeclarations. A host
 * that also registers raw tools outside that table is outside the adapter's protection.
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const distCjs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cjs');

const { withCodeRiftsGemini } = require(path.join(distCjs, 'index.js'));
if (typeof withCodeRiftsGemini !== 'function') {
  throw new Error('examples/gemini-adapter: build dist first (npm run build)');
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

// One call: raw tools + client + operation → Gemini tools + honest assurance.
const {
  tools,                 // Gemini: [ { functionDeclarations: [ { name, description?, parameters }, … ] } ]
  protected_tools,       // guarded executors for dispatch after functionCall
  registry_report,       // registry's own truth
  composition_assurance, // product-level (narrower) — do NOT flatten away
  receipt_thread,        // composition cursor — not product-truth chain evidence
} = withCodeRiftsGemini({
  tools: rawTools,
  client,
  operation: 'merge', // REQUIRED — no default
});

// Host would then: model.generateContent({ contents, tools })
// and dispatch functionCall via protected_tools by name (never re-register rawTools).

// ── Demo print (offline) ──────────────────────────────────────────────────────

function main() {
  console.log('Gemini tools (generateContent tools — functionDeclarations wrapper):');
  console.log(JSON.stringify(tools, null, 2));
  console.log('\ncomposition_assurance (untouched; may still be incomplete):');
  console.log(JSON.stringify(composition_assurance, null, 2));
  console.log('\nregistry_report.coverage:', registry_report.coverage);
  console.log('registry_report.claim.inescapable_runtime:', registry_report.claim.inescapable_runtime);
  console.log('composition_assurance.inescapable_runtime:', composition_assurance.inescapable_runtime);
  console.log('protected_tools names (guarded only):', protected_tools.map((t) => t.name));
  console.log('functionDeclarations count:', tools[0]?.functionDeclarations?.length);
  console.log('receipt_thread.enabled:', receipt_thread.enabled);
  console.log('\nOK — Gemini adapter shape only; assurance not upgraded.');
}

// Export for tests (same symbols the demo uses).
export {
  withCodeRiftsGemini,
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
