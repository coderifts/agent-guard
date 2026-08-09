/**
 * Anthropic tool_use adapter example (ID632 slice 2).
 *
 * NOT shipped in the npm tarball (see examples/README.md). Shows the 5–10 line
 * ergonomic: raw tools + client + operation → Anthropic-ready guarded tools, without
 * hand-wiring the registry. Same pattern as examples/openai-adapter.mjs.
 *
 * Run offline (no network, no Anthropic key):
 *   npm run build && node examples/anthropic-adapter.mjs
 *   node --test test/anthropic-adapter.test.js
 *
 * Honesty: composition_assurance is passed through as the core reports it
 * (may still have inescapable_runtime:false). The adapter converts tool SHAPE only.
 *
 * 6/D: only the guarded/protected tools appear in the Anthropic tools table. A host
 * that also registers raw tools outside that table is outside the adapter's protection.
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const distCjs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cjs');

const { withCodeRiftsAnthropic } = require(path.join(distCjs, 'index.js'));
if (typeof withCodeRiftsAnthropic !== 'function') {
  throw new Error('examples/anthropic-adapter: build dist first (npm run build)');
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

// One call: raw tools + client + operation → Anthropic tools + honest assurance.
const {
  tools,                 // Anthropic messages.create `tools` array
  protected_tools,       // guarded executors for dispatch after tool_use
  registry_report,       // registry's own truth
  composition_assurance, // product-level (narrower) — do NOT flatten away
  receipt_thread,        // composition cursor — not product-truth chain evidence
} = withCodeRiftsAnthropic({
  tools: rawTools,
  client,
  operation: 'merge', // REQUIRED — no default
});

// Host would then: anthropic.messages.create({ model, messages, tools, max_tokens })
// and dispatch tool_use blocks via protected_tools by name (never re-register rawTools).

// ── Demo print (offline) ──────────────────────────────────────────────────────

function main() {
  console.log('Anthropic tools (for messages.create):');
  console.log(JSON.stringify(tools, null, 2));
  console.log('\ncomposition_assurance (untouched; may still be incomplete):');
  console.log(JSON.stringify(composition_assurance, null, 2));
  console.log('\nregistry_report.coverage:', registry_report.coverage);
  console.log('registry_report.claim.inescapable_runtime:', registry_report.claim.inescapable_runtime);
  console.log('composition_assurance.inescapable_runtime:', composition_assurance.inescapable_runtime);
  console.log('protected_tools names (guarded only):', protected_tools.map((t) => t.name));
  console.log('receipt_thread.enabled:', receipt_thread.enabled);
  console.log('\nOK — Anthropic adapter shape only; assurance not upgraded.');
}

// Export for tests (same symbols the demo uses).
export {
  withCodeRiftsAnthropic,
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
  // Compare against process.argv[1] as file URL so `node examples/anthropic-adapter.mjs` runs main.
  const { pathToFileURL } = require('node:url');
  return process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : '';
}
