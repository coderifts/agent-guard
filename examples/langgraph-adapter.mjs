/**
 * LangChain / LangGraph tool adapter example (ID632 slice 3).
 *
 * NOT shipped in the npm tarball (see examples/README.md). Shows the 5–10 line
 * ergonomic: raw tools + client + operation → plain tool descriptors the host
 * can hand to LangChain tool() / LangGraph ToolNode — WITHOUT importing those
 * packages in this package (host owns the framework dependency).
 *
 * Run offline (no network, no langchain/langgraph install):
 *   npm run build && node examples/langgraph-adapter.mjs
 *   node --test test/langgraph-adapter.test.js
 *
 * Honesty: composition_assurance is passed through as the core reports it
 * (may still have inescapable_runtime:false). The adapter converts shape +
 * binds guarded execute only.
 *
 * 6/D: only the guarded/protected tools appear in the descriptor table. A host
 * that also registers raw tools outside that table is outside the adapter's protection.
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const distCjs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cjs');

const { withCodeRiftsLangGraph } = require(path.join(distCjs, 'index.js'));
if (typeof withCodeRiftsLangGraph !== 'function') {
  throw new Error('examples/langgraph-adapter: build dist first (npm run build)');
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

// One call: raw tools + client + operation → LangGraph descriptors + honest assurance.
const {
  tools,                 // plain descriptors { name, description?, schema, func, invoke }
  protected_tools,       // guarded tools (same set)
  registry_report,       // registry's own truth
  composition_assurance, // product-level (narrower) — do NOT flatten away
  receipt_thread,        // composition cursor — not product-truth chain evidence
} = withCodeRiftsLangGraph({
  tools: rawTools,
  client,
  operation: 'merge', // REQUIRED — no default
});

// Host wires into LangChain/LangGraph (HOST owns these imports — not this package):
//
//   import { tool } from '@langchain/core/tools';
//   import { ToolNode } from '@langchain/langgraph/prebuilt';
//   const lcTools = tools.map((d) =>
//     tool(d.func, { name: d.name, description: d.description, schema: d.schema }),
//   );
//   const toolNode = new ToolNode(lcTools);
//   // graph: StateGraph … .addNode('tools', toolNode) / llm.bindTools(lcTools)
//
// Never re-register rawTools into the graph — only `tools` / protected_tools.

// ── Demo print (offline, no framework packages) ───────────────────────────────

function main() {
  console.log('LangGraph/LangChain descriptors (dependency-free plain objects):');
  for (const d of tools) {
    console.log(JSON.stringify({
      name: d.name,
      description: d.description,
      schema: d.schema,
      func: typeof d.func,
      invoke: typeof d.invoke,
      same_func_and_invoke: d.func === d.invoke,
    }, null, 2));
  }
  console.log('\ncomposition_assurance (untouched; may still be incomplete):');
  console.log(JSON.stringify(composition_assurance, null, 2));
  console.log('\nregistry_report.coverage:', registry_report.coverage);
  console.log('registry_report.claim.inescapable_runtime:', registry_report.claim.inescapable_runtime);
  console.log('composition_assurance.inescapable_runtime:', composition_assurance.inescapable_runtime);
  console.log('protected_tools names (guarded only):', protected_tools.map((t) => t.name));
  console.log('receipt_thread.enabled:', receipt_thread.enabled);
  console.log('\nOK — LangGraph adapter descriptors only; no langchain dependency; assurance not upgraded.');
}

// Export for tests (same symbols the demo uses).
export {
  withCodeRiftsLangGraph,
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
