'use strict';

/**
 * ID632 slice 3 — LangChain/LangGraph tool adapter over withCodeRifts.
 *
 * Same proofs as OpenAI/Anthropic; target shape is a dependency-free descriptor
 * { name, description?, schema, func, invoke } with guarded execute bound.
 *
 * Proofs:
 *  1. withCodeRiftsLangGraph calls the core (guarded tools + assurance present)
 *  2. Descriptor shape: name + schema + func/invoke (no hard langchain import)
 *  3. ONLY protected tools in the table (never raw-only names)
 *  4. composition_assurance / registry_report / receipt_thread passed through unflattened
 *  5. Example module loads and matches the same shape
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');

const {
  withCodeRiftsLangGraph,
  langGraphToolAdapter,
  toLangGraphTools,
  protectedToolToLangGraph,
  withCodeRifts,
} = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };

const rawTools = () => [
  {
    name: 'edit_file',
    description: 'Edit a file',
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
    },
    execute: async () => 'read',
  },
];

describe('withCodeRiftsLangGraph — thin LangGraph adapter (ID632)', () => {
  it('1. returns LangGraph-shaped descriptors from raw tools + client + operation', () => {
    const r = withCodeRiftsLangGraph({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    assert.ok(Array.isArray(r.tools));
    assert.equal(r.tools.length, 2);
    for (const t of r.tools) {
      assert.equal(typeof t.name, 'string');
      assert.equal(typeof t.schema, 'object');
      assert.ok(t.schema !== null);
      assert.equal(typeof t.func, 'function');
      assert.equal(typeof t.invoke, 'function');
      assert.equal(t.func, t.invoke, 'func and invoke are the same guarded execute');
      // Not OpenAI/Anthropic wrappers
      assert.equal('type' in t, false);
      assert.equal('function' in t, false);
      assert.equal('input_schema' in t, false);
      assert.equal('parameters' in t, false);
    }
    const edit = r.tools.find((t) => t.name === 'edit_file');
    assert.ok(edit);
    assert.equal(edit.description, 'Edit a file');
    assert.equal(edit.schema.type, 'object');
    assert.ok(edit.schema.properties.path);
  });

  it('2. PROOF only-protected-tools: descriptor names ⊆ protected_tools; no raw-only leakage', () => {
    const raw = rawTools();
    const r = withCodeRiftsLangGraph({ tools: raw, client: STUB_CLIENT, operation: 'merge' });
    const descNames = r.tools.map((t) => t.name).sort();
    const protectedNames = r.protected_tools.map((t) => t.name).sort();
    assert.deepEqual(descNames, protectedNames, 'LangGraph tools are exactly the protected set');
    for (const p of r.protected_tools) {
      assert.ok(p._coderifts, 'protected_tools carry _coderifts (guarded registry surface)');
      assert.equal(typeof p.execute, 'function');
    }
    // Descriptors do not embed raw _coderifts; they bind guarded func/invoke only.
    for (const t of r.tools) {
      assert.equal('_coderifts' in t, false);
    }
  });

  it('3. PROOF assurance passed through unflattened (composition may still be incomplete)', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const r = withCodeRiftsLangGraph({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });

    assert.deepEqual(r.composition_assurance, core.composition_assurance);
    assert.deepEqual(r.registry_report, core.registry_report);
    assert.equal(typeof r.receipt_thread, 'object');
    assert.equal(typeof r.receipt_thread.enabled, 'boolean');

    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(
      r.composition_assurance.residuals.includes('composition_call_policy_incomplete'),
      `expected composition_call_policy_incomplete residual, got ${JSON.stringify(r.composition_assurance.residuals)}`,
    );
  });

  it('4. langGraphToolAdapter composition style matches withCodeRiftsLangGraph shape', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const viaAdapter = langGraphToolAdapter(core);
    const viaOneShot = withCodeRiftsLangGraph({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    assert.deepEqual(
      viaAdapter.tools.map((t) => ({ name: t.name, description: t.description, schema: t.schema })),
      viaOneShot.tools.map((t) => ({ name: t.name, description: t.description, schema: t.schema })),
    );
    assert.deepEqual(viaAdapter.composition_assurance, viaOneShot.composition_assurance);
    assert.deepEqual(viaAdapter.registry_report, viaOneShot.registry_report);
  });

  it('5. protectedToolToLangGraph / toLangGraphTools: empty schema when inputSchema missing', () => {
    const bare = {
      name: 'noop',
      execute: async () => 'ok',
      _coderifts: { guarded: false, mutationClass: 'readonly' },
    };
    const d = protectedToolToLangGraph(bare);
    assert.equal(d.name, 'noop');
    assert.equal(d.schema.type, 'object');
    assert.deepEqual(d.schema.properties, {});
    assert.equal(typeof d.func, 'function');
    assert.equal(d.func, d.invoke);
    assert.deepEqual(toLangGraphTools([bare]).map((x) => x.name), ['noop']);
  });

  it('5b. func/invoke call the guarded execute (not a missing binding)', async () => {
    const r = withCodeRiftsLangGraph({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    const read = r.tools.find((t) => t.name === 'read_file');
    assert.ok(read);
    const out = await read.invoke({ path: 'x' });
    assert.equal(out, 'read');
    const out2 = await read.func({ path: 'x' });
    assert.equal(out2, 'read');
  });

  it('6. missing operation still fails at construction (core rule, not reimplemented)', () => {
    assert.throws(
      () => withCodeRiftsLangGraph({ tools: rawTools(), client: STUB_CLIENT }),
      (err) => err instanceof Error && /operation/i.test(err.message),
    );
  });

  it('7. repository is carried through when supplied', () => {
    const r = withCodeRiftsLangGraph({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
      repository: 'acme/api',
    });
    assert.equal(r.repository, 'acme/api');
  });

  it('8. PROOF no hard langchain/langgraph dependency in package or adapter source', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
    for (const name of Object.keys(deps || {})) {
      assert.ok(
        !/langchain|langgraph/i.test(name),
        `unexpected framework dep ${name} — adapter must stay dependency-free`,
      );
    }
    // Strip block comments so JSDoc host-wiring notes do not look like real imports.
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'adapters', 'langgraph.ts'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
    assert.doesNotMatch(src, /from\s+['"]@?langchain/);
    assert.doesNotMatch(src, /from\s+['"]langgraph/);
    assert.doesNotMatch(src, /require\s*\(\s*['"]@?langchain/);
    assert.doesNotMatch(src, /require\s*\(\s*['"]langgraph/);
  });
});

describe('examples/langgraph-adapter — offline demo', () => {
  it('example module exports descriptors + unflattened assurance', async () => {
    const url = pathToFileURL(path.join(__dirname, '..', 'examples', 'langgraph-adapter.mjs')).href;
    const mod = await import(url);
    assert.ok(Array.isArray(mod.tools));
    assert.ok(mod.tools.length >= 1);
    assert.equal(typeof mod.tools[0].name, 'string');
    assert.equal(typeof mod.tools[0].schema, 'object');
    assert.equal(typeof mod.tools[0].func, 'function');
    assert.equal(typeof mod.tools[0].invoke, 'function');
    assert.ok(mod.composition_assurance);
    assert.equal(mod.composition_assurance.inescapable_runtime, false);
    assert.ok(Array.isArray(mod.protected_tools));
    assert.equal(mod.tools.length, mod.protected_tools.length);
  });
});
