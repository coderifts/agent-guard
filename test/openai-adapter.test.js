'use strict';

/**
 * ID632 slice 1 — OpenAI tool-calling adapter over withCodeRifts.
 *
 * Proofs:
 *  1. withCodeRiftsOpenAI calls the core (guarded tools + assurance present)
 *  2. OpenAI tool shape: { type:'function', function:{ name, description?, parameters } }
 *  3. ONLY protected tools in the OpenAI table (never raw-only names)
 *  4. composition_assurance / registry_report / receipt_thread passed through unflattened
 *  5. Example module loads and matches the same shape
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const {
  withCodeRiftsOpenAI,
  openAIToolAdapter,
  toOpenAITools,
  protectedToolToOpenAI,
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

describe('withCodeRiftsOpenAI — thin OpenAI adapter (ID632)', () => {
  it('1. returns OpenAI-shaped tools from raw tools + client + operation', () => {
    const r = withCodeRiftsOpenAI({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    assert.ok(Array.isArray(r.tools));
    assert.equal(r.tools.length, 2);
    for (const t of r.tools) {
      assert.equal(t.type, 'function');
      assert.equal(typeof t.function.name, 'string');
      assert.equal(typeof t.function.parameters, 'object');
      assert.ok(t.function.parameters !== null);
    }
    const edit = r.tools.find((t) => t.function.name === 'edit_file');
    assert.ok(edit);
    assert.equal(edit.function.description, 'Edit a file');
    assert.equal(edit.function.parameters.type, 'object');
    assert.ok(edit.function.parameters.properties.path);
  });

  it('2. PROOF only-protected-tools: OpenAI names ⊆ protected_tools; no raw-only leakage', () => {
    // Host holds a raw tool name that is NOT in the returned table when we pass only rawTools.
    const raw = rawTools();
    const r = withCodeRiftsOpenAI({ tools: raw, client: STUB_CLIENT, operation: 'merge' });
    const openaiNames = r.tools.map((t) => t.function.name).sort();
    const protectedNames = r.protected_tools.map((t) => t.name).sort();
    assert.deepEqual(openaiNames, protectedNames, 'OpenAI tools are exactly the protected set');
    // Every returned tool is from the frozen registry (has _coderifts).
    for (const p of r.protected_tools) {
      assert.ok(p._coderifts, 'protected_tools carry _coderifts (guarded registry surface)');
      assert.equal(typeof p.execute, 'function');
    }
    // OpenAI list does not embed execute / raw executors.
    for (const t of r.tools) {
      assert.equal('execute' in t, false);
      assert.equal('execute' in t.function, false);
      assert.equal('_coderifts' in t, false);
    }
  });

  it('3. PROOF assurance passed through unflattened (composition may still be incomplete)', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const r = withCodeRiftsOpenAI({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });

    // Same fields, same honesty as core — not flattened into a single "all green" claim.
    assert.deepEqual(r.composition_assurance, core.composition_assurance);
    assert.deepEqual(r.registry_report, core.registry_report);
    assert.equal(typeof r.receipt_thread, 'object');
    assert.equal(typeof r.receipt_thread.enabled, 'boolean');
    assert.equal(typeof r.coverage_observed.snapshot, 'function');
    assert.equal(typeof r.coverage_observed.reportToolDispatch, 'function');
    assert.equal(r.composition_assurance.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');

    // Product-level may still be incomplete while registry looks COMPLETE.
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(
      r.composition_assurance.residuals.includes('composition_call_policy_incomplete'),
      `expected composition_call_policy_incomplete residual, got ${JSON.stringify(r.composition_assurance.residuals)}`,
    );
  });

  it('4. openAIToolAdapter composition style matches withCodeRiftsOpenAI shape', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const viaAdapter = openAIToolAdapter(core);
    const viaOneShot = withCodeRiftsOpenAI({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    assert.deepEqual(viaAdapter.tools, viaOneShot.tools);
    assert.deepEqual(viaAdapter.composition_assurance, viaOneShot.composition_assurance);
    assert.deepEqual(viaAdapter.registry_report, viaOneShot.registry_report);
    assert.equal(viaAdapter.coverage_observed, core.coverage_observed);
  });

  it('5. protectedToolToOpenAI / toOpenAITools: empty schema when inputSchema missing', () => {
    const bare = {
      name: 'noop',
      execute: async () => null,
      _coderifts: { guarded: false, mutationClass: 'readonly' },
    };
    const oai = protectedToolToOpenAI(bare);
    assert.equal(oai.type, 'function');
    assert.equal(oai.function.name, 'noop');
    assert.equal(oai.function.parameters.type, 'object');
    assert.deepEqual(oai.function.parameters.properties, {});
    assert.deepEqual(toOpenAITools([bare]), [oai]);
  });

  it('6. missing operation still fails at construction (core rule, not reimplemented)', () => {
    assert.throws(
      () => withCodeRiftsOpenAI({ tools: rawTools(), client: STUB_CLIENT }),
      (err) => err instanceof Error && /operation/i.test(err.message),
    );
  });

  it('7. repository is carried through when supplied', () => {
    const r = withCodeRiftsOpenAI({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
      repository: 'acme/api',
    });
    assert.equal(r.repository, 'acme/api');
  });
});

describe('examples/openai-adapter — offline demo', () => {
  it('example module exports OpenAI tools + unflattened assurance', async () => {
    const url = pathToFileURL(path.join(__dirname, '..', 'examples', 'openai-adapter.mjs')).href;
    const mod = await import(url);
    assert.ok(Array.isArray(mod.tools));
    assert.ok(mod.tools.length >= 1);
    assert.equal(mod.tools[0].type, 'function');
    assert.ok(mod.composition_assurance);
    assert.equal(mod.composition_assurance.inescapable_runtime, false);
    assert.ok(Array.isArray(mod.protected_tools));
    // Only protected names — example raw list length matches protected (both registered).
    assert.equal(mod.tools.length, mod.protected_tools.length);
  });
});
