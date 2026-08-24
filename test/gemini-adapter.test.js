'use strict';

/**
 * ID632 slice 4 — Google Gemini function-calling adapter over withCodeRifts.
 *
 * Same proofs as OpenAI/Anthropic; target shape nests all tools under one
 * functionDeclarations array: tools: [ { functionDeclarations: [ … ] } ].
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const {
  withCodeRiftsGemini,
  geminiToolAdapter,
  toGeminiTools,
  protectedToolToFunctionDeclaration,
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

describe('withCodeRiftsGemini — thin Gemini adapter (ID632)', () => {
  it('1. returns Gemini functionDeclarations wrapper from raw tools + client + operation', () => {
    const r = withCodeRiftsGemini({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    assert.ok(Array.isArray(r.tools));
    // Single wrapper entry (not one {type:function} per tool).
    assert.equal(r.tools.length, 1);
    const wrap = r.tools[0];
    assert.ok(Array.isArray(wrap.functionDeclarations));
    assert.equal(wrap.functionDeclarations.length, 2);
    for (const d of wrap.functionDeclarations) {
      assert.equal(typeof d.name, 'string');
      assert.equal(typeof d.parameters, 'object');
      assert.ok(d.parameters !== null);
      // Not OpenAI shape
      assert.equal('type' in d, false);
      assert.equal('function' in d, false);
    }
    const edit = wrap.functionDeclarations.find((d) => d.name === 'edit_file');
    assert.ok(edit);
    assert.equal(edit.description, 'Edit a file');
    assert.equal(edit.parameters.type, 'object');
    assert.ok(edit.parameters.properties.path);
  });

  it('2. PROOF only-protected-tools: declaration names ⊆ protected_tools; no raw-only leakage', () => {
    const raw = rawTools();
    const r = withCodeRiftsGemini({ tools: raw, client: STUB_CLIENT, operation: 'merge' });
    const declNames = r.tools[0].functionDeclarations.map((d) => d.name).sort();
    const protectedNames = r.protected_tools.map((t) => t.name).sort();
    assert.deepEqual(declNames, protectedNames, 'Gemini declarations are exactly the protected set');
    for (const p of r.protected_tools) {
      assert.ok(p._coderifts, 'protected_tools carry _coderifts (guarded registry surface)');
      assert.equal(typeof p.execute, 'function');
    }
    for (const d of r.tools[0].functionDeclarations) {
      assert.equal('execute' in d, false);
      assert.equal('_coderifts' in d, false);
    }
  });

  it('3. PROOF assurance passed through unflattened (composition may still be incomplete)', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const r = withCodeRiftsGemini({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });

    assert.deepEqual(r.composition_assurance, core.composition_assurance);
    assert.deepEqual(r.registry_report, core.registry_report);
    assert.equal(typeof r.receipt_thread, 'object');
    assert.equal(typeof r.receipt_thread.enabled, 'boolean');
    assert.equal(typeof r.coverage_observed.snapshot, 'function');
    assert.equal(typeof r.coverage_observed.reportToolDispatch, 'function');
    assert.equal(r.composition_assurance.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');

    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(
      r.composition_assurance.residuals.includes('composition_call_policy_incomplete'),
      `expected composition_call_policy_incomplete residual, got ${JSON.stringify(r.composition_assurance.residuals)}`,
    );
  });

  it('4. geminiToolAdapter composition style matches withCodeRiftsGemini shape', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const viaAdapter = geminiToolAdapter(core);
    const viaOneShot = withCodeRiftsGemini({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    assert.deepEqual(viaAdapter.tools, viaOneShot.tools);
    assert.deepEqual(viaAdapter.composition_assurance, viaOneShot.composition_assurance);
    assert.deepEqual(viaAdapter.registry_report, viaOneShot.registry_report);
    assert.equal(viaAdapter.coverage_observed, core.coverage_observed);
  });

  it('5. protectedToolToFunctionDeclaration / toGeminiTools: empty schema when inputSchema missing', () => {
    const bare = {
      name: 'noop',
      execute: async () => null,
      _coderifts: { guarded: false, mutationClass: 'readonly' },
    };
    const decl = protectedToolToFunctionDeclaration(bare);
    assert.equal(decl.name, 'noop');
    assert.equal(decl.parameters.type, 'object');
    assert.deepEqual(decl.parameters.properties, {});
    const tools = toGeminiTools([bare]);
    assert.equal(tools.length, 1);
    assert.deepEqual(tools[0].functionDeclarations, [decl]);
  });

  it('5b. empty protected list → empty tools array (no empty functionDeclarations wrapper)', () => {
    assert.deepEqual(toGeminiTools([]), []);
  });

  it('6. missing operation still fails at construction (core rule, not reimplemented)', () => {
    assert.throws(
      () => withCodeRiftsGemini({ tools: rawTools(), client: STUB_CLIENT }),
      (err) => err instanceof Error && /operation/i.test(err.message),
    );
  });

  it('7. repository is carried through when supplied', () => {
    const r = withCodeRiftsGemini({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
      repository: 'acme/api',
    });
    assert.equal(r.repository, 'acme/api');
  });
});

describe('examples/gemini-adapter — offline demo', () => {
  it('example module exports Gemini tools + unflattened assurance', async () => {
    const url = pathToFileURL(path.join(__dirname, '..', 'examples', 'gemini-adapter.mjs')).href;
    const mod = await import(url);
    assert.ok(Array.isArray(mod.tools));
    assert.equal(mod.tools.length, 1);
    assert.ok(Array.isArray(mod.tools[0].functionDeclarations));
    assert.ok(mod.tools[0].functionDeclarations.length >= 1);
    assert.equal(typeof mod.tools[0].functionDeclarations[0].name, 'string');
    assert.ok(mod.composition_assurance);
    assert.equal(mod.composition_assurance.inescapable_runtime, false);
    assert.ok(Array.isArray(mod.protected_tools));
    assert.equal(
      mod.tools[0].functionDeclarations.length,
      mod.protected_tools.length,
    );
  });
});
