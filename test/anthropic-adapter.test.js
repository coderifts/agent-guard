'use strict';

/**
 * ID632 slice 2 — Anthropic tool_use adapter over withCodeRifts.
 *
 * Same proofs as the OpenAI adapter; only the target tool shape differs.
 *
 * Proofs:
 *  1. withCodeRiftsAnthropic calls the core (guarded tools + assurance present)
 *  2. Anthropic tool shape: { name, description?, input_schema }
 *  3. ONLY protected tools in the Anthropic table (never raw-only names)
 *  4. composition_assurance / registry_report / receipt_thread passed through unflattened
 *  5. Example module loads and matches the same shape
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const {
  withCodeRiftsAnthropic,
  anthropicToolAdapter,
  toAnthropicTools,
  protectedToolToAnthropic,
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

describe('withCodeRiftsAnthropic — thin Anthropic adapter (ID632)', () => {
  it('1. returns Anthropic-shaped tools from raw tools + client + operation', () => {
    const r = withCodeRiftsAnthropic({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    assert.ok(Array.isArray(r.tools));
    assert.equal(r.tools.length, 2);
    for (const t of r.tools) {
      assert.equal(typeof t.name, 'string');
      assert.equal(typeof t.input_schema, 'object');
      assert.ok(t.input_schema !== null);
      // Anthropic shape: no OpenAI-style type/function wrapper
      assert.equal('type' in t, false);
      assert.equal('function' in t, false);
      assert.equal('parameters' in t, false);
    }
    const edit = r.tools.find((t) => t.name === 'edit_file');
    assert.ok(edit);
    assert.equal(edit.description, 'Edit a file');
    assert.equal(edit.input_schema.type, 'object');
    assert.ok(edit.input_schema.properties.path);
  });

  it('2. PROOF only-protected-tools: Anthropic names ⊆ protected_tools; no raw-only leakage', () => {
    const raw = rawTools();
    const r = withCodeRiftsAnthropic({ tools: raw, client: STUB_CLIENT, operation: 'merge' });
    const anthropicNames = r.tools.map((t) => t.name).sort();
    const protectedNames = r.protected_tools.map((t) => t.name).sort();
    assert.deepEqual(anthropicNames, protectedNames, 'Anthropic tools are exactly the protected set');
    for (const p of r.protected_tools) {
      assert.ok(p._coderifts, 'protected_tools carry _coderifts (guarded registry surface)');
      assert.equal(typeof p.execute, 'function');
    }
    // Anthropic list does not embed execute / raw executors.
    for (const t of r.tools) {
      assert.equal('execute' in t, false);
      assert.equal('_coderifts' in t, false);
    }
  });

  it('3. PROOF assurance passed through unflattened (composition may still be incomplete)', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const r = withCodeRiftsAnthropic({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });

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

  it('4. anthropicToolAdapter composition style matches withCodeRiftsAnthropic shape', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const viaAdapter = anthropicToolAdapter(core);
    const viaOneShot = withCodeRiftsAnthropic({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    assert.deepEqual(viaAdapter.tools, viaOneShot.tools);
    assert.deepEqual(viaAdapter.composition_assurance, viaOneShot.composition_assurance);
    assert.deepEqual(viaAdapter.registry_report, viaOneShot.registry_report);
  });

  it('5. protectedToolToAnthropic / toAnthropicTools: empty schema when inputSchema missing', () => {
    const bare = {
      name: 'noop',
      execute: async () => null,
      _coderifts: { guarded: false, mutationClass: 'readonly' },
    };
    const anth = protectedToolToAnthropic(bare);
    assert.equal(anth.name, 'noop');
    assert.equal(anth.input_schema.type, 'object');
    assert.deepEqual(anth.input_schema.properties, {});
    assert.deepEqual(toAnthropicTools([bare]), [anth]);
  });

  it('6. missing operation still fails at construction (core rule, not reimplemented)', () => {
    assert.throws(
      () => withCodeRiftsAnthropic({ tools: rawTools(), client: STUB_CLIENT }),
      (err) => err instanceof Error && /operation/i.test(err.message),
    );
  });

  it('7. repository is carried through when supplied', () => {
    const r = withCodeRiftsAnthropic({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
      repository: 'acme/api',
    });
    assert.equal(r.repository, 'acme/api');
  });
});

describe('examples/anthropic-adapter — offline demo', () => {
  it('example module exports Anthropic tools + unflattened assurance', async () => {
    const url = pathToFileURL(path.join(__dirname, '..', 'examples', 'anthropic-adapter.mjs')).href;
    const mod = await import(url);
    assert.ok(Array.isArray(mod.tools));
    assert.ok(mod.tools.length >= 1);
    assert.equal(typeof mod.tools[0].name, 'string');
    assert.equal(typeof mod.tools[0].input_schema, 'object');
    assert.ok(mod.composition_assurance);
    assert.equal(mod.composition_assurance.inescapable_runtime, false);
    assert.ok(Array.isArray(mod.protected_tools));
    assert.equal(mod.tools.length, mod.protected_tools.length);
  });
});
