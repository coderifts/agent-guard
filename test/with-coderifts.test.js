'use strict';

/**
 * withCodeRifts (S1) acceptance — the additive orchestration layer above the frozen guardToolRegistry.
 *
 * Proves the two-scope separation: the registry's own report passes through UNTOUCHED (and may say
 * COMPLETE / inescapable_runtime:true), while the composition assurance is separately computed and is
 * deliberately narrower in S1 (PARTIAL, inescapable_runtime:false, residual call-policy-incomplete).
 * Also proves construction-time failure for a missing/empty operation and a missing client.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { withCodeRifts, guardToolRegistry } = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };            // stand-in CodeRifts client

const cleanMutators = () => [
  { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
  { name: 'write_config', mutationClass: 'mutating', execute: async () => 'wrote' },
];
const readonlyOnly = () => [
  { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read' },
  { name: 'list_dir', mutationClass: 'readonly', execute: async () => ['a'] },
];

describe('withCodeRifts (S1) — orchestration over the frozen registry', () => {
  it('1. clean mutating tool list: tools are returned protected; registry says inescapable_runtime true', () => {
    const r = withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: 'merge' });
    assert.equal(r.tools.length, 2);
    for (const t of r.tools) {
      assert.equal(typeof t.execute, 'function');
      assert.equal(t._coderifts.guarded, true);          // every mutator wrapped
    }
    assert.equal(r.registry_report.claim.inescapable_runtime, true);
    assert.equal(r.registry_report.coverage, 'COMPLETE');
  });

  it('2. SAME call: composition_assurance.inescapable_runtime is false AND residuals name the call-policy gap', () => {
    const r = withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: 'merge' });
    // Two scopes visible together: registry true, composition false — separately computed.
    assert.equal(r.registry_report.claim.inescapable_runtime, true);
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(
      r.composition_assurance.residuals.includes('composition_call_policy_incomplete'),
      `expected residual composition_call_policy_incomplete, got ${JSON.stringify(r.composition_assurance.residuals)}`,
    );
  });

  it('3. composition_assurance.coverage is PARTIAL — never COMPLETE even when the registry is COMPLETE', () => {
    const r = withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: 'merge' });
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.notEqual(r.composition_assurance.coverage, 'COMPLETE');
  });

  it('4. missing operation throws at construction (message names operation as required)', () => {
    assert.throws(
      () => withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT }),
      (err) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /`operation` is required/);
        return true;
      },
    );
  });

  it('5. empty-string operation throws the same way at construction', () => {
    assert.throws(
      () => withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: '   ' }),
      (err) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /`operation` is required/);
        return true;
      },
    );
  });

  it('6. missing client throws at construction, before any tool is invoked', () => {
    assert.throws(
      () => withCodeRifts({ tools: cleanMutators(), operation: 'merge' }),
      (err) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /`client` is required/);
        return true;
      },
    );
  });

  it('7. registry_report is passed through UNCHANGED (deep-equal vs a direct guardToolRegistry call)', () => {
    const tools = cleanMutators();
    const r = withCodeRifts({ tools, client: STUB_CLIENT, operation: 'merge' });
    const direct = guardToolRegistry(cleanMutators(), { guard: { client: STUB_CLIENT, operation: 'merge' } });
    assert.deepEqual(r.registry_report, direct.report);
  });

  it('8. readonly-only tool list still yields composition inescapable_runtime false (S1 never claims runtime inescapability)', () => {
    const r = withCodeRifts({ tools: readonlyOnly(), client: STUB_CLIENT, operation: 'tool_call' });
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.ok(r.composition_assurance.residuals.includes('composition_call_policy_incomplete'));
  });
});
