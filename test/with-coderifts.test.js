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

const { withCodeRifts, guardToolRegistry, RegistryConstructionError } = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };            // stand-in CodeRifts client

const cleanMutators = () => [
  { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
  { name: 'write_config', mutationClass: 'mutating', execute: async () => 'wrote' },
];
const readonlyOnly = () => [
  { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read' },
  { name: 'list_dir', mutationClass: 'readonly', execute: async () => ['a'] },
];
// 'xyzzy' matches NO readonly/mutating heuristic substring and carries no mutationClass → unclassified.
// (Names like 'frobnicate' are a trap — it contains 'cat', a readonly heuristic, so it is NOT unclassified.)
const unclassifiedOnly = () => [{ name: 'xyzzy', execute: async () => 'x' }];
// 'edit_thing' matches the 'edit' heuristic → a heuristic mutator (used with forceReadonly).
const heuristicMutator = () => [{ name: 'edit_thing', execute: async () => 'x' }];

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

describe('withCodeRifts (S2) — startup honesty and classification defaults', () => {
  it('9. unclassified tool with no unknownToolPolicy is treated as MUTATING (asserted via the registry report)', () => {
    const r = withCodeRifts({ tools: unclassifiedOnly(), client: STUB_CLIENT, operation: 'tool_call' });
    // Default is 'mutating': the unclassified tool is guarded, not silently downgraded.
    assert.equal(r.registry_report.unknown_treated_as, 'mutating');
    assert.ok(r.registry_report.guarded_mutators.includes('xyzzy'));
    assert.ok(!r.registry_report.readonly_passthrough.includes('xyzzy'));
    // No unknown→readonly residual because nothing was downgraded.
    assert.ok(!r.composition_assurance.residuals.includes('composition_unknown_treated_as_readonly'));
  });

  it('10. explicit unknownToolPolicy:readonly on an unclassified tool records composition_unknown_treated_as_readonly', () => {
    const r = withCodeRifts({
      tools: unclassifiedOnly(), client: STUB_CLIENT, operation: 'tool_call',
      registry: { unknownToolPolicy: 'readonly' },
    });
    assert.equal(r.registry_report.unknown_treated_as, 'readonly');
    assert.ok(r.composition_assurance.residuals.includes('composition_unknown_treated_as_readonly'));
    // S1 semantics intact.
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
  });

  it('11. forceReadonly on a heuristic mutator under DEFAULT config: the registry FORCE_READONLY_MUTATOR error propagates unchanged', () => {
    assert.throws(
      () => withCodeRifts({
        tools: heuristicMutator(), client: STUB_CLIENT, operation: 'merge',
        registry: { forceReadonly: ['edit_thing'] },
      }),
      (err) => {
        // Not wrapped, not swallowed: the exact registry error surfaces.
        assert.ok(err instanceof RegistryConstructionError, `expected RegistryConstructionError, got ${err && err.name}`);
        assert.equal(err.code, 'FORCE_READONLY_MUTATOR');
        return true;
      },
    );
  });

  it('12. forceReadonly on a HEURISTIC mutator + failOnUnguardedMutator:false → registry BYPASSED + composition_forced_readonly_on_heuristic_mutator residual', () => {
    const r = withCodeRifts({
      tools: heuristicMutator(), client: STUB_CLIENT, operation: 'merge',
      registry: { forceReadonly: ['edit_thing'], failOnUnguardedMutator: false },
    });
    assert.equal(r.registry_report.coverage, 'BYPASSED');
    assert.ok(r.composition_assurance.residuals.includes('composition_forced_readonly_on_heuristic_mutator'));
    // S1 semantics intact even in the weakened case.
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
  });

  it('13. requireCoverage COMPLETE with a BYPASSED registry ABORTS (message names BYPASSED and COMPLETE) — by the ordering, not a special rule', () => {
    assert.throws(
      () => withCodeRifts({
        tools: heuristicMutator(), client: STUB_CLIENT, operation: 'merge',
        requireCoverage: 'COMPLETE',
        registry: { forceReadonly: ['edit_thing'], failOnUnguardedMutator: false },
      }),
      (err) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /requireCoverage not met/);
        assert.match(err.message, /BYPASSED/);
        assert.match(err.message, /COMPLETE/);
        // States plainly it is a registry-surface constraint, not a product guarantee.
        assert.match(err.message, /REGISTRY/);
        return true;
      },
    );
  });

  it('14. requireCoverage COMPLETE on a clean registry does NOT abort, and S1 composition semantics still hold', () => {
    const r = withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: 'merge', requireCoverage: 'COMPLETE' });
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
  });

  it('15. requireCoverage weaker than actual (PARTIAL required, COMPLETE actual) does not abort', () => {
    const r = withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: 'merge', requireCoverage: 'PARTIAL' });
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
  });

  it('16. multiple simultaneous problems produce ONE error listing ALL of them (missing operation AND missing client)', () => {
    let caught;
    try {
      withCodeRifts({ tools: cleanMutators() });   // no operation, no client
    } catch (e) {
      caught = e;
    }
    assert.ok(caught instanceof Error, 'expected a thrown Error');
    assert.match(caught.message, /`operation` is required/);
    assert.match(caught.message, /`client` is required/);
    // ONE error, both conditions listed together.
    assert.match(caught.message, /2 condition\(s\)/);
  });

  it('17. DOCUMENTED LIMITATION (frozen registry): forceReadonly is IGNORED for an explicit-mutationClass tool — COMPLETE, no residual, requireCoverage COMPLETE passes', () => {
    // resolveClass (tool-registry.ts:154-165) returns on tool.mutationClass at :157 BEFORE forceReadonly
    // is consulted at :158, so an explicitly-declared mutator listed in forceReadonly stays 'mutating'
    // and guarded — the forceReadonly is silently a no-op. The composition reads only the registry's
    // warnings, so it produces NO weakening residual here and CANNOT detect the ignored forceReadonly.
    // This is a property of the FROZEN registry, not the composition. If the registry ever changes so
    // that forceReadonly overrides an explicit mutationClass, THIS TEST FAILING is the signal that the
    // limitation is gone — which is what we want.
    const explicitMutatorInForceReadonly = [
      { name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' },
    ];
    const r = withCodeRifts({
      tools: explicitMutatorInForceReadonly, client: STUB_CLIENT, operation: 'merge',
      requireCoverage: 'COMPLETE',                       // passes: registry is COMPLETE, forceReadonly ignored
      registry: { forceReadonly: ['Edit'], failOnUnguardedMutator: false },
    });
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.ok(r.registry_report.guarded_mutators.includes('Edit'));
    assert.ok(!r.composition_assurance.residuals.includes('composition_forced_readonly_on_heuristic_mutator'));
    // The only residual is the S1 call-policy one; the ignored forceReadonly leaves no trace.
    assert.deepEqual(r.composition_assurance.residuals, ['composition_call_policy_incomplete']);
    // S1 semantics intact.
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
  });
});

// ── Composition observation (onEvent pass-through + onOutcome) ───────────────────────────────────
// Live calls need a client with preflightChangeSet + verifyReceipt (STUB_CLIENT is construction-only).
const { computeBodyHash } = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: 'dec_obs_1', correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint || ('sha256:' + 'a'.repeat(64)),
    input_fingerprint: 'sha256:' + 'b'.repeat(64),
    safe_for_agent: decision === 'ALLOW' || decision === 'WARN',
    analysis_complete: true,
    receipt: opts.noReceipt ? undefined : { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function response(execution_action, decision, opts) {
  return { decision, execution_action, decision_result: envelope(execution_action, decision, opts) };
}
function mockClient({ preflight } = {}) {
  let lastEnv = null;
  return {
    async preflightChangeSet() {
      const resp = preflight ? preflight() : response('CONTINUE', 'ALLOW');
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

/** Args that trigger preflight via defaultBinder (forwards args.artifacts). */
const CONTRACT_ARGS = {
  artifacts: [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0\npaths: {}\n', after: 'openapi: 3.0.0\npaths: {/x: {get: {}}}\n' }],
};

describe('withCodeRifts — composition observation (onEvent + onOutcome)', () => {
  it('a. onEvent reaches guardToolCall: a guarded call produces at least one event', async () => {
    const events = [];
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onEvent: (e) => events.push(e),
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    assert.ok(tool && tool._coderifts.guarded);
    await tool.execute(CONTRACT_ARGS);
    assert.ok(events.length >= 1, `expected at least one onEvent, got ${events.length}`);
  });

  it('b. onOutcome fires once per guarded call with correct toolName and outcome object', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onOutcome: (o) => { seen.push(o); },
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    await tool.execute(CONTRACT_ARGS);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].toolName, 'edit_file');
    assert.ok(seen[0].outcome && typeof seen[0].outcome === 'object');
    assert.equal(typeof seen[0].outcome.executed, 'boolean');
  });

  it('c. BLOCK is visible via onOutcome, NOT via a block-specific onEvent (why both hooks exist)', async () => {
    // Frozen emit() has no dedicated BLOCK/REQUIRE_APPROVAL event after preflight_result — those
    // outcomes are quiet on onEvent. onOutcome is the composition surface that sees them. This test
    // documents why both hooks exist: either alone is incomplete telemetry.
    const events = [];
    const seen = [];
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'SHOULD_NOT_RUN' }],
      client: mockClient({ preflight: () => response('STOP', 'BLOCK') }),
      operation: 'merge',
      onEvent: (e) => events.push(e),
      onOutcome: (o) => { seen.push(o); },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].outcome.executed, false);
    assert.equal(seen[0].outcome.verdict.kind, 'BLOCK');
    // No block-specific event type exists on the frozen surface (and execution_skipped never fires).
    assert.ok(!events.some((e) => e.type === 'execution_skipped'), 'execution_skipped must not fire');
    assert.ok(!events.some((e) => /block/i.test(e.type)), 'no block-named event type');
    assert.ok(!events.some((e) => e.type === 'execution_started'), 'BLOCK must not start the factory');
    // Host sees the same blocked outcome (also covers deep equality path for blocked returns).
    assert.equal(hostOutcome.executed, false);
    assert.equal(hostOutcome.verdict.kind, 'BLOCK');
  });

  it('d. host return value is unchanged by observation (deep-equal to what onOutcome saw)', async () => {
    let observed;
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onOutcome: (o) => { observed = o.outcome; },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.ok(observed, 'onOutcome fired');
    assert.deepEqual(hostOutcome, observed);
    // Reference identity: host receives the same object observation saw (not a clone).
    assert.equal(hostOutcome, observed);
  });

  it('e. onOutcome that throws does not break the call — host still receives the outcome', async () => {
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onOutcome: () => { throw new Error('observer boom'); },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.ok(hostOutcome && typeof hostOutcome === 'object');
    assert.equal(typeof hostOutcome.executed, 'boolean');
  });

  it('f. onOutcome that returns a rejected promise does not unhandle-reject and does not break the call', async () => {
    const unhandled = [];
    const onUR = (reason) => { unhandled.push(reason); };
    process.on('unhandledRejection', onUR);
    try {
      const r = withCodeRifts({
        tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
        client: mockClient(),
        operation: 'merge',
        onOutcome: () => Promise.reject(new Error('async observer boom')),
      });
      const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
      // Allow microtasks from the swallowed rejection path to settle.
      await Promise.resolve();
      await Promise.resolve();
      assert.ok(hostOutcome && typeof hostOutcome.executed === 'boolean');
      assert.equal(unhandled.length, 0, `unexpected unhandledRejection(s): ${unhandled}`);
    } finally {
      process.off('unhandledRejection', onUR);
    }
  });

  it('g. readonly passthrough tool does not fire onOutcome', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [
        { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read-ok' },
        { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
      ],
      client: mockClient(),
      operation: 'merge',
      onOutcome: (o) => { seen.push(o.toolName); },
    });
    const read = r.tools.find((t) => t.name === 'read_file');
    assert.equal(read._coderifts.guarded, false);
    const readResult = await read.execute({});
    assert.equal(readResult, 'read-ok');
    assert.deepEqual(seen, [], 'readonly must not fire onOutcome');
  });

  it('h. neither hook changes composition_assurance (PARTIAL, inescapable false, residual present)', () => {
    const r = withCodeRifts({
      tools: cleanMutators(),
      client: mockClient(),
      operation: 'merge',
      onEvent: () => {},
      onOutcome: () => {},
    });
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(r.composition_assurance.residuals.includes('composition_call_policy_incomplete'));
  });
});
