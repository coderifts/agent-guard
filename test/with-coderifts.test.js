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

  it('17. forceReadonly on explicit mutationClass emits force_readonly_ignored_explicit_mutation_class warning (tool stays guarded)', () => {
    // resolveClass returns on tool.mutationClass BEFORE forceReadonly is consulted, so the tool stays
    // mutating/guarded. The registry MUST warn so a break-glass request is not silently ignored.
    const explicitMutatorInForceReadonly = [
      { name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' },
    ];
    const r = withCodeRifts({
      tools: explicitMutatorInForceReadonly, client: STUB_CLIENT, operation: 'merge',
      requireCoverage: 'COMPLETE',
      registry: { forceReadonly: ['Edit'], failOnUnguardedMutator: false },
    });
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.ok(r.registry_report.guarded_mutators.includes('Edit'));
    assert.ok(
      r.registry_report.warnings.includes('force_readonly_ignored_explicit_mutation_class:Edit'),
      `expected ignored-forceReadonly warning, got ${JSON.stringify(r.registry_report.warnings)}`,
    );
    // Not a heuristic force-downgrade residual — tool was never made readonly.
    assert.ok(!r.composition_assurance.residuals.includes('composition_forced_readonly_on_heuristic_mutator'));
    assert.ok(r.composition_assurance.residuals.includes('composition_call_policy_incomplete'));
    assert.ok(r.composition_assurance.residuals.includes('composition_freshness_not_configured'));
    assert.equal(r.composition_assurance.freshness_resolver_wired, false);
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
  });
});

// ── Composition observation (onEvent + onSettledCall) ────────────────────────────────────────────
// Live calls need a client with preflightChangeSet + verifyReceipt (STUB_CLIENT is construction-only).
const {
  computeBodyHash,
  foldTableSettledCalls,
  guardedFractionAmongRoutes,
} = require('../dist/cjs/index.js');

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
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
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

describe('withCodeRifts — composition observation (onEvent + onSettledCall)', () => {
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

  it('b. GUARDED+RETURNED: onSettledCall fires once with non-optional outcome', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onSettledCall: (o) => { seen.push(o); },
    });
    await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].kind, 'settled_call');
    assert.equal(seen[0].route, 'GUARDED');
    assert.equal(seen[0].terminal, 'RETURNED');
    assert.equal(seen[0].toolName, 'edit_file');
    assert.ok(seen[0].outcome && typeof seen[0].outcome === 'object');
    assert.equal(typeof seen[0].outcome.executed, 'boolean');
    assert.equal('result' in seen[0], false, 'GUARDED+RETURNED must not use result field');
  });

  it('c. BLOCK is visible via onSettledCall GUARDED arm, NOT via a block-specific onEvent', async () => {
    const events = [];
    const seen = [];
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'SHOULD_NOT_RUN' }],
      client: mockClient({ preflight: () => response('STOP', 'BLOCK') }),
      operation: 'merge',
      onEvent: (e) => events.push(e),
      onSettledCall: (o) => { seen.push(o); },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].route, 'GUARDED');
    assert.equal(seen[0].terminal, 'RETURNED');
    assert.equal(seen[0].outcome.executed, false);
    assert.equal(seen[0].outcome.verdict.kind, 'BLOCK');
    assert.ok(!events.some((e) => e.type === 'execution_skipped'), 'execution_skipped must not fire');
    assert.ok(!events.some((e) => /block/i.test(e.type)), 'no block-named event type');
    assert.ok(!events.some((e) => e.type === 'execution_started'), 'BLOCK must not start the factory');
    assert.equal(hostOutcome.executed, false);
    assert.equal(hostOutcome.verdict.kind, 'BLOCK');
  });

  it('d. host return value is reference-identical to GUARDED+RETURNED observation outcome', async () => {
    let observed;
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onSettledCall: (o) => {
        if (o.route === 'GUARDED' && o.terminal === 'RETURNED') observed = o.outcome;
      },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.ok(observed, 'onSettledCall fired');
    assert.deepEqual(hostOutcome, observed);
    assert.equal(hostOutcome, observed);
  });

  it('e. onSettledCall that throws does not break the call', async () => {
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
      onSettledCall: () => { throw new Error('observer boom'); },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.ok(hostOutcome && typeof hostOutcome === 'object');
    assert.equal(typeof hostOutcome.executed, 'boolean');
  });

  it('f. onSettledCall rejected promise does not unhandle-reject or break the call', async () => {
    const unhandled = [];
    const onUR = (reason) => { unhandled.push(reason); };
    process.on('unhandledRejection', onUR);
    try {
      const r = withCodeRifts({
        tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
        client: mockClient(),
        operation: 'merge',
        onSettledCall: () => Promise.reject(new Error('async observer boom')),
      });
      const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
      await Promise.resolve();
      await Promise.resolve();
      assert.ok(hostOutcome && typeof hostOutcome.executed === 'boolean');
      assert.equal(unhandled.length, 0, `unexpected unhandledRejection(s): ${unhandled}`);
    } finally {
      process.off('unhandledRejection', onUR);
    }
  });

  it('g. PASSTHROUGH+RETURNED: readonly fires onSettledCall with result (not outcome)', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [
        { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read-ok' },
        { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
      ],
      client: mockClient(),
      operation: 'merge',
      onSettledCall: (o) => { seen.push(o); },
    });
    const read = r.tools.find((t) => t.name === 'read_file');
    assert.equal(read._coderifts.guarded, false);
    const readResult = await read.execute({});
    assert.equal(readResult, 'read-ok');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].kind, 'settled_call');
    assert.equal(seen[0].route, 'PASSTHROUGH');
    assert.equal(seen[0].terminal, 'RETURNED');
    assert.equal(seen[0].result, 'read-ok');
    assert.equal('outcome' in seen[0], false);
  });

  it('h. GUARDED factory throw is absorbed by guardToolCall → RETURNED with outcome.error (not Promise reject)', async () => {
    // Frozen guardToolCall catches factory throws and returns a GuardOutcome
    // (executionAttempted true, executed false). The composition therefore observes
    // GUARDED+RETURNED with a non-optional outcome — never invents a THREW arm for this path.
    const seen = [];
    const r = withCodeRifts({
      tools: [{
        name: 'edit_file',
        mutationClass: 'mutating',
        execute: async () => { throw new Error('factory boom'); },
      }],
      client: mockClient(),
      operation: 'merge',
      onSettledCall: (o) => { seen.push(o); },
    });
    const hostOutcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].kind, 'settled_call');
    assert.equal(seen[0].route, 'GUARDED');
    assert.equal(seen[0].terminal, 'RETURNED');
    assert.equal(seen[0].outcome.executed, false);
    assert.ok(seen[0].outcome.error, 'factory error is on the outcome');
    assert.equal(hostOutcome.executed, false);
    assert.equal(hostOutcome, seen[0].outcome);
  });

  it('h2. GUARDED+THREW arm is a valid SettledCallObservation (foldable; live factory throws are RETURNED)', () => {
    // guardToolCall absorbs factory throws into GuardOutcome (see h). THREW is for Promise
    // rejection of the guarded execute chain; live catch-path coverage is PASSTHROUGH/BYPASSED THREW.
    const threwObs = {
      kind: 'settled_call',
      route: 'GUARDED',
      terminal: 'THREW',
      toolName: 'edit_file',
      error: new Error('chain reject'),
    };
    const counts = foldTableSettledCalls([threwObs]);
    assert.equal(counts.GUARDED, 1);
    assert.equal(threwObs.terminal, 'THREW');
    assert.equal('outcome' in threwObs, false);
  });

  it('i. PASSTHROUGH+THREW: readonly throw is observed then rethrown', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [{
        name: 'read_file',
        mutationClass: 'readonly',
        execute: async () => { throw new Error('read boom'); },
      }],
      client: mockClient(),
      operation: 'merge',
      onSettledCall: (o) => { seen.push(o); },
    });
    await assert.rejects(
      () => r.tools.find((t) => t.name === 'read_file').execute({}),
      /read boom/,
    );
    assert.equal(seen.length, 1);
    assert.equal(seen[0].route, 'PASSTHROUGH');
    assert.equal(seen[0].terminal, 'THREW');
  });

  it('j. BYPASSED+RETURNED: forceReadonly heuristic mutator (failHard false) is route BYPASSED', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [{ name: 'edit_thing', execute: async () => 'raw-ok' }],
      client: mockClient(),
      operation: 'merge',
      registry: { forceReadonly: ['edit_thing'], failOnUnguardedMutator: false },
      onSettledCall: (o) => { seen.push(o); },
    });
    assert.equal(r.registry_report.coverage, 'BYPASSED');
    const t = r.tools.find((x) => x.name === 'edit_thing');
    assert.equal(t._coderifts.guarded, false);
    const out = await t.execute({});
    assert.equal(out, 'raw-ok');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].route, 'BYPASSED');
    assert.equal(seen[0].terminal, 'RETURNED');
    assert.equal(seen[0].result, 'raw-ok');
  });

  it('j2. BYPASSED+THREW: forceReadonly passthrough throw is observed then rethrown', async () => {
    const seen = [];
    const r = withCodeRifts({
      tools: [{
        name: 'edit_thing',
        execute: async () => { throw new Error('bypass boom'); },
      }],
      client: mockClient(),
      operation: 'merge',
      registry: { forceReadonly: ['edit_thing'], failOnUnguardedMutator: false },
      onSettledCall: (o) => { seen.push(o); },
    });
    await assert.rejects(
      () => r.tools.find((x) => x.name === 'edit_thing').execute({}),
      /bypass boom/,
    );
    assert.equal(seen.length, 1);
    assert.equal(seen[0].route, 'BYPASSED');
    assert.equal(seen[0].terminal, 'THREW');
  });

  it('k. zero settled calls: fold is zeros; fraction is absent (not zero)', () => {
    const counts = foldTableSettledCalls([]);
    assert.deepEqual(counts, { GUARDED: 0, PASSTHROUGH: 0, BYPASSED: 0 });
    const frac = guardedFractionAmongRoutes(counts);
    assert.equal(frac.kind, 'absent');
    assert.equal(frac.why, 'no_settled_calls');
    assert.equal('fraction' in frac, false);
  });

  it('l. one-route-only observation: fraction is absent (not a number) — partial data property', () => {
    const onlyGuarded = foldTableSettledCalls([
      {
        kind: 'settled_call', route: 'GUARDED', terminal: 'RETURNED',
        toolName: 'a', outcome: { executed: true, verdict: { kind: 'ALLOW' } },
      },
      {
        kind: 'settled_call', route: 'GUARDED', terminal: 'RETURNED',
        toolName: 'b', outcome: { executed: true, verdict: { kind: 'ALLOW' } },
      },
    ]);
    assert.equal(onlyGuarded.GUARDED, 2);
    assert.equal(onlyGuarded.PASSTHROUGH, 0);
    const frac = guardedFractionAmongRoutes(onlyGuarded);
    assert.equal(frac.kind, 'absent');
    assert.equal(frac.why, 'one_route_only');
    assert.equal(typeof frac.fraction, 'undefined');
    // Explicit: no helper may yield a number from one-sided data.
    assert.notEqual(frac.kind, 'present');
  });

  it('m. multi-route observation: fold counts and fraction present only when ≥2 routes seen', () => {
    const events = [
      {
        kind: 'settled_call', route: 'GUARDED', terminal: 'RETURNED',
        toolName: 'edit_file', outcome: { executed: true, verdict: { kind: 'ALLOW' } },
      },
      {
        kind: 'settled_call', route: 'PASSTHROUGH', terminal: 'RETURNED',
        toolName: 'read_file', result: 'ok',
      },
    ];
    const counts = foldTableSettledCalls(events);
    assert.deepEqual(counts, { GUARDED: 1, PASSTHROUGH: 1, BYPASSED: 0 });
    const frac = guardedFractionAmongRoutes(counts);
    assert.equal(frac.kind, 'present');
    assert.equal(frac.fraction, 0.5);
  });

  it('n. neither hook changes composition_assurance', () => {
    const r = withCodeRifts({
      tools: cleanMutators(),
      client: mockClient(),
      operation: 'merge',
      onEvent: () => {},
      onSettledCall: () => {},
    });
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(r.composition_assurance.residuals.includes('composition_call_policy_incomplete'));
  });
});

// ── S5 receipt carry-forward (composition cursor) ───────────────────────────────────────────────
// The composition holds a per-instance token cursor. It does NOT verify chain authenticity.
// Host previousReceipt always wins. Overlap refuses to advance (asserted, not just documented).

/**
 * Client that captures each preflight's previous_receipt and issues unique receipt tokens.
 * verifyReceipt is token-keyed so concurrent preflights do not cross-bind envelopes.
 * @param {{ tokens?: string[], decisions?: Array<'ALLOW'|'BLOCK'> }} [opts]
 */
function threadingClient(opts = {}) {
  const tokens = opts.tokens || ['TOK_A', 'TOK_B', 'TOK_C', 'TOK_D'];
  const decisions = opts.decisions || [];
  const captures = [];
  const envsByToken = new Map();
  let i = 0;
  return {
    captures,
    client: {
      async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet(req) {
        captures.push({ previous_receipt: req && req.previous_receipt });
        const decision = decisions[i] || 'ALLOW';
        const execution_action = decision === 'ALLOW' ? 'CONTINUE' : 'STOP';
        const token = tokens[i] || `TOK_${i}`;
        i += 1;
        const env = envelope(execution_action, decision);
        // Unique fingerprint per call so body-hash bind stays independent of token.
        env.fingerprint = 'sha256:' + String(i).padStart(64, '0');
        env.receipt = {
          token, format_version: 'crchain.v1', key_id: 'k', issued_at: 'x',
        };
        envsByToken.set(token, env);
        return { decision, execution_action, decision_result: env };
      },
      async verifyReceipt(tok) {
        const env = envsByToken.get(tok);
        return env ? boundVerify(env) : { valid: false, status: 'INVALID' };
      },
    },
  };
}

// envelope() helper above uses opts.noReceipt; extend token via opts for threading tests.
// Patch: envelope already accepts opts.fingerprint; receipt token is hardcoded 'tok'.
// threadingClient overwrites lastEnv.receipt after envelope() — good.

describe('withCodeRifts — S5 receipt carry-forward (composition cursor)', () => {
  it('1. second call receives first call receipt without host passing previousReceipt', async () => {
    const { client, captures } = threadingClient({ tokens: ['R1', 'R2'] });
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
    });
    assert.equal(r.receipt_thread.enabled, true);
    const tool = r.tools.find((t) => t.name === 'edit_file');
    const o1 = await tool.execute(CONTRACT_ARGS);
    assert.equal(o1.enforced, true);
    assert.equal(captures[0].previous_receipt, undefined, 'first call is a root');
    assert.equal(r.receipt_thread.lastToken(), 'R1');
    assert.equal(r.receipt_thread.lastSkipReason(), null);

    const o2 = await tool.execute(CONTRACT_ARGS);
    assert.equal(o2.enforced, true);
    assert.equal(captures[1].previous_receipt, 'R1', 'cursor threaded first receipt into second preflight');
    assert.equal(r.receipt_thread.lastToken(), 'R2');
  });

  it('2. explicit previousReceipt from the host overrides the cursor', async () => {
    const { client, captures } = threadingClient({ tokens: ['R1', 'R2'] });
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
      previousReceipt: 'HOST_PRIOR',
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    await tool.execute(CONTRACT_ARGS);
    assert.equal(captures[0].previous_receipt, 'HOST_PRIOR');
    // Cursor still advances from the outcome (composition remembers last enforced receipt).
    assert.equal(r.receipt_thread.lastToken(), 'R1');
    await tool.execute(CONTRACT_ARGS);
    // Host override still wins on the second call — not the cursor.
    assert.equal(captures[1].previous_receipt, 'HOST_PRIOR');
  });

  it('3. host getter override is re-read each call and wins over cursor', async () => {
    const { client, captures } = threadingClient({ tokens: ['R1', 'R2'] });
    let n = 0;
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
      previousReceipt: () => { n += 1; return n === 1 ? 'G1' : 'G2'; },
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    await tool.execute(CONTRACT_ARGS);
    await tool.execute(CONTRACT_ARGS);
    assert.equal(captures[0].previous_receipt, 'G1');
    assert.equal(captures[1].previous_receipt, 'G2');
    assert.equal(n, 2);
  });

  it('4. BLOCK does not advance the cursor', async () => {
    const { client, captures } = threadingClient({
      tokens: ['R1', 'R_BLOCK', 'R3'],
      decisions: ['ALLOW', 'BLOCK', 'ALLOW'],
    });
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    await tool.execute(CONTRACT_ARGS);
    assert.equal(r.receipt_thread.lastToken(), 'R1');

    const blocked = await tool.execute(CONTRACT_ARGS);
    assert.equal(blocked.executed, false);
    assert.equal(blocked.enforced, false);
    assert.equal(r.receipt_thread.lastToken(), 'R1', 'cursor stays at last enforced receipt');
    assert.equal(r.receipt_thread.lastSkipReason(), 'not_enforced');
    // Second preflight still saw R1 as previous (first advanced); third should still see R1.
    assert.equal(captures[1].previous_receipt, 'R1');

    await tool.execute(CONTRACT_ARGS);
    assert.equal(captures[2].previous_receipt, 'R1', 'BLOCK did not move the cursor');
    assert.equal(r.receipt_thread.lastToken(), 'R3');
  });

  it('5. unenforced path (ALLOW without verifiable receipt) does not advance', async () => {
    // Client returns ALLOW with a receipt token that FAILS verify → fail-closed, not enforced.
    let lastEnv = null;
    let n = 0;
    const captures = [];
    const client = {
      async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet(req) {
        captures.push({ previous_receipt: req && req.previous_receipt });
        n += 1;
        lastEnv = envelope('CONTINUE', 'ALLOW', { token: `U${n}` });
        lastEnv.fingerprint = 'sha256:' + String(n).padStart(64, '0');
        lastEnv.receipt = { token: `U${n}`, format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' };
        return { decision: 'ALLOW', execution_action: 'CONTINUE', decision_result: lastEnv };
      },
      async verifyReceipt() {
        return { valid: false, status: 'INVALID' }; // receipt not verified → not enforced
      },
    };
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    const o1 = await tool.execute(CONTRACT_ARGS);
    assert.equal(o1.enforced, false);
    assert.equal(r.receipt_thread.lastToken(), undefined);
    assert.equal(r.receipt_thread.lastSkipReason(), 'not_enforced');
    await tool.execute(CONTRACT_ARGS);
    assert.equal(captures[1].previous_receipt, undefined, 'no cursor to thread');
  });

  it('6. threadReceipts:false disables carry-forward (opt-out)', async () => {
    const { client, captures } = threadingClient({ tokens: ['R1', 'R2'] });
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
      threadReceipts: false,
    });
    assert.equal(r.receipt_thread.enabled, false);
    const tool = r.tools.find((t) => t.name === 'edit_file');
    await tool.execute(CONTRACT_ARGS);
    await tool.execute(CONTRACT_ARGS);
    assert.equal(captures[0].previous_receipt, undefined);
    assert.equal(captures[1].previous_receipt, undefined);
    assert.equal(r.receipt_thread.lastToken(), undefined);
  });

  it('7. concurrent overlap refuses to advance (asserted) — no last-write-wins chain', async () => {
    // Hold preflight until both calls are in flight, then release with distinct tokens.
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    let started = 0;
    const envsByToken = new Map();
    const captures = [];
    let seq = 0;
    const client = {
      async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet(req) {
        captures.push({ previous_receipt: req && req.previous_receipt });
        started += 1;
        if (started === 2) release();
        await gate;
        seq += 1;
        const token = seq === 1 ? 'OVERLAP_A' : (seq === 2 ? 'OVERLAP_B' : `AFTER_${seq}`);
        const env = envelope('CONTINUE', 'ALLOW');
        env.fingerprint = 'sha256:' + String(seq).padStart(64, '0');
        env.receipt = { token, format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' };
        envsByToken.set(token, env);
        return { decision: 'ALLOW', execution_action: 'CONTINUE', decision_result: env };
      },
      async verifyReceipt(tok) {
        const env = envsByToken.get(tok);
        return env ? boundVerify(env) : { valid: false, status: 'INVALID' };
      },
    };

    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
    });
    // Both concurrent calls start from empty cursor (root) — after they finish, cursor must
    // still be empty because overlap refused both advances.
    const tool = r.tools.find((t) => t.name === 'edit_file');
    const p1 = tool.execute(CONTRACT_ARGS);
    const p2 = tool.execute(CONTRACT_ARGS);
    const [o1, o2] = await Promise.all([p1, p2]);
    assert.equal(o1.enforced, true);
    assert.equal(o2.enforced, true);
    assert.equal(
      r.receipt_thread.lastToken(),
      undefined,
      'overlap must not advance the cursor to either concurrent receipt',
    );
    assert.equal(r.receipt_thread.lastSkipReason(), 'concurrent_overlap');

    // After overlap clears, a sequential call still sees no cursor (not OVERLAP_A/B).
    const o3 = await tool.execute(CONTRACT_ARGS);
    assert.equal(o3.enforced, true);
    assert.equal(captures[2].previous_receipt, undefined);
    assert.ok(r.receipt_thread.lastToken(), 'sequential call after overlap may advance');
  });

  it('8. sequential after seed: concurrent pair does not clobber a prior good cursor', async () => {
    let phase = 'seed';
    let release;
    let gate = Promise.resolve();
    let startedInPhase = 0;
    const envsByToken = new Map();
    let n = 0;
    const captures = [];
    const client = {
      async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet(req) {
        captures.push({ previous_receipt: req && req.previous_receipt, phase });
        n += 1;
        if (phase === 'overlap') {
          startedInPhase += 1;
          if (startedInPhase === 2) release();
          await gate;
        }
        const token = `T${n}`;
        const env = envelope('CONTINUE', 'ALLOW');
        env.fingerprint = 'sha256:' + String(n).padStart(64, '0');
        env.receipt = { token, format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' };
        envsByToken.set(token, env);
        return { decision: 'ALLOW', execution_action: 'CONTINUE', decision_result: env };
      },
      async verifyReceipt(tok) {
        const env = envsByToken.get(tok);
        return env ? boundVerify(env) : { valid: false, status: 'INVALID' };
      },
    };
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: 'merge',
    });
    const tool = r.tools.find((t) => t.name === 'edit_file');
    await tool.execute(CONTRACT_ARGS);
    assert.equal(r.receipt_thread.lastToken(), 'T1');

    phase = 'overlap';
    startedInPhase = 0;
    gate = new Promise((resolve) => { release = resolve; });
    await Promise.all([tool.execute(CONTRACT_ARGS), tool.execute(CONTRACT_ARGS)]);
    assert.equal(r.receipt_thread.lastToken(), 'T1', 'overlap must not clobber the prior sequential cursor');
    assert.equal(r.receipt_thread.lastSkipReason(), 'concurrent_overlap');

    phase = 'after';
    await tool.execute(CONTRACT_ARGS);
    // After overlap, sequential call still threads the PRE-OVERLAP cursor (T1), not T2/T3.
    const afterCap = captures.filter((c) => c.phase === 'after')[0];
    assert.equal(afterCap.previous_receipt, 'T1');
    assert.equal(r.receipt_thread.lastToken(), 'T4');
  });
});
