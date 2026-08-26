/**
 * ENFORCING_STRICT — opt-in fail-closed lock (guard@8.1).
 *
 * Construction aborts on any conflicting opt-down. Absent profile: today's defaults unchanged.
 * Honesty: calls_outside_guarded_path_invisible is named; inescapable_runtime stays false.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { withCodeRifts } = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };
const STUB_RESOLVER = async () => null;

const cleanMutators = () => [
  { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
  { name: 'write_config', mutationClass: 'mutating', execute: async () => 'wrote' },
];

function strictBase(extra = {}) {
  return {
    tools: cleanMutators(),
    client: STUB_CLIENT,
    operation: 'merge',
    profile: 'ENFORCING_STRICT',
    resolvePriorContent: STUB_RESOLVER,
    // 9.8.0: ENFORCING_STRICT now requires the execution chain. This fixture had no grant, which
    // is exactly the composition the auditor found building cleanly — updated deliberately, not
    // to make a red suite green.
    executionGrant: { enabled: true },
    ...extra,
  };
}

function assertWeakenAbort(extra, flag) {
  assert.throws(
    () => withCodeRifts(strictBase(extra)),
    (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /ENFORCING_STRICT cannot be weakened:/);
      assert.match(err.message, new RegExp(`${flag} conflicts`));
      return true;
    },
  );
}

describe('ENFORCING_STRICT — construction abort on weaken', () => {
  it('requireCoverage weaker than COMPLETE → abort', () => {
    assertWeakenAbort({ requireCoverage: 'PARTIAL' }, 'requireCoverage');
  });

  it('requireFreshness: false → abort', () => {
    assertWeakenAbort({ requireFreshness: false }, 'requireFreshness');
  });

  it('requireExecutionStateMatch: false → abort', () => {
    assertWeakenAbort({ requireExecutionStateMatch: false }, 'requireExecutionStateMatch');
  });

  it("requireExecutionStateMatch: 'warn' → abort", () => {
    assertWeakenAbort({ requireExecutionStateMatch: 'warn' }, 'requireExecutionStateMatch');
  });

  it('requireConditionalWrite: false → abort', () => {
    assertWeakenAbort({ requireConditionalWrite: false }, 'requireConditionalWrite');
  });

  it('requireCommitObservation: false → abort', () => {
    assertWeakenAbort({ requireCommitObservation: false }, 'requireCommitObservation');
  });

  it('failOnUnguardedMutator: false → abort', () => {
    assertWeakenAbort({ registry: { failOnUnguardedMutator: false } }, 'failOnUnguardedMutator');
  });

  it("unknownToolPolicy: 'readonly' → abort", () => {
    assertWeakenAbort({ registry: { unknownToolPolicy: 'readonly' } }, 'unknownToolPolicy');
  });

  it('missing resolvePriorContent → abort (construction-detectable)', () => {
    const { resolvePriorContent: _drop, ...noResolver } = strictBase();
    assert.throws(
      () => withCodeRifts(noResolver),
      (err) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /ENFORCING_STRICT cannot be weakened: resolvePriorContent conflicts/);
        return true;
      },
    );
  });
});

describe('ENFORCING_STRICT — clean table constructs and report is honest', () => {
  it('constructs; registry COMPLETE; composition names raw-path residual; inescapable stays false', () => {
    const r = withCodeRifts(strictBase());
    assert.equal(r.tools.length, 2);
    for (const t of r.tools) {
      assert.equal(t._coderifts.guarded, true);
    }
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.registry_report.unknown_treated_as, 'mutating');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(
      r.composition_assurance.residuals.includes('calls_outside_guarded_path_invisible'),
      `expected calls_outside_guarded_path_invisible, got ${JSON.stringify(r.composition_assurance.residuals)}`,
    );
    assert.ok(r.composition_assurance.residuals.includes('composition_call_policy_incomplete'));
    assert.equal(r.composition_assurance.freshness_resolver_wired, true);
  });

  it('absent profile still constructs without resolver (defaults unchanged)', () => {
    const r = withCodeRifts({ tools: cleanMutators(), client: STUB_CLIENT, operation: 'merge' });
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.ok(!r.composition_assurance.residuals.includes('calls_outside_guarded_path_invisible'));
    assert.ok(r.composition_assurance.residuals.includes('composition_freshness_not_configured'));
  });
});

describe('ENFORCING_STRICT — intentional weaken is RED (lock proof)', () => {
  it('deleting the abort (simulated): a weaken that is NOT aborted would construct — lock must throw', () => {
    // Positive: the lock fires. Negative proof: without profile the same weaken is legal.
    const weaken = {
      tools: cleanMutators(),
      client: STUB_CLIENT,
      operation: 'merge',
      requireFreshness: false,
      registry: { failOnUnguardedMutator: false, unknownToolPolicy: 'readonly' },
    };
    const open = withCodeRifts(weaken);
    assert.ok(open.tools.length >= 1);
    assert.throws(
      () => withCodeRifts({ ...weaken, profile: 'ENFORCING_STRICT', resolvePriorContent: STUB_RESOLVER }),
      /ENFORCING_STRICT cannot be weakened/,
    );
  });
});
