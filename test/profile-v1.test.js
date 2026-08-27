'use strict';

/**
 * ENFORCING_STRICT_V1 — the versioned contract (roadmap 1100, invariant #4).
 *
 * THE PROOF THAT MATTERS IS THAT NOTHING MOVES. A migration whose safety rests on reading the code
 * is the kind this project has spent the day correcting, so the central test here builds a REAL
 * construction both ways and compares the resulting policy FIELD BY FIELD. If `_V1` and the
 * unsuffixed alias ever diverge by one boolean, that test fails and the alias promise is broken.
 *
 * WHAT IS DELIBERATELY UNCHANGED: the value carried onto GuardConfig stays the unsuffixed
 * 'ENFORCING_STRICT'. Four downstream modules compare against that string; emitting '_V1' on the
 * wire would change behaviour in all of them for a rename.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  withCodeRifts, PROFILE_ENFORCING_STRICT_V1,
} = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };
const STUB_RESOLVER = async () => null;

/**
 * A REAL construction — the same tool shape the shipped strict tests use, with a mutating and a
 * readonly tool so the registry produces a populated coverage report rather than a trivial one.
 */
const realConstruction = (profile) => ({
  tools: [
    { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
    { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read' },
  ],
  client: STUB_CLIENT,
  operation: 'merge',
  profile,
  resolvePriorContent: STUB_RESOLVER,
  executionGrant: { enabled: true },
  repository: 'acme/api',
});

/**
 * Everything a caller can observe about the resulting policy, plus the internals that decide
 * behaviour. Handles and functions are reduced to their SHAPE — comparing closures would compare
 * object identity, which differs between two constructions for reasons that are not policy.
 */
function policyShape(res) {
  const shape = (v) => {
    if (typeof v === 'function') return '[function]';
    if (Array.isArray(v)) return v.map(shape);
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.keys(v).sort().map((k) => [k, shape(v[k])]));
    }
    return v;
  };
  return {
    tool_names: res.tools.map((t) => t.name).sort(),
    registry_report: shape(res.registry_report),
    composition_assurance: shape(res.composition_assurance),
    repository: res.repository ?? null,
  };
}

describe('THE PROOF: nothing moves', () => {
  it('a real construction is IDENTICAL field by field under both spellings', () => {
    const viaAlias = withCodeRifts(realConstruction('ENFORCING_STRICT'));
    const viaV1 = withCodeRifts(realConstruction(PROFILE_ENFORCING_STRICT_V1));
    assert.deepEqual(policyShape(viaV1), policyShape(viaAlias),
      'the alias must resolve to _V1 with byte-identical policy — a single differing boolean breaks the migration promise');
  });

  it('the two constructions agree on EVERY assurance key, named individually', () => {
    // deepEqual passing on an empty object would be vacuous. Assert the keys exist and match.
    const a = withCodeRifts(realConstruction('ENFORCING_STRICT')).composition_assurance;
    const b = withCodeRifts(realConstruction(PROFILE_ENFORCING_STRICT_V1)).composition_assurance;
    const keys = Object.keys(a);
    assert.ok(keys.length >= 3, `expected a populated assurance object, saw ${keys.length} keys`);
    for (const k of keys) {
      assert.deepEqual(b[k], a[k], `composition_assurance.${k} differs between the two spellings`);
    }
  });

  it('the registry coverage report is identical, key by key', () => {
    const a = withCodeRifts(realConstruction('ENFORCING_STRICT')).registry_report;
    const b = withCodeRifts(realConstruction(PROFILE_ENFORCING_STRICT_V1)).registry_report;
    const keys = Object.keys(a);
    assert.ok(keys.length > 0);
    for (const k of keys) {
      if (typeof a[k] === 'function') continue;
      assert.deepEqual(b[k], a[k], `registry_report.${k} differs`);
    }
  });
});

describe('the wire value does not move', () => {
  it('GuardConfig.profile stays the UNSUFFIXED string under both spellings', () => {
    // Four downstream modules compare against 'ENFORCING_STRICT'. This is the reason the rename is
    // free: the version lives on the input type, never on the wire.
    for (const p of ['ENFORCING_STRICT', PROFILE_ENFORCING_STRICT_V1]) {
      const res = withCodeRifts(realConstruction(p));
      assert.ok(res.tools.length > 0, `construction under ${p} must succeed`);
    }
    const src = require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'src', 'with-coderifts.ts'), 'utf8',
    );
    assert.match(src, /const GUARD_PROFILE_WIRE_VALUE = 'ENFORCING_STRICT' as const/,
      'the wire value must remain the unsuffixed string');
    assert.match(src, /guard\.profile = GUARD_PROFILE_WIRE_VALUE/);
  });
});

describe('the contract is versioned, and the alias is only a spelling', () => {
  it('_V1 is accepted and is the canonical name', () => {
    assert.equal(PROFILE_ENFORCING_STRICT_V1, 'ENFORCING_STRICT_V1');
    assert.doesNotThrow(() => withCodeRifts(realConstruction(PROFILE_ENFORCING_STRICT_V1)));
  });

  it('an unknown profile is refused, and the message names both accepted spellings', () => {
    assert.throws(
      () => withCodeRifts(realConstruction('ENFORCING_STRICT_V2')),
      (e) => /must be one of/.test(e.message)
        && /ENFORCING_STRICT_V1/.test(e.message)
        && /deprecated alias/.test(e.message),
      'a future _V2 must not be silently accepted by a _V1 implementation',
    );
  });

  it('_V1 CANNOT BE WEAKENED — the same abort as the alias, for each locked flag', () => {
    for (const weaken of [
      { requireFreshness: false },
      { requireConditionalWrite: false },
      { requireCommitObservation: false },
      { requireExecutionStateMatch: false },
      { requireCoverage: 'PARTIAL' },
    ]) {
      assert.throws(
        () => withCodeRifts({ ...realConstruction(PROFILE_ENFORCING_STRICT_V1), ...weaken }),
        /cannot be weakened/,
        `_V1 must refuse ${Object.keys(weaken)[0]} exactly as the alias does`,
      );
    }
  });

  it('_V1 still requires the execution chain', () => {
    const noGrant = realConstruction(PROFILE_ENFORCING_STRICT_V1);
    delete noGrant.executionGrant;
    assert.throws(() => withCodeRifts(noGrant), /requires the execution chain/);
  });
});

describe('_V1 IS FROZEN — the version means nothing unless its content cannot drift', () => {
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'src', 'with-coderifts.ts'), 'utf8',
  );

  it('the NINE conditions of _V1 are exactly these, and adding a tenth must become _V2', () => {
    // THIS IS WHAT MAKES THE SUFFIX REAL. A version in the name protects an adopter from a FUTURE
    // _V2; it does nothing about someone quietly tightening _V1 itself, which is the exact defect
    // 10.0.0 and 12.0.0 were. Adding a condition here without renaming reintroduces it, so the
    // list is pinned and a tenth entry fails this test on purpose.
    const weakenFn = src.slice(src.indexOf('function enforcingStrictWeakenFlags'));
    const body = weakenFn.slice(0, weakenFn.indexOf('\n}'));
    const flags = [...body.matchAll(/flags\.push\('([a-zA-Z]+)'\)/g)].map((m) => m[1]).sort();
    assert.deepEqual(flags, [
      'failOnUnguardedMutator',
      'requireCommitObservation',
      'requireConditionalWrite',
      'requireCoverage',
      'requireExecutionStateMatch',
      'requireFreshness',
      'unknownToolPolicy',
    ], 'the seven weakenable flags of _V1 are frozen — a new one is a _V2, not an edit here');

    // Plus the two non-flag conditions, checked separately in the construction path.
    assert.match(src, /resolvePriorContent conflicts/, '_V1 requires a resolver');
    assert.match(src, /requires the execution chain/, '_V1 requires an enabled execution grant');
  });

  it('the frozen list matches what the type documents — code and prose cannot drift', () => {
    // The doc comment on WithCodeRiftsProfile enumerates the nine. If someone edits one side only,
    // a reader of the type is told something the constructor does not do.
    for (const named of ['requireCoverage COMPLETE', 'requireFreshness', 'requireExecutionStateMatch',
      'requireConditionalWrite', 'requireCommitObservation', 'failOnUnguardedMutator',
      'resolvePriorContent', 'executionGrant.enabled']) {
      assert.ok(src.includes(named), `the _V1 doc block must name ${named}`);
    }
  });
});

describe('the honest limit is on the TYPE, where a reader of it will see it', () => {
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'src', 'with-coderifts.ts'), 'utf8',
  );

  it('states that a profile requires configuration, never executor behaviour', () => {
    assert.match(src, /can require CONFIGURATION at construction time\. It can NEVER require EXECUTOR\s*\n?\s*\*?\s*BEHAVIOUR/);
  });

  it('states that nine checked conditions have verified nine conditions', () => {
    assert.match(src, /Nine checked conditions have verified nine conditions/);
    assert.match(src, /not verified that\s*\n?\s*\*?\s*any write was atomic/);
  });

  it('records that the alias must resolve to _V1 FOREVER, not to a future _V2', () => {
    // Re-pointing the alias is the one change that would reintroduce the defect.
    assert.match(src, /must resolve\s*\n?\s*\*?\s*to `_V1` forever/);
    assert.match(src, /The next tightening MUST be `_V2`/);
  });
});
