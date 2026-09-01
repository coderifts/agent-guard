'use strict';

/**
 * The unversioned spelling gets a pointer, not a deprecation.
 *
 * The alias is PERMANENT by design (`with-coderifts.ts:232` — "must resolve to `_V1` forever"), so
 * the notice must not say deprecated, must not name a removal version, and must not imply either.
 * A notice announcing a removal that will never happen is a false statement shipped to everyone on
 * the alias, which is worse than the silence it replaced.
 *
 * The assertions therefore run in both directions: the text says what it should, and it does NOT
 * say the four things it must never say.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const {
  withCodeRifts, UNVERSIONED_PROFILE_NOTICE, _resetUnversionedProfileNoticeForTest,
  PROFILE_ENFORCING_STRICT_V1,
} = require('../dist/cjs/index.js');

const construction = (profile) => ({
  tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
  client: { preflight: async () => ({}) },
  operation: 'merge',
  profile,
  resolvePriorContent: async () => null,
  executionGrant: { enabled: true },
  repository: 'acme/api',
});

/** Capture console.warn — the channel policy.ts already uses for an advisory that is not an error. */
let warned;
let originalWarn;
beforeEach(() => {
  warned = [];
  originalWarn = console.warn;
  console.warn = (...args) => { warned.push(args.join(' ')); };
  _resetUnversionedProfileNoticeForTest();
});
afterEach(() => { console.warn = originalWarn; });

describe('the notice text', () => {
  it('is exactly the sentence, and names both spellings', () => {
    assert.equal(
      UNVERSIONED_PROFILE_NOTICE,
      'ENFORCING_STRICT is the unversioned spelling of ENFORCING_STRICT_V1; prefer the versioned name.',
    );
  });

  it('promises NOTHING about removal — the alias is permanent by design', () => {
    for (const forbidden of [/deprecat/i, /remov/i, /major/i, /will be/i]) {
      assert.ok(
        !forbidden.test(UNVERSIONED_PROFILE_NOTICE),
        `the notice must not match ${forbidden}: the alias resolves to _V1 forever`,
      );
    }
  });
});

describe('emission', () => {
  it('the unversioned spelling emits it once', () => {
    withCodeRifts(construction('ENFORCING_STRICT'));
    assert.deepEqual(warned, [UNVERSIONED_PROFILE_NOTICE]);
  });

  it('EXACTLY ONE emission across two constructions', () => {
    withCodeRifts(construction('ENFORCING_STRICT'));
    withCodeRifts(construction('ENFORCING_STRICT'));
    assert.equal(warned.length, 1, `expected one notice, got ${warned.length}`);
  });

  it('ZERO emissions when the versioned name is used', () => {
    withCodeRifts(construction(PROFILE_ENFORCING_STRICT_V1));
    withCodeRifts(construction('ENFORCING_STRICT_V1'));
    assert.deepEqual(warned, []);
  });

  it('ZERO emissions when no profile is set', () => {
    withCodeRifts(construction(undefined));
    assert.deepEqual(warned, []);
  });

  it('an atomic profile does not trigger the strict notice, even when construction aborts', () => {
    // ATOMIC_V1 aborts here (its invariant conjunction is not wired in this fixture). The notice
    // is emitted BEFORE validation, so this also checks it is keyed on the spelling and not on
    // whether the construction went on to succeed.
    assert.throws(() => withCodeRifts(construction('ENFORCING_ATOMIC_V1')), /ATOMIC_PROFILE_UNSATISFIED/);
    assert.deepEqual(warned, []);
  });

  it('the notice fires on the alias even when construction later aborts', () => {
    assert.throws(() => withCodeRifts({ ...construction('ENFORCING_STRICT'), operation: '' }));
    assert.deepEqual(warned, [UNVERSIONED_PROFILE_NOTICE]);
  });

  it('goes to console.warn, not process.emitWarning — this is not a DeprecationWarning', async () => {
    const seen = [];
    const onWarn = (w) => seen.push(w.name);
    process.on('warning', onWarn);
    withCodeRifts(construction('ENFORCING_STRICT'));
    await new Promise((r) => setImmediate(r));
    process.off('warning', onWarn);
    assert.equal(warned.length, 1);
    assert.ok(!seen.includes('DeprecationWarning'), 'the alias is not deprecated');
  });
});

describe('nothing else moved', () => {
  it('the wire value under the alias is still the suffix-less string', () => {
    // Four downstream modules compare opts.profile === 'ENFORCING_STRICT'; the notice observes
    // the spelling and must not rewrite it.
    const a = withCodeRifts(construction('ENFORCING_STRICT'));
    const b = withCodeRifts(construction('ENFORCING_STRICT_V1'));
    assert.deepEqual(
      Object.keys(a.registry_report).sort(),
      Object.keys(b.registry_report).sort(),
    );
  });

  it('a construction that emits the notice still succeeds', () => {
    const r = withCodeRifts(construction('ENFORCING_STRICT'));
    assert.equal(r.tools.length, 1);
    assert.equal(warned.length, 1);
  });
});
