'use strict';

/**
 * Pure freshness core — content identity, four outcomes, write-style id requirement.
 * No network, no filesystem, no Date.now().
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  assessFreshness,
  assessWriteStylePrior,
  contentByteIdentical,
  computePathSetTreeHash,
  freshnessAllowsEnforce,
} = require('../dist/cjs/index.js');

const BEFORE = 'openapi: 3.0.0\npaths:\n  /x:\n    get:\n      responses:\n        "200":\n          description: ok\n';
const BEFORE_MUTATED = 'openapi: 3.0.0\npaths:\n  /x:\n    get:\n      responses:\n        "200":\n          description: gone\n';
// Same contract bytes, different surrounding formatting of a *different* file in the tree hash set.
const CONTRACT_SAME = BEFORE;

describe('freshness — content identity (not time)', () => {
  it('byte-identical before is fresh regardless of any "age" notion (no TTL field in result)', () => {
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
    });
    assert.equal(r.outcome, 'FRESH');
    assert.equal(r.failClosed, false);
    assert.equal(r.level, 'contract_only');
    assert.equal(r.contractMatch, true);
    assert.equal(Object.prototype.hasOwnProperty.call(r, 'ageMs'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(r, 'ttl'), false);
  });

  it('contentByteIdentical is strict string equality', () => {
    assert.equal(contentByteIdentical('a', 'a'), true);
    assert.equal(contentByteIdentical('a', 'b'), false);
    assert.equal(contentByteIdentical('a\n', 'a'), false);
  });
});

describe('freshness — four outcomes', () => {
  it('TARGET_MUTATED when contract before moved (tree unbound → contract_only level)', () => {
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE_MUTATED,
    });
    assert.equal(r.outcome, 'TARGET_MUTATED');
    assert.equal(r.failClosed, true);
    assert.equal(r.level, 'contract_only');
    assert.equal(r.contractMatch, false);
    assert.equal(r.treeMatch, null);
    assert.match(r.message, /TARGET_MUTATED/);
  });

  it('formatting-only / tree-only move with identical contract → STALE_CONTEXT, not TARGET_MUTATED', () => {
    const tree1 = computePathSetTreeHash([
      { path: 'openapi.yaml', content: CONTRACT_SAME },
      { path: 'README.md', content: 'v1\n' },
    ]);
    const tree2 = computePathSetTreeHash([
      { path: 'openapi.yaml', content: CONTRACT_SAME },
      { path: 'README.md', content: 'v2  (format / prose only)\n' },
    ]);
    assert.notEqual(tree1, tree2);

    const r = assessFreshness({
      preflightBefore: CONTRACT_SAME,
      resolvedBeforeNow: CONTRACT_SAME,
      preflightTreeHash: tree1,
      resolvedTreeHashNow: tree2,
    });
    assert.equal(r.outcome, 'STALE_CONTEXT');
    assert.equal(r.contractMatch, true);
    assert.equal(r.treeMatch, false);
    assert.equal(r.failClosed, true); // default closed
    assert.equal(r.level, 'full');
    // Must say it is not tampering
    assert.match(r.message, /NOT tampering/i);
    assert.notEqual(r.outcome, 'TAMPERED');
    assert.notEqual(r.outcome, 'TARGET_MUTATED');
  });

  it('STALE_CONTEXT is distinguishable from TAMPERED in the outcome field', () => {
    const tree1 = computePathSetTreeHash([{ path: 'a.yaml', content: BEFORE }]);
    const tree2 = computePathSetTreeHash([{ path: 'a.yaml', content: BEFORE + '\n' }]);

    const stale = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
      preflightTreeHash: tree1,
      resolvedTreeHashNow: tree2,
    });
    const tampered = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE_MUTATED,
      preflightTreeHash: tree1,
      resolvedTreeHashNow: tree2,
    });
    assert.equal(stale.outcome, 'STALE_CONTEXT');
    assert.equal(tampered.outcome, 'TAMPERED');
    assert.notEqual(stale.outcome, tampered.outcome);
    assert.equal(tampered.failClosed, true);
    assert.match(tampered.message, /TAMPERED/);
  });

  it('UNKNOWN_FRESHNESS when current before is not measurable', () => {
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: null,
    });
    assert.equal(r.outcome, 'UNKNOWN_FRESHNESS');
    assert.equal(r.failClosed, true);
    assert.equal(r.contractMatch, null);
    assert.match(r.message, /not measurable/i);
    assert.notEqual(r.outcome, 'TARGET_MUTATED');
  });

  it('UNKNOWN_FRESHNESS when tree was bound but current tree is unmeasurable', () => {
    const tree1 = computePathSetTreeHash([{ path: 'a.yaml', content: BEFORE }]);
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
      preflightTreeHash: tree1,
      resolvedTreeHashNow: null,
    });
    assert.equal(r.outcome, 'UNKNOWN_FRESHNESS');
    assert.equal(r.level, 'full');
    assert.equal(r.failClosed, true);
    assert.match(r.message, /tree/i);
  });

  it('policy allowStaleContext opts out of fail-closed for STALE_CONTEXT only', () => {
    const t1 = computePathSetTreeHash([{ path: 'a', content: 'x' }]);
    const t2 = computePathSetTreeHash([{ path: 'a', content: 'y' }]);
    const denied = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
      preflightTreeHash: t1,
      resolvedTreeHashNow: t2,
      allowStaleContext: false,
    });
    const allowed = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
      preflightTreeHash: t1,
      resolvedTreeHashNow: t2,
      allowStaleContext: true,
    });
    assert.equal(denied.outcome, 'STALE_CONTEXT');
    assert.equal(denied.failClosed, true);
    assert.equal(allowed.outcome, 'STALE_CONTEXT');
    assert.equal(allowed.failClosed, false);
    // TARGET_MUTATED never opts out via this flag
    const mut = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE_MUTATED,
      preflightTreeHash: t1,
      resolvedTreeHashNow: t1,
      allowStaleContext: true,
    });
    assert.equal(mut.outcome, 'TARGET_MUTATED');
    assert.equal(mut.failClosed, true);
  });
});

describe('freshness — receipt without tree hash reports reduced level', () => {
  it('fresh without tree hash is contract_only and message says so', () => {
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
      // no preflightTreeHash
    });
    assert.equal(r.outcome, 'FRESH');
    assert.equal(r.level, 'contract_only');
    assert.match(r.message, /contract_only|Tree-hash check was not bound/i);
  });

  it('mutation without tree hash is still TARGET_MUTATED at contract_only (not quiet pass)', () => {
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE_MUTATED,
    });
    assert.equal(r.outcome, 'TARGET_MUTATED');
    assert.equal(r.level, 'contract_only');
    assert.equal(r.failClosed, true);
  });

  it('full level when tree hashes are both present and match', () => {
    const t = computePathSetTreeHash([{ path: 'openapi.yaml', content: BEFORE }]);
    const r = assessFreshness({
      preflightBefore: BEFORE,
      resolvedBeforeNow: BEFORE,
      preflightTreeHash: t,
      resolvedTreeHashNow: t,
    });
    assert.equal(r.outcome, 'FRESH');
    assert.equal(r.level, 'full');
    assert.equal(r.treeMatch, true);
  });
});

describe('freshness — write-style prior (caller names, gate resolves)', () => {
  it('write-style without artifact id fails closed and says what is missing', () => {
    const r = assessWriteStylePrior({
      path: 'openapi.yaml',
      after: 'new content',
    });
    assert.equal(r.gateable, false);
    assert.equal(r.reason, 'MISSING_ARTIFACT_ID');
    assert.equal(r.claimedBeforeAcceptedAsMeasurement, false);
    assert.match(r.message, /artifact (id|identifier)/i);
  });

  it('claimed before without artifact id is rejected as claim, never a measurement ladder', () => {
    const r = assessWriteStylePrior({
      path: 'openapi.yaml',
      after: 'new',
      claimedBefore: BEFORE,
    });
    assert.equal(r.gateable, false);
    assert.equal(r.reason, 'CLAIMED_BEFORE_NOT_MEASUREMENT');
    assert.equal(r.claimedBeforeAcceptedAsMeasurement, false);
    assert.match(r.message, /claim/i);
  });

  it('artifact id present is gateable (gate will resolve; no before required from caller)', () => {
    const r = assessWriteStylePrior({
      artifactId: 'openapi:openapi.yaml',
      path: 'openapi.yaml',
      after: 'new',
    });
    assert.equal(r.gateable, true);
    assert.equal(r.reason, 'ok');
    assert.equal(r.claimedBeforeAcceptedAsMeasurement, false);
  });
});

describe('freshnessAllowsEnforce', () => {
  it('true only for FRESH or policy-accepted STALE_CONTEXT', () => {
    const fresh = assessFreshness({ preflightBefore: 'a', resolvedBeforeNow: 'a' });
    assert.equal(freshnessAllowsEnforce(fresh), true);

    const t1 = computePathSetTreeHash([{ path: 'p', content: '1' }]);
    const t2 = computePathSetTreeHash([{ path: 'p', content: '2' }]);
    const staleClosed = assessFreshness({
      preflightBefore: 'a', resolvedBeforeNow: 'a',
      preflightTreeHash: t1, resolvedTreeHashNow: t2,
    });
    assert.equal(freshnessAllowsEnforce(staleClosed), false);

    const staleOpen = assessFreshness({
      preflightBefore: 'a', resolvedBeforeNow: 'a',
      preflightTreeHash: t1, resolvedTreeHashNow: t2,
      allowStaleContext: true,
    });
    assert.equal(freshnessAllowsEnforce(staleOpen), true);

    const mut = assessFreshness({ preflightBefore: 'a', resolvedBeforeNow: 'b' });
    assert.equal(freshnessAllowsEnforce(mut), false);
  });
});

describe('computePathSetTreeHash', () => {
  it('is deterministic and order-independent by path sort', () => {
    const a = computePathSetTreeHash([
      { path: 'b.yaml', content: '2' },
      { path: 'a.yaml', content: '1' },
    ]);
    const b = computePathSetTreeHash([
      { path: 'a.yaml', content: '1' },
      { path: 'b.yaml', content: '2' },
    ]);
    assert.equal(a, b);
    assert.match(a, /^sha256:[0-9a-f]{64}$/);
  });
});
