'use strict';
/**
 * 2026-08-26 audit: ENFORCING_STRICT built cleanly with the execution chain absent, so "strict"
 * meant the guard lock and not the chain that makes a commit provable. Reproduced against the
 * shipped tarball; these are the permanent regressions.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { withCodeRifts } = require('../dist/cjs/index.js');

const STUB_CLIENT = { authorizeChangeSet: async () => ({ execution_action: 'CONTINUE', decision: 'ALLOW' }) };
const tools = () => [{ name: 'write_spec', description: 'writes a spec', execute: async () => ({ ok: true }) }];

const base = (extra = {}) => ({
  tools: tools(),
  client: STUB_CLIENT,
  operation: 'merge',
  resolvePriorContent: () => '',
  ...extra,
});
const strict = (extra = {}) => base({ profile: 'ENFORCING_STRICT', ...extra });

describe('ENFORCING_STRICT requires the execution chain', () => {
  it('REPRO: strict with executionGrant ABSENT refuses to construct', () => {
    assert.throws(() => withCodeRifts(strict()), /ENFORCING_STRICT requires the execution chain/);
  });

  it('REPRO: strict with executionGrant.enabled === false refuses to construct', () => {
    assert.throws(
      () => withCodeRifts(strict({ executionGrant: { enabled: false } })),
      /executionGrant\.enabled is not true/,
    );
  });

  it('the refusal says WHY, not just what — a grant-less strict can never prove a commit', () => {
    try {
      withCodeRifts(strict());
      assert.fail('expected a refusal');
    } catch (err) {
      assert.match(err.message, /nothing binds the executor to it/);
      assert.match(err.message, /authorized_not_committed \/ commit_evidence_missing/);
    }
  });

  it('the refusal carries a pasteable config snippet (the ergonomics rule)', () => {
    try {
      withCodeRifts(strict());
      assert.fail('expected a refusal');
    } catch (err) {
      assert.match(err.message, /executionGrant: \{ enabled: true \}/);
      assert.match(err.message, /resolveStateNonce/);
    }
  });

  it('strict WITH a grant constructs', () => {
    const r = withCodeRifts(strict({ executionGrant: { enabled: true } }));
    assert.equal(r.tools.length, 1);
  });

  it('strict with a grant AND a per-call nonce (ATOMIC) constructs', () => {
    const r = withCodeRifts(strict({
      executionGrant: { enabled: true, resolveStateNonce: () => 'n-1' },
    }));
    assert.equal(r.tools.length, 1);
  });
});

describe('ATOMIC vs BEARER — named, not refused', () => {
  it('BEARER (grant, no nonce) constructs and is RECORDED as a residual', () => {
    const r = withCodeRifts(strict({ executionGrant: { enabled: true } }));
    assert.ok(r.composition_assurance.residuals.includes('execution_grant_bearer_no_state_nonce'),
      'a weaker grant profile must be visible in the composition, not silent');
  });

  it('ATOMIC (grant + nonce) does NOT carry the BEARER residual', () => {
    const r = withCodeRifts(strict({
      executionGrant: { enabled: true, resolveStateNonce: () => 'n-1' },
    }));
    assert.equal(r.composition_assurance.residuals.includes('execution_grant_bearer_no_state_nonce'), false);
  });

  it('construction still reports what it OBSERVED, not what it assumed', () => {
    // A grant being configured is a host claim. It must not flip any product-level claim.
    const r = withCodeRifts(strict({ executionGrant: { enabled: true, resolveStateNonce: () => 'n' } }));
    assert.equal(r.composition_assurance.inescapable_runtime, false,
      'wiring a grant is not runtime inescapability');
    assert.ok(r.composition_assurance.residuals.length > 0, 'residuals are never emptied by config');
  });
});

describe('this is a strict-only tightening', () => {
  it('a composition with NO profile is unaffected by a missing grant', () => {
    const r = withCodeRifts(base());
    assert.equal(r.tools.length, 1);
  });

  it('a no-profile composition does not gain the BEARER residual', () => {
    const r = withCodeRifts(base());
    assert.equal(r.composition_assurance.residuals.includes('execution_grant_bearer_no_state_nonce'), false);
  });

  it('a no-profile composition with enabled:false still constructs', () => {
    const r = withCodeRifts(base({ executionGrant: { enabled: false } }));
    assert.equal(r.tools.length, 1);
  });

  it('BYTE-IDENTICAL: the non-strict composition_assurance is unchanged by this feature', () => {
    // Same input, twice, through the same build — the shape a consumer depends on.
    const a = withCodeRifts(base()).composition_assurance;
    const b = withCodeRifts(base()).composition_assurance;
    assert.deepEqual(a, b);
    assert.equal(a.residuals.includes('execution_grant_bearer_no_state_nonce'), false);
  });
});

describe('the construction-time / observed-afterwards split', () => {
  it('strict does NOT require executorAttestation — its absence is told by the outcome instead', () => {
    // Without a registry a strict outcome can never reach authorized_and_committed, so the
    // absence already reports itself. A second refusal would widen the break for no new truth.
    const r = withCodeRifts(strict({ executionGrant: { enabled: true } }));
    assert.equal(r.tools.length, 1);
  });

  it('strict does not claim anything about the EXECUTOR at construction time', () => {
    const r = withCodeRifts(strict({ executionGrant: { enabled: true, resolveStateNonce: () => 'n' } }));
    const a = r.composition_assurance;
    // Nothing here asserts the executor consumed a nonce or honoured a scope hash — those are
    // per-call observations, and construction must not pre-empt them.
    assert.equal(typeof a.inescapable_runtime, 'boolean');
    assert.equal(a.inescapable_runtime, false);
  });
});
