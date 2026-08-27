'use strict';

/**
 * 1099 — the outcome can now say HOW STRONG the guarantee was, and can say it does not know.
 *
 * `conditional_write` answered succeeded / not_reported. Neither distinguishes a mutation that
 * committed inside one transaction from one that was merely followed by a read-back, and a field
 * that cannot tell them apart is a field that lets us claim the stronger one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  buildConditionalWriteBasis,
  isExecuteIfUnchangedOutcome,
  buildCasAttestation,
  buildExecutionProof,
} = require('../dist/cjs/index.js');

describe('1099 — guarantee classes on the basis', () => {
  for (const g of ['SAME_TRANSACTION', 'CONDITIONAL_EXTERNAL', 'NON_ATOMIC']) {
    it(`carries ${g} when the host reports it`, () => {
      const { basis } = buildConditionalWriteBasis({
        writeStyle: false, mutating: true, requireConditionalWrite: false,
        ctx: { conditional_write: true, guarantee: g },
      });
      assert.equal(basis.guarantee, g);
    });
  }

  it('NEVER infers a guarantee from conditional_write:true', () => {
    const { basis } = buildConditionalWriteBasis({
      writeStyle: false, mutating: true, requireConditionalWrite: false,
      ctx: { conditional_write: true },
    });
    assert.equal(basis.guarantee, undefined, 'silence is not a guarantee class');
  });

  it('rejects a guarantee value that is not one of the three', () => {
    const { basis } = buildConditionalWriteBasis({
      writeStyle: false, mutating: true, requireConditionalWrite: false,
      ctx: { conditional_write: true, guarantee: 'ATOMIC_ISH' },
    });
    assert.equal(basis.guarantee, undefined);
  });

  it('conditional_write:true + NON_ATOMIC is coherent — the host conditioned nothing', () => {
    const { basis, blockCause } = buildConditionalWriteBasis({
      writeStyle: false, mutating: true, requireConditionalWrite: true,
      ctx: { conditional_write: true, guarantee: 'NON_ATOMIC' },
    });
    assert.equal(basis.guarantee, 'NON_ATOMIC');
    assert.equal(blockCause, undefined, 'the policy gates on the report, not on the strength');
  });

  it('no guarantee is reported when the host was silent about the write itself', () => {
    const { basis } = buildConditionalWriteBasis({
      writeStyle: false, mutating: true, requireConditionalWrite: false, ctx: {},
    });
    assert.equal(basis.conditional_write, 'not_reported');
    assert.equal(basis.guarantee, undefined);
  });
});

describe('1099 — INDETERMINATE is a first-class outcome', () => {
  const outcome = {
    status: 'indeterminate',
    reason: 'response_lost',
    expected_token: 'fs:v1:1:' + 'a'.repeat(64),
    observed_token: null,
    detail: 'socket closed before response',
  };

  it('is recognised as an ExecuteIfUnchangedOutcome', () => {
    assert.equal(isExecuteIfUnchangedOutcome(outcome), true);
  });

  it('all three reasons are recognised, and an invented one is not', () => {
    for (const reason of ['response_lost', 'ambiguous_provider_reply', 'observation_failed']) {
      assert.equal(isExecuteIfUnchangedOutcome({ ...outcome, reason }), true, reason);
    }
    assert.equal(isExecuteIfUnchangedOutcome({ ...outcome, reason: 'probably_fine' }), false);
  });

  it('write_ran is the string "unknown" — never collapsed to a boolean', () => {
    const proof = buildExecutionProof({
      enforced: false, preflighted: true,
      verdict: { kind: 'ALLOW', action: 'CONTINUE', receiptVerified: true, envelope: null },
      call: { toolName: 't', arguments: {} },
      result: undefined,
    });
    const att = buildCasAttestation(proof, outcome, {});
    assert.equal(att.cas.status, 'indeterminate');
    assert.equal(att.cas.write_ran, 'unknown');
    assert.notEqual(att.cas.write_ran, false, 'false would claim it did not run');
    assert.notEqual(att.cas.write_ran, true, 'true would claim it did');
  });

  it('derived.indeterminate is set, and it is NOT a pass', () => {
    const proof = buildExecutionProof({
      enforced: false, preflighted: true,
      verdict: { kind: 'ALLOW', action: 'CONTINUE', receiptVerified: true, envelope: null },
      call: { toolName: 't', arguments: {} },
      result: undefined,
    });
    const att = buildCasAttestation(proof, outcome, {});
    assert.equal(att.derived.indeterminate, true);
    assert.equal(att.derived.authorized_and_committed, false, 'an unknown write is never authorized_and_committed');
    assert.equal(att.derived.write_ran, false, 'the boolean derived flag stays false — only cas.write_ran carries unknown');
    assert.equal(att.derived.refused, false, 'indeterminate is not refused either');
  });
});
