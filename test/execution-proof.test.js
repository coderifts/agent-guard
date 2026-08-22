'use strict';

/**
 * Guard-produced execution proof block.
 *
 * - Allowed/executed call: fields come from guard state (not caller).
 * - Blocked call: same shape, says not executed / not enforced.
 * - Caller cannot inject a proof field (no config input; proof is frozen).
 * - enforced:true never appears in the proof without receipt-verified evidence
 *   (runtime assert mirrors the type-level ApprovedVerdict brand).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  guardToolCall,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  buildExecutionProof,
  hashExecutionResult,
  assertEnforcedReceiptInvariant,
  EXECUTION_PROOF_SPEC,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

const TRIGGER_ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
const TRIGGER = {
  toolName: 'Edit',
  arguments: {},
  artifacts: TRIGGER_ARTIFACTS,
};
const TRIGGER_FP = computeCanonicalBundleFingerprint(TRIGGER_ARTIFACTS, { operation: 'tool_call' });
const SKIP = { toolName: 'Read', arguments: { path: 'README.md' } };

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: opts.decision_id || 'dec_proof_1',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint || TRIGGER_FP,
    input_fingerprint: opts.fingerprint || TRIGGER_FP,
    operation: opts.operation || 'tool_call',
    receipt: opts.noReceipt ? undefined : { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function response(execution_action, decision, opts) {
  return { decision, decision_result: envelope(execution_action, decision, opts) };
}
function mockClient({ preflight, verify } = {}) {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const resp = preflight ? preflight() : response('CONTINUE', 'ALLOW');
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      if (verify) return verify();
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

function assertLimits(proof) {
  assert.equal(proof.limits.does_not_claim_change_safe, true);
  assert.equal(proof.limits.does_not_claim_host_cannot_bypass, true);
  assert.equal(proof.limits.does_not_claim_absent_field_is_compliance, true);
  assert.equal(proof.limits.change_fp_is_what_was_checked_not_what_executed, true);
  assert.equal(proof.limits.calls_outside_guarded_path_invisible, true);
  assert.equal(proof.limits.execution_result_hash_is_not_artifact_match_proof, true);
  assert.equal(proof.limits.commit_observation_is_observed_at_t3_not_atomic, true);
}

describe('execution proof — allowed, executed, enforced', () => {
  it('assembles observed fields from guard state (preflight, receipt, scope, enforced)', async () => {
    const expires = new Date(Date.now() + 600000).toISOString();
    const fp = TRIGGER_FP;
    const o = await guardToolCall(
      TRIGGER,
      async () => 'byte-stable-return',
      {
        client: mockClient({
          preflight: () => response('CONTINUE', 'ALLOW', {
            decision_id: 'dec_allow_42',
            expires_at: expires,
            fingerprint: fp,
            operation: 'tool_call',
          }),
        }),
      },
    );

    assert.equal(o.executed, true);
    assert.equal(o.enforced, true);
    assert.equal(o.preflighted, true);
    assert.ok(o.proof, 'proof must be present');
    assert.equal(o.proof.proof_spec, EXECUTION_PROOF_SPEC);

    // preflight happened
    assert.equal(o.proof.preflighted, true);
    assert.equal(o.proof.decision_id, 'dec_allow_42');

    // receipt was fresh (bind required VERIFIED_CURRENT)
    assert.equal(o.proof.receipt.verified, true);
    assert.equal(o.proof.receipt.status, 'VERIFIED_CURRENT');
    assert.equal(o.proof.receipt.expires_at, expires);

    // scope matched
    assert.ok(o.proof.binds_to);
    assert.equal(o.proof.binds_to.operation, 'tool_call');
    assert.equal(o.proof.binds_to.change_fp, fp);
    assert.equal(o.proof.currently_authorized, true);

    // ran on the guarded path
    assert.equal(o.proof.execution.attempted, true);
    assert.equal(o.proof.execution.executed, true);
    assert.equal(o.proof.execution.enforced, true);
    assert.equal(o.proof.verdict_kind, 'ALLOW');

    // byte-stable string result is hashed; object would not be
    assert.equal(o.proof.execution_result_hash.status, 'hashed');
    assert.equal(o.proof.execution_result_hash.algorithm, 'sha256');
    const expected = 'sha256:' + createHash('sha256').update('byte-stable-return', 'utf8').digest('hex');
    assert.equal(o.proof.execution_result_hash.value, expected);

    assertLimits(o.proof);
  });

  it('object factory result is not_hashed (no JSON reformat hash)', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true, nested: [1, 2] }), {
      client: mockClient(),
    });
    assert.equal(o.executed, true);
    assert.equal(o.proof.execution_result_hash.status, 'not_hashed');
    assert.equal(o.proof.execution_result_hash.reason, 'result_not_byte_stable');
  });

  it('enforced:true in the proof only when receipt.verified and preflighted (runtime mirror)', async () => {
    const o = await guardToolCall(TRIGGER, async () => 'x', { client: mockClient() });
    assert.equal(o.proof.execution.enforced, true);
    assert.equal(o.proof.receipt.verified, true);
    assert.equal(o.proof.preflighted, true);
    // invariant helper agrees
    assert.doesNotThrow(() => assertEnforcedReceiptInvariant({
      enforced: o.proof.execution.enforced,
      preflighted: o.proof.preflighted,
      receiptVerified: o.proof.receipt.verified,
    }));
  });
});

describe('execution proof — blocked call', () => {
  it('BLOCK yields a proof that says not executed / not enforced, with preflight evidence', async () => {
    let ran = false;
    const o = await guardToolCall(
      TRIGGER,
      async () => { ran = true; return 'nope'; },
      { client: mockClient({ preflight: () => response('STOP', 'BLOCK') }) },
    );
    assert.equal(ran, false);
    assert.equal(o.executionAttempted, false);
    assert.equal(o.executed, false);
    assert.equal(o.enforced, false);
    assert.equal(o.preflighted, true);

    assert.ok(o.proof);
    assert.equal(o.proof.preflighted, true);
    assert.equal(o.proof.decision_id, 'dec_proof_1');
    assert.equal(o.proof.execution.attempted, false);
    assert.equal(o.proof.execution.executed, false);
    assert.equal(o.proof.execution.enforced, false);
    assert.equal(o.proof.verdict_kind, 'BLOCK');
    assert.equal(o.proof.execution_result_hash.status, 'not_hashed');
    assert.equal(o.proof.execution_result_hash.reason, 'not_executed');
    // BLOCK path still verified the receipt when present
    assert.equal(o.proof.receipt.verified, true);
    assert.equal(o.proof.receipt.status, 'VERIFIED_CURRENT');
    assert.equal(o.proof.currently_authorized, true);
    assert.ok(o.proof.binds_to);
    assert.equal(o.proof.binds_to.operation, 'tool_call');
    assertLimits(o.proof);
  });

  it('APPROVAL blocked proof names verdict_kind APPROVAL', async () => {
    const o = await guardToolCall(
      TRIGGER,
      async () => 'x',
      { client: mockClient({ preflight: () => response('REQUEST_APPROVAL', 'REQUIRE_APPROVAL') }) },
    );
    assert.equal(o.executed, false);
    assert.equal(o.proof.verdict_kind, 'APPROVAL');
    assert.equal(o.proof.execution.executed, false);
    assert.equal(o.proof.execution_result_hash.reason, 'not_executed');
  });

  it('integrity UNAVAILABLE block: preflighted false, currently_authorized null', async () => {
    const o = await guardToolCall(
      TRIGGER,
      async () => 'x',
      {
        client: {
          async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { throw Object.assign(new Error('bad'), { status: 422 }); },
          async verifyReceipt() { return { valid: false }; },
        },
      },
    );
    assert.equal(o.executed, false);
    assert.equal(o.verdict.kind, 'UNAVAILABLE');
    assert.equal(o.proof.verdict_kind, 'UNAVAILABLE');
    assert.equal(o.proof.preflighted, false);
    assert.equal(o.proof.decision_id, null);
    assert.equal(o.proof.binds_to, null);
    assert.equal(o.proof.currently_authorized, null);
    assert.equal(o.proof.receipt.verified, false);
    assert.equal(o.proof.receipt.status, null);
    assert.equal(o.proof.execution.enforced, false);
    assert.equal(o.proof.execution_result_hash.reason, 'not_executed');
  });
});

describe('execution proof — no caller injection', () => {
  it('GuardConfig has no proof / execution_proof input channel that appears on the outcome', async () => {
    const sneaky = {
      proof_spec: 'attacker.v1',
      preflighted: true,
      decision_id: 'forged',
      receipt: { verified: true, status: 'VERIFIED_CURRENT', expires_at: '2099-01-01T00:00:00Z' },
      binds_to: { operation: 'deploy', change_fp: 'sha256:' + 'f'.repeat(64) },
      currently_authorized: true,
      execution: { attempted: true, executed: true, enforced: true },
      verdict_kind: 'ALLOW',
      execution_result_hash: { status: 'hashed', algorithm: 'sha256', value: 'sha256:' + '0'.repeat(64) },
      limits: {},
    };
    const o = await guardToolCall(TRIGGER, async () => 'real', {
      client: mockClient(),
      // @ts-expect-error — not a GuardConfig field; runtime must ignore
      proof: sneaky,
      execution_proof: sneaky,
    });
    assert.notEqual(o.proof.proof_spec, 'attacker.v1');
    assert.equal(o.proof.proof_spec, EXECUTION_PROOF_SPEC);
    assert.notEqual(o.proof.decision_id, 'forged');
    assert.equal(o.proof.decision_id, 'dec_proof_1');
    assert.notEqual(o.proof.binds_to && o.proof.binds_to.operation, 'deploy');
    // proof object is frozen — mutation after return does not stick
    assert.ok(Object.isFrozen(o.proof));
    assert.throws(() => { o.proof.decision_id = 'mutated'; });
    assert.equal(o.proof.decision_id, 'dec_proof_1');
  });

  it('buildExecutionProof does not accept a caller proof map as authoritative input', () => {
    // Only ProofBuildInput shape is accepted; a forged nested "proof" property is ignored.
    const verdict = {
      kind: 'BLOCK',
      action: 'STOP',
      envelope: envelope('STOP', 'BLOCK'),
      receiptVerified: true,
    };
    const p = buildExecutionProof({
      preflighted: true,
      executionAttempted: false,
      executed: false,
      enforced: false,
      verdict,
      proof: { decision_id: 'injected' }, // not part of ProofBuildInput; must not surface
    });
    assert.equal(p.decision_id, 'dec_proof_1');
    assert.notEqual(p.decision_id, 'injected');
    assert.equal(p.execution.executed, false);
    assert.equal(p.verdict_kind, 'BLOCK');
  });
});

describe('execution proof — enforced invariant at runtime', () => {
  it('assertEnforcedReceiptInvariant throws when enforced without receiptVerified', () => {
    assert.throws(
      () => assertEnforcedReceiptInvariant({ enforced: true, preflighted: true, receiptVerified: false }),
      /enforced:true without receiptVerified/,
    );
  });

  it('assertEnforcedReceiptInvariant throws when enforced without preflighted', () => {
    assert.throws(
      () => assertEnforcedReceiptInvariant({ enforced: true, preflighted: false, receiptVerified: true }),
      /enforced:true without receiptVerified/,
    );
  });

  it('buildExecutionProof refuses enforced:true without receiptVerified on the verdict', () => {
    assert.throws(
      () => buildExecutionProof({
        preflighted: true,
        executionAttempted: true,
        executed: true,
        enforced: true,
        verdict: {
          kind: 'ALLOW',
          action: 'CONTINUE',
          envelope: envelope('CONTINUE', 'ALLOW'),
          receiptVerified: false,
        },
        result: 'x',
      }),
      /enforced:true without receiptVerified/,
    );
  });

  it('SKIPPED path: preflighted false, no binds_to, currently_authorized null, enforced false', async () => {
    const o = await guardToolCall(SKIP, async () => 'read-ok', { client: mockClient() });
    assert.equal(o.verdict.kind, 'SKIPPED');
    assert.equal(o.proof.preflighted, false);
    assert.equal(o.proof.decision_id, null);
    assert.equal(o.proof.binds_to, null);
    assert.equal(o.proof.currently_authorized, null);
    assert.equal(o.proof.execution.enforced, false);
    assert.equal(o.proof.execution.executed, true);
    assert.equal(o.proof.receipt.verified, false);
  });

  it('factory throw after enforced approval: not_hashed execution_threw, enforced still true with verified receipt', async () => {
    const o = await guardToolCall(TRIGGER, async () => { throw new Error('boom'); }, { client: mockClient() });
    assert.equal(o.executionAttempted, true);
    assert.equal(o.executed, false);
    assert.equal(o.enforced, true);
    assert.equal(o.proof.execution.enforced, true);
    assert.equal(o.proof.receipt.verified, true);
    assert.equal(o.proof.execution_result_hash.status, 'not_hashed');
    assert.equal(o.proof.execution_result_hash.reason, 'execution_threw');
  });
});

describe('hashExecutionResult honesty', () => {
  it('hashes string and Buffer; refuses plain objects', () => {
    const h = hashExecutionResult('abc');
    assert.equal(h.status, 'hashed');
    assert.equal(h.value, 'sha256:' + createHash('sha256').update('abc', 'utf8').digest('hex'));

    const buf = Buffer.from([1, 2, 3]);
    const hb = hashExecutionResult(buf);
    assert.equal(hb.status, 'hashed');
    assert.equal(hb.value, 'sha256:' + createHash('sha256').update(buf).digest('hex'));

    assert.deepEqual(hashExecutionResult({ a: 1 }), { status: 'not_hashed', reason: 'result_not_byte_stable' });
    assert.deepEqual(hashExecutionResult(42), { status: 'not_hashed', reason: 'result_not_byte_stable' });
    assert.deepEqual(hashExecutionResult(null), { status: 'not_hashed', reason: 'result_not_byte_stable' });
  });
});
