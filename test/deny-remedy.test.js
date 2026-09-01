'use strict';

/**
 * A refused tool call names the next step.
 *
 * The load-bearing assertion is the one this repo already enforces: on a
 * refused path the factory NEVER runs and no result is invented. The remedy is
 * attached after that verdict, so every case below asserts executed:false,
 * enforced:false and the absence of `result` alongside the remedy it carries.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  guardToolCall, computeBodyHash, computeArtifactDigest, computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');
const { denyErrorForReason, DENY_ERROR } = require('../dist/cjs/deny-remedy.js');
const { assertValidRemedy } = require('./remedy-shape.js');

const ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0', after: 'openapi: 3.0.1' }];
const TRIGGER = { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS };
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);
const LOCAL_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });

function envelope(o = {}) {
  const { __token, __noReceipt, ...rest } = o;
  const env = {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: LOCAL_FP, input_fingerprint: LOCAL_FP,
    analysis_complete: true, artifact_digest: LOCAL_DIGEST, operation: 'tool_call',
    ...rest,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  if (!__noReceipt) env.receipt = { token: __token || 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  return env;
}
const signedFor = (env) => ({ fp: env.fingerprint, bh: computeBodyHash(env) });

function client(env, { response, verify } = {}) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { return response || { decision: env.decision, execution_action: env.execution_action, decision_result: env }; },
    async verifyReceipt() { return verify || { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; },
  };
}
async function run(env, opts = {}, cfg = {}) {
  let executed = false;
  const outcome = await guardToolCall(TRIGGER, async () => { executed = true; return 'SIDE_EFFECT'; }, { client: client(env, opts), ...cfg });
  return { outcome, executed };
}

/** The invariant this repo already holds, asserted alongside every remedy. */
function assertBlockedAndEmpty(r) {
  assert.equal(r.executed, false, 'the factory must not have run');
  assert.equal(r.outcome.executed, false);
  assert.equal(r.outcome.enforced, false);
  assert.equal(r.outcome.executionAttempted, false);
  assert.ok(!('result' in r.outcome), 'a blocked outcome must not carry an invented result');
}

describe('deny-remedy — a refused tool call names the next step', () => {
  it('GRANT_REQUIRED: an allow-class decision with no receipt', async () => {
    const r = await run(envelope({ __noReceipt: true }));
    assertBlockedAndEmpty(r);
    assert.equal(r.outcome.verdict.cause, 'RECEIPT_MISSING');
    assertValidRemedy(r.outcome.remedy, 'RECEIPT_MISSING');
    assert.equal(r.outcome.remedy.error, DENY_ERROR.GRANT_REQUIRED);
    assert.equal(r.outcome.remedy.target, 'apply_openapi');
    // This surface HAS a fingerprint of the change set it refused, so it carries one.
    assert.match(r.outcome.remedy.fingerprint, /^sha256:[0-9a-f]{64}$/);
  });

  it('GRANT_INVALID: a receipt that does not verify', async () => {
    const env = envelope();
    const r = await run(env, { verify: { valid: false, status: 'INVALID_SIGNATURE' } });
    assertBlockedAndEmpty(r);
    assert.equal(r.outcome.verdict.cause, 'RECEIPT_UNVERIFIED');
    assertValidRemedy(r.outcome.remedy, 'RECEIPT_UNVERIFIED');
    assert.equal(r.outcome.remedy.error, DENY_ERROR.GRANT_INVALID);
  });

  it('GRANT_MISMATCH: a valid receipt bound to a different envelope', async () => {
    const env = envelope();
    const other = envelope({ decision_id: 'dec_other' });
    const r = await run(env, { verify: { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(other) } });
    assertBlockedAndEmpty(r);
    assert.equal(r.outcome.verdict.cause, 'RECEIPT_ENVELOPE_MISMATCH');
    assertValidRemedy(r.outcome.remedy, 'RECEIPT_ENVELOPE_MISMATCH');
    assert.equal(r.outcome.remedy.error, DENY_ERROR.GRANT_MISMATCH);
  });
});

describe('deny-remedy — the refusals it declines to describe', () => {
  it('SCHEMA_INVALID carries NO remedy: another grant is not the next step', async () => {
    const r = await run(envelope(), { response: { decision_result: { execution_action: 1 } } });
    assertBlockedAndEmpty(r);
    assert.equal(denyErrorForReason(r.outcome.verdict.cause), null);
    assert.ok(!('remedy' in r.outcome), `unexpected remedy for ${r.outcome.verdict.cause}`);
  });

  it('a policy BLOCK carries NO remedy: the grant verified, the answer was no', async () => {
    const env = envelope({ decision: 'BLOCK', execution_action: 'STOP', safe_for_agent: false });
    const r = await run(env);
    assertBlockedAndEmpty(r);
    assert.equal(r.outcome.verdict.kind, 'BLOCK');
    assert.ok(!('remedy' in r.outcome), 'a BLOCK is a decision, not a missing grant');
  });

  it('an executed call carries NO remedy', async () => {
    const r = await run(envelope());
    assert.equal(r.executed, true, JSON.stringify(r.outcome.verdict));
    assert.equal(r.outcome.executed, true);
    assert.ok(!('remedy' in r.outcome), 'an executed outcome must not carry a refusal remedy');
  });
});

describe('deny-remedy — the verdict is unchanged', () => {
  const verdictOf = (o) => ({
    executionAttempted: o.executionAttempted, executed: o.executed, enforced: o.enforced,
    preflighted: o.preflighted, kind: o.verdict.kind, cause: o.verdict.cause,
    action: o.verdict.action, resolution: o.verdict.resolution,
  });

  it('every field the guard decided with matches the pre-remedy values', async () => {
    assert.deepEqual(verdictOf((await run(envelope({ __noReceipt: true }))).outcome), {
      executionAttempted: false, executed: false, enforced: false, preflighted: false,
      kind: 'UNAVAILABLE', cause: 'RECEIPT_MISSING', action: 'STOP', resolution: 'CLOSED',
    });
  });

  it('the remedy is the ONLY added key on a refused outcome', async () => {
    const withRemedy = (await run(envelope({ __noReceipt: true }))).outcome;
    const noRemedy = (await run(envelope(), { response: { decision_result: { execution_action: 1 } } })).outcome;
    const added = Object.keys(withRemedy).filter((k) => !Object.keys(noRemedy).includes(k));
    assert.deepEqual(added, ['remedy']);
  });
});
