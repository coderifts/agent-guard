'use strict';

/**
 * N-6 first-run freshness: fail-closed stays; the binder-visible ERROR names
 * the missing piece (resolvePriorContent) and the one-line fix.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  guardToolCall,
  bindLangGraphGuardOutcome,
  bindOpenAIGuardOutcome,
  bindAnthropicGuardOutcome,
  bindGeminiGuardOutcome,
  freshnessRefusalTeaching,
  FRESHNESS_RESOLVER_FIX,
  computeCanonicalBundleFingerprint,
  computeBodyHash,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

const AFTER = 'openapi: 3.0.0\npaths:\n  /x:\n    get: {}\n';
const BEFORE = 'openapi: 3.0.0\npaths: {}\n';
const ARTIFACTS = [{ id: 'openapi:spec.yaml', type: 'openapi', before: BEFORE, after: AFTER }];
const ARTIFACTS_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });

function envelope() {
  return {
    spec_version: 'decision-result.v1.1',
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    decision_id: 'dec_fw',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900000).toISOString(),
    fingerprint: ARTIFACTS_FP,
    input_fingerprint: ARTIFACTS_FP,
    operation: 'tool_call',
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function mockClient() {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const resp = { decision: 'ALLOW', decision_result: envelope() };
      lastEnv = resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

describe('freshness teaching — FRESHNESS_REQUIRED names cause and fix', () => {
  it('NOT_CONFIGURED write-style requireFreshness: message names resolvePriorContent and the one-line fix', async () => {
    const o = await guardToolCall(
      {
        toolName: 'Write',
        arguments: { path: 'openapi.yaml', contents: AFTER },
        filesTouched: ['openapi.yaml'],
      },
      async () => 1,
      { client: mockClient(), requireFreshness: true },
      { wiring: 'NOT_CONFIGURED' },
    );
    assert.equal(o.executed, false);
    assert.equal(o.verdict.cause, 'FRESHNESS_REQUIRED');
    const teach = freshnessRefusalTeaching(o);
    assert.ok(teach);
    assert.match(teach, /FRESHNESS_REQUIRED/);
    assert.match(teach, /resolvePriorContent/);
    assert.match(teach, /prior-content resolver not configured/);
    assert.match(teach, /createFsPriorContentResolver/);
    assert.ok(teach.includes(FRESHNESS_RESOLVER_FIX));

    const lg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_f' });
    assert.match(lg.content, /FRESHNESS_REQUIRED/);
    assert.match(lg.content, /resolvePriorContent/);
    assert.match(lg.content, /createFsPriorContentResolver/);

    const oa = bindOpenAIGuardOutcome(o, { tool_call_id: 'tc_f' });
    assert.match(oa.content, /resolvePriorContent/);

    const an = bindAnthropicGuardOutcome(o, { tool_use_id: 'tc_f' });
    assert.match(an.content, /resolvePriorContent/);

    const ge = bindGeminiGuardOutcome(o, { name: 'Write' });
    assert.match(ge.functionResponse.response.gate_message, /resolvePriorContent/);
  });

  it('BLOCK refusal prefix stays byte-identical (no freshness teaching appended)', () => {
    const o = {
      executionAttempted: false,
      executed: false,
      enforced: false,
      verdict: { kind: 'BLOCK', action: 'STOP', envelope: {}, receiptVerified: true },
      preflighted: true,
      proof: { proof_spec: 'guard-execution-proof.v1', limits: {} },
      freshness: { wiring: 'NOT_CONFIGURED', write_style: false, require_freshness: false },
      conditional_write: { conditional_write: 'not_reported', require_conditional_write: false, write_style: false },
      commit_observation: { status: 'not_observed', observed_at: 't', host_attestation: 'absent' },
    };
    const teach = freshnessRefusalTeaching(o);
    assert.equal(teach, null);
    const lg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_b', attachProof: false });
    assert.equal(
      lg.content,
      'CodeRifts gate did not permit execution (verdict: BLOCK). No tool result was produced.',
    );
  });
});

describe('freshness teaching — FRESHNESS_FAILED names measurement fail-closed', () => {
  it('ACTIVE mutated before: message names FRESHNESS_FAILED and re-preflight, not a missing resolver', async () => {
    const o = await guardToolCall(
      {
        toolName: 'Edit',
        arguments: { path: 'spec.yaml', old_string: 'a', new_string: 'b' },
        artifacts: ARTIFACTS,
      },
      async () => 1,
      { client: mockClient() },
      { wiring: 'ACTIVE', priorResolved: { 'openapi:spec.yaml': BEFORE + '\n# moved\n' } },
    );
    assert.equal(o.verdict.cause, 'FRESHNESS_FAILED');
    const teach = freshnessRefusalTeaching(o);
    assert.ok(teach);
    assert.match(teach, /FRESHNESS_FAILED/);
    assert.match(teach, /TARGET_MUTATED|fail-closed/);
    assert.match(teach, /Re-preflight/);
    assert.doesNotMatch(teach, /resolver not configured/);
    const lg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_fail' });
    assert.match(lg.content, /FRESHNESS_FAILED/);
    assert.match(lg.content, /Re-preflight/);
  });
});
