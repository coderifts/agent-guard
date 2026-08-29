'use strict';

/**
 * Roadmap 129 — bindVercelGuardOutcome (Option B; Vercel tool-result part).
 * Same arms as bindOpenAIGuardOutcome; id field is toolCallId.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  bindVercelGuardOutcome,
  defaultSerializeVercelToolResult,
  attachProofToAgentResponse,
  renderFinalAnswerProof,
  EXECUTION_PROOF_SPEC,
} = require('../dist/cjs/index.js');

const LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
  conditional_write_is_host_asserted_not_cas_verified: true,
});
const FRESHNESS = Object.freeze({ wiring: 'NOT_CONFIGURED', write_style: false, require_freshness: false });
const CW = Object.freeze({ conditional_write: 'not_reported', require_conditional_write: false, write_style: false });

function baseProof(over = {}) {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_v1',
    receipt: Object.freeze({ verified: true, status: 'VERIFIED_CURRENT', expires_at: '2099-01-01T00:00:00.000Z' }),
    binds_to: Object.freeze({ operation: 'tool_call', change_fp: 'sha256:' + 'b'.repeat(64) }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({ status: 'hashed', algorithm: 'sha256', value: 'a'.repeat(64) }),
    limits: LIMITS,
    ...over,
  });
}

function armAllow() {
  const proof = baseProof();
  return {
    executionAttempted: true, executed: true, enforced: true,
    result: { ok: true, value: 7 },
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: { decision_id: 'dec_v1' }, receiptVerified: true },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}
function armSkipped() {
  const proof = baseProof({
    preflighted: false, decision_id: null,
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
    binds_to: null, currently_authorized: null,
    execution: Object.freeze({ attempted: true, executed: true, enforced: false }),
    verdict_kind: 'SKIPPED',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
  });
  return {
    executionAttempted: true, executed: true, enforced: false,
    result: 'skip-ok',
    verdict: { kind: 'SKIPPED', reason: 'NOT_A_CONTRACT_CALL', signals: [], detectorVersion: 't' },
    preflighted: false, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}
function armBlock() {
  const proof = baseProof({
    currently_authorized: false,
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
    verdict_kind: 'BLOCK',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
  });
  return {
    executionAttempted: false, executed: false, enforced: false,
    verdict: { kind: 'BLOCK', action: 'STOP', envelope: {}, receiptVerified: false },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}
function armApproval() {
  const proof = baseProof({
    currently_authorized: false,
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
    verdict_kind: 'APPROVAL',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
  });
  return {
    executionAttempted: false, executed: false, enforced: false,
    verdict: { kind: 'APPROVAL', action: 'REQUEST_APPROVAL', envelope: {}, receiptVerified: false },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}
function armError() {
  const proof = baseProof({
    execution: Object.freeze({ attempted: true, executed: false, enforced: true }),
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'execution_threw' }),
  });
  return {
    executionAttempted: true, executed: false, enforced: true,
    error: new Error('factory boom'),
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: {}, receiptVerified: true },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}

function assertShape(msg, toolCallId, hasName) {
  assert.equal(msg.type, 'tool-result');
  assert.equal(msg.toolCallId, toolCallId);
  assert.equal(typeof msg.result, 'string');
  const keys = Object.keys(msg).sort();
  if (hasName) {
    assert.deepEqual(keys, ['result', 'toolCallId', 'toolName', 'type']);
  } else {
    assert.deepEqual(keys, ['result', 'toolCallId', 'type']);
  }
}

describe('bindVercelGuardOutcome — roadmap 129', () => {
  it('defaultSerializeVercelToolResult mirrors OpenAI defaults', () => {
    assert.equal(defaultSerializeVercelToolResult('x'), 'x');
    assert.equal(defaultSerializeVercelToolResult({ a: 1 }), '{"a":1}');
  });

  it('arm 1 ALLOW-executed: equivalence to attachProofToAgentResponse', () => {
    const o = armAllow();
    const msg = bindVercelGuardOutcome(o, { toolCallId: 'tc_allow', toolName: 'apply_openapi' });
    assertShape(msg, 'tc_allow', true);
    assert.equal(msg.toolName, 'apply_openapi');
    const expected = attachProofToAgentResponse(
      defaultSerializeVercelToolResult(o.result),
      o.proof,
    );
    assert.equal(msg.result, expected);
    assert.match(msg.result, /CodeRifts execution proof/);
  });

  it('arm 2 SKIPPED-executed', () => {
    const o = armSkipped();
    const msg = bindVercelGuardOutcome(o, { toolCallId: 'tc_skip' });
    assertShape(msg, 'tc_skip', false);
    assert.ok(msg.result.startsWith('skip-ok'));
    assert.equal(msg.result, attachProofToAgentResponse('skip-ok', o.proof));
  });

  it('arm 3 BLOCK: no fabricated result', () => {
    const o = armBlock();
    const msg = bindVercelGuardOutcome(o, { toolCallId: 'tc_block' });
    assertShape(msg, 'tc_block', false);
    assert.match(msg.result, /did not permit execution/i);
    assert.match(msg.result, /verdict: BLOCK/);
    assert.doesNotMatch(msg.result, /^\{"ok"/);
    const body =
      'CodeRifts gate did not permit execution (verdict: BLOCK). '
      + 'No tool result was produced.';
    assert.equal(msg.result, attachProofToAgentResponse(body, o.proof));
  });

  it('arm 4 APPROVAL: no result key fabrication', () => {
    const o = armApproval();
    const msg = bindVercelGuardOutcome(o, { toolCallId: 'tc_appr' });
    assertShape(msg, 'tc_appr', false);
    assert.match(msg.result, /verdict: APPROVAL/);
    assert.match(msg.result, /did not permit execution/i);
  });

  it('arm 5 error-threw', () => {
    const o = armError();
    const msg = bindVercelGuardOutcome(o, { toolCallId: 'tc_err' });
    assertShape(msg, 'tc_err', false);
    assert.match(msg.result, /factory boom/);
    assert.match(msg.result, /Tool execution failed/i);
    assert.match(msg.result, /CodeRifts execution proof/);
  });

  it('pure / non-mutating', () => {
    const o = armAllow();
    const before = JSON.stringify(o);
    bindVercelGuardOutcome(o, { toolCallId: 'tc_pure' });
    assert.equal(JSON.stringify(o), before);
  });

  it('S4: default attaches proof; attachProof:false suppresses', () => {
    const o = armAllow();
    const def = bindVercelGuardOutcome(o, { toolCallId: 'tc_def' });
    assert.match(def.result, /CodeRifts execution proof/);
    const off = bindVercelGuardOutcome(o, { toolCallId: 'tc_off', attachProof: false });
    assert.equal(off.result, defaultSerializeVercelToolResult(o.result));
    assert.ok(!/CodeRifts execution proof/.test(off.result));
  });

  it('rendered proof text present (renderFinalAnswerProof reuse)', () => {
    const o = armAllow();
    const msg = bindVercelGuardOutcome(o, { toolCallId: 'tc_r' });
    const rendered = renderFinalAnswerProof(o.proof);
    assert.ok(msg.result.includes(rendered.trim()) || msg.result.includes('CodeRifts execution proof'));
  });
});
