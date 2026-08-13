'use strict';

/**
 * ID827 phase 2 — bindGeminiGuardOutcome (Option B; structured functionResponse).
 *
 * GEMINI SPECIAL: response is an OBJECT — not a stringified tool blob.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  bindGeminiGuardOutcome,
  defaultSerializeGeminiToolResult,
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
    decision_id: 'dec_g1',
    receipt: Object.freeze({ verified: true, status: 'VERIFIED_CURRENT', expires_at: '2099-01-01T00:00:00.000Z' }),
    binds_to: Object.freeze({ operation: 'tool_call', change_fp: 'sha256:' + 'e'.repeat(64) }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({ status: 'hashed', algorithm: 'sha256', value: 'f'.repeat(64) }),
    limits: LIMITS,
    ...over,
  });
}

function armAllow() {
  const proof = baseProof();
  return {
    executionAttempted: true, executed: true, enforced: true,
    result: { ok: true, value: 99 },
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: {}, receiptVerified: true },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}
function armSkipped() {
  const proof = baseProof({
    preflighted: false, decision_id: null, currently_authorized: null, binds_to: null,
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
    execution: Object.freeze({ attempted: true, executed: true, enforced: false }),
    verdict_kind: 'SKIPPED',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
  });
  return {
    executionAttempted: true, executed: true, enforced: false,
    result: 'gemini-skip',
    verdict: { kind: 'SKIPPED', reason: 'NOT_A_CONTRACT_CALL', signals: [], detectorVersion: 't' },
    preflighted: false, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}
function armBlock() {
  const proof = baseProof({
    currently_authorized: false, verdict_kind: 'BLOCK',
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
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
    currently_authorized: false, verdict_kind: 'APPROVAL',
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
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
    error: new Error('gemini factory fail'),
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: {}, receiptVerified: true },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}

function assertGeminiShape(part, name) {
  assert.equal(typeof part.functionResponse, 'object');
  assert.equal(part.functionResponse.name, name);
  assert.equal(typeof part.functionResponse.response, 'object');
  assert.ok(part.functionResponse.response !== null);
  assert.ok(!Array.isArray(part.functionResponse.response));
  // NOT a string blob
  assert.notEqual(typeof part.functionResponse.response, 'string');
  assert.deepEqual(Object.keys(part).sort(), ['functionResponse']);
  assert.deepEqual(Object.keys(part.functionResponse).sort(), ['name', 'response']);
}

describe('bindGeminiGuardOutcome — ID827 phase 2 (object response)', () => {
  it('defaultSerializeGeminiToolResult keeps structured values', () => {
    assert.deepEqual(defaultSerializeGeminiToolResult({ a: 1 }), { a: 1 });
    assert.equal(defaultSerializeGeminiToolResult('s'), 's');
    assert.equal(defaultSerializeGeminiToolResult(3), 3);
  });

  it('arm 1 ALLOW-executed: response is object with result + proof fields', () => {
    const o = armAllow();
    const part = bindGeminiGuardOutcome(o, { name: 'edit_file' });
    assertGeminiShape(part, 'edit_file');
    const res = part.functionResponse.response;
    assert.ok('result' in res);
    assert.deepEqual(res.result, { ok: true, value: 99 });
    assert.equal(res.final_answer_proof, o.proof);
    assert.equal(typeof res.final_answer_proof_text, 'string');
    assert.match(res.final_answer_proof_text, /CodeRifts execution proof/);
    // Equivalence: attachProofToAgentResponse on { result } yields same proof fields
    const expected = attachProofToAgentResponse({ result: o.result }, o.proof);
    assert.equal(res.final_answer_proof_text, expected.final_answer_proof_text);
    assert.equal(res.final_answer_proof, expected.final_answer_proof);
  });

  it('arm 2 SKIPPED-executed: result present, structured', () => {
    const o = armSkipped();
    const part = bindGeminiGuardOutcome(o, { name: 'read_file' });
    assertGeminiShape(part, 'read_file');
    assert.equal(part.functionResponse.response.result, 'gemini-skip');
    assert.equal(part.functionResponse.response.final_answer_proof, o.proof);
    assert.ok(!('gate_message' in part.functionResponse.response));
  });

  it('arm 3 BLOCK: gate_message, NO result key (no fabrication)', () => {
    const o = armBlock();
    const part = bindGeminiGuardOutcome(o, { name: 'edit_file' });
    assertGeminiShape(part, 'edit_file');
    const res = part.functionResponse.response;
    assert.ok(!('result' in res), 'blocked arm must not fabricate result');
    assert.equal(typeof res.gate_message, 'string');
    assert.match(res.gate_message, /did not permit execution/i);
    assert.match(res.gate_message, /verdict: BLOCK/);
    assert.equal(res.final_answer_proof, o.proof);
    assert.equal(typeof res.final_answer_proof_text, 'string');
  });

  it('arm 4 APPROVAL: gate_message, no result', () => {
    const o = armApproval();
    const part = bindGeminiGuardOutcome(o, { name: 'deploy' });
    const res = part.functionResponse.response;
    assert.ok(!('result' in res));
    assert.match(res.gate_message, /verdict: APPROVAL/);
    assert.equal(res.final_answer_proof, o.proof);
  });

  it('arm 5 error-threw: gate_message with error, proof present, no result', () => {
    const o = armError();
    const part = bindGeminiGuardOutcome(o, { name: 'edit_file' });
    const res = part.functionResponse.response;
    assert.ok(!('result' in res));
    assert.match(res.gate_message, /gemini factory fail/);
    assert.match(res.gate_message, /Tool execution failed/i);
    assert.equal(res.final_answer_proof, o.proof);
    assert.match(res.final_answer_proof_text, /CodeRifts execution proof/);
  });

  it('custom serialize override projects into result field', () => {
    const o = armAllow();
    const part = bindGeminiGuardOutcome(o, {
      name: 'edit_file',
      serialize: (r) => ({ custom: r.value }),
    });
    assert.deepEqual(part.functionResponse.response.result, { custom: 99 });
  });

  it('pure / non-mutating', () => {
    const o = armAllow();
    const before = JSON.stringify(o);
    bindGeminiGuardOutcome(o, { name: 'edit_file' });
    assert.equal(JSON.stringify(o), before);
  });

  it('proof text matches renderFinalAnswerProof', () => {
    const o = armAllow();
    const part = bindGeminiGuardOutcome(o, { name: 'edit_file' });
    assert.equal(
      part.functionResponse.response.final_answer_proof_text,
      renderFinalAnswerProof(o.proof),
    );
  });
});
