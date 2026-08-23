'use strict';

/**
 * ID827 phase 2 — bindAnthropicGuardOutcome (Option B; Anthropic tool_result).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  bindAnthropicGuardOutcome,
  defaultSerializeAnthropicToolResult,
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
    decision_id: 'dec_a1',
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
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: { decision_id: 'dec_a1' }, receiptVerified: true },
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

function assertShape(msg, tool_use_id) {
  assert.equal(msg.type, 'tool_result');
  assert.equal(msg.tool_use_id, tool_use_id);
  assert.equal(typeof msg.content, 'string');
  assert.deepEqual(Object.keys(msg).sort(), ['content', 'tool_use_id', 'type']);
}

describe('bindAnthropicGuardOutcome — ID827 phase 2', () => {
  it('defaultSerializeAnthropicToolResult mirrors OpenAI defaults', () => {
    assert.equal(defaultSerializeAnthropicToolResult('x'), 'x');
    assert.equal(defaultSerializeAnthropicToolResult({ a: 1 }), '{"a":1}');
  });

  it('arm 1 ALLOW-executed: equivalence to attachProofToAgentResponse', () => {
    const o = armAllow();
    const msg = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_allow' });
    assertShape(msg, 'tu_allow');
    const expected = attachProofToAgentResponse(
      defaultSerializeAnthropicToolResult(o.result),
      o.proof,
    );
    assert.equal(msg.content, expected);
    assert.match(msg.content, /CodeRifts execution proof/);
  });

  it('arm 2 SKIPPED-executed', () => {
    const o = armSkipped();
    const msg = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_skip' });
    assertShape(msg, 'tu_skip');
    assert.ok(msg.content.startsWith('skip-ok'));
    assert.equal(msg.content, attachProofToAgentResponse('skip-ok', o.proof));
  });

  it('arm 3 BLOCK: no fabricated result', () => {
    const o = armBlock();
    const msg = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_block' });
    assertShape(msg, 'tu_block');
    assert.match(msg.content, /did not permit execution/i);
    assert.match(msg.content, /verdict: BLOCK/);
    assert.doesNotMatch(msg.content, /^\{"ok"/);
    const body =
      'CodeRifts gate did not permit execution (verdict: BLOCK). '
      + 'No tool result was produced.';
    assert.equal(msg.content, attachProofToAgentResponse(body, o.proof));
  });

  it('arm 4 APPROVAL: no result key fabrication', () => {
    const o = armApproval();
    const msg = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_appr' });
    assertShape(msg, 'tu_appr');
    assert.match(msg.content, /verdict: APPROVAL/);
    assert.match(msg.content, /did not permit execution/i);
  });

  it('arm 5 error-threw', () => {
    const o = armError();
    const msg = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_err' });
    assertShape(msg, 'tu_err');
    assert.match(msg.content, /factory boom/);
    assert.match(msg.content, /Tool execution failed/i);
    assert.match(msg.content, /CodeRifts execution proof/);
  });

  it('pure / non-mutating', () => {
    const o = armAllow();
    const before = JSON.stringify(o);
    bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_pure' });
    assert.equal(JSON.stringify(o), before);
  });

  it('S4: default attaches proof; attachProof:false suppresses', () => {
    const o = armAllow();
    const def = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_def' });
    assert.match(def.content, /CodeRifts execution proof/);
    const off = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_off', attachProof: false });
    assert.equal(off.content, defaultSerializeAnthropicToolResult(o.result));
    assert.ok(!/CodeRifts execution proof/.test(off.content));
  });

  it('rendered proof text present (renderFinalAnswerProof reuse)', () => {
    const o = armAllow();
    const msg = bindAnthropicGuardOutcome(o, { tool_use_id: 'tu_r' });
    const rendered = renderFinalAnswerProof(o.proof);
    assert.ok(msg.content.includes(rendered.trim()) || msg.content.includes('CodeRifts execution proof'));
  });
});
