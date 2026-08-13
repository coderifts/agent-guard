'use strict';

/**
 * ID827 phase 2 — bindLangGraphGuardOutcome (Option B; ToolMessage shape).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  bindLangGraphGuardOutcome,
  defaultSerializeLangGraphToolResult,
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
    decision_id: 'dec_lg1',
    receipt: Object.freeze({ verified: true, status: 'VERIFIED_CURRENT', expires_at: '2099-01-01T00:00:00.000Z' }),
    binds_to: Object.freeze({ operation: 'tool_call', change_fp: 'sha256:' + 'c'.repeat(64) }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({ status: 'hashed', algorithm: 'sha256', value: 'd'.repeat(64) }),
    limits: LIMITS,
    ...over,
  });
}

function armAllow() {
  const proof = baseProof();
  return {
    executionAttempted: true, executed: true, enforced: true,
    result: { ok: true, n: 1 },
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
    result: 'lg-skip',
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
    error: new Error('lg factory fail'),
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: {}, receiptVerified: true },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}

function assertShape(msg, tool_call_id, hasName) {
  assert.equal(typeof msg.content, 'string');
  assert.equal(msg.tool_call_id, tool_call_id);
  const keys = Object.keys(msg).sort();
  if (hasName) {
    assert.deepEqual(keys, ['content', 'name', 'tool_call_id']);
  } else {
    assert.deepEqual(keys, ['content', 'tool_call_id']);
  }
}

describe('bindLangGraphGuardOutcome — ID827 phase 2', () => {
  it('defaultSerializeLangGraphToolResult', () => {
    assert.equal(defaultSerializeLangGraphToolResult(9), '9');
    assert.equal(defaultSerializeLangGraphToolResult({ x: 1 }), '{"x":1}');
  });

  it('arm 1 ALLOW-executed + optional name', () => {
    const o = armAllow();
    const msg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_allow', name: 'edit_file' });
    assertShape(msg, 'tc_allow', true);
    assert.equal(msg.name, 'edit_file');
    assert.equal(
      msg.content,
      attachProofToAgentResponse(defaultSerializeLangGraphToolResult(o.result), o.proof),
    );
    assert.match(msg.content, /CodeRifts execution proof/);
  });

  it('arm 2 SKIPPED-executed', () => {
    const o = armSkipped();
    const msg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_skip' });
    assertShape(msg, 'tc_skip', false);
    assert.equal(msg.content, attachProofToAgentResponse('lg-skip', o.proof));
  });

  it('arm 3 BLOCK: no fabricated result', () => {
    const o = armBlock();
    const msg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_block' });
    assertShape(msg, 'tc_block', false);
    assert.match(msg.content, /did not permit execution/i);
    assert.match(msg.content, /verdict: BLOCK/);
    assert.doesNotMatch(msg.content, /^\{"ok"/);
  });

  it('arm 4 APPROVAL', () => {
    const o = armApproval();
    const msg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_appr' });
    assert.match(msg.content, /verdict: APPROVAL/);
    assert.match(msg.content, /No tool result was produced/);
  });

  it('arm 5 error-threw', () => {
    const o = armError();
    const msg = bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_err' });
    assert.match(msg.content, /lg factory fail/);
    assert.match(msg.content, /Tool execution failed/i);
    assert.ok(msg.content.includes(renderFinalAnswerProof(o.proof).trim())
      || msg.content.includes('CodeRifts execution proof'));
  });

  it('pure / non-mutating', () => {
    const o = armAllow();
    const before = JSON.stringify(o);
    bindLangGraphGuardOutcome(o, { tool_call_id: 'tc_pure' });
    assert.equal(JSON.stringify(o), before);
  });
});
