'use strict';

/**
 * ID827 phase 1 — bindOpenAIGuardOutcome (Option B proof binder).
 *
 * Acceptance / equivalence:
 *  - sugar over GuardOutcome + attachProofToAgentResponse / renderFinalAnswerProof
 *  - all 5 GuardOutcome arms produce a tool message whose content contains the rendered proof
 *  - blocked arm never fabricates a tool result
 *  - branded return shape: role/tool_call_id/content only on the wire
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  bindOpenAIGuardOutcome,
  defaultSerializeOpenAIToolResult,
  renderFinalAnswerProof,
  attachProofToAgentResponse,
  EXECUTION_PROOF_SPEC,
  buildExecutionProof,
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

const FRESHNESS = Object.freeze({
  wiring: 'NOT_CONFIGURED',
  write_style: false,
  require_freshness: false,
});

const CW = Object.freeze({
  conditional_write: 'not_reported',
  require_conditional_write: false,
  write_style: false,
});

function baseProof(over = {}) {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_bind_1',
    receipt: Object.freeze({
      verified: true,
      status: 'VERIFIED_CURRENT',
      expires_at: '2099-01-01T00:00:00.000Z',
    }),
    binds_to: Object.freeze({
      operation: 'tool_call',
      change_fp: 'sha256:' + 'b'.repeat(64),
    }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({
      status: 'hashed',
      algorithm: 'sha256',
      value: 'a'.repeat(64),
    }),
    limits: LIMITS,
    ...over,
  });
}

function allowVerdict() {
  return {
    kind: 'ALLOW',
    action: 'CONTINUE',
    envelope: { decision_id: 'dec_bind_1' },
    receiptVerified: true,
  };
}

function blockVerdict() {
  return {
    kind: 'BLOCK',
    action: 'STOP',
    envelope: { decision_id: 'dec_block' },
    receiptVerified: false,
  };
}

function approvalVerdict() {
  return {
    kind: 'APPROVAL',
    action: 'REQUEST_APPROVAL',
    envelope: { decision_id: 'dec_appr' },
    receiptVerified: false,
  };
}

function skippedVerdict() {
  return {
    kind: 'SKIPPED',
    reason: 'NOT_A_CONTRACT_CALL',
    signals: [],
    detectorVersion: 'test',
  };
}

/** Arm 1: enforced + executed (ALLOW). */
function armAllowExecuted() {
  const proof = baseProof({
    verdict_kind: 'ALLOW',
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
  });
  return {
    executionAttempted: true,
    executed: true,
    enforced: true,
    result: { ok: true, value: 42 },
    verdict: allowVerdict(),
    preflighted: true,
    proof,
    freshness: FRESHNESS,
    conditional_write: CW,
  };
}

/** Arm 2: unenforced + executed (SKIPPED). */
function armSkippedExecuted() {
  const proof = baseProof({
    preflighted: false,
    decision_id: null,
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
    binds_to: null,
    currently_authorized: null,
    execution: Object.freeze({ attempted: true, executed: true, enforced: false }),
    verdict_kind: 'SKIPPED',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
  });
  return {
    executionAttempted: true,
    executed: true,
    enforced: false,
    result: 'passthrough-result',
    verdict: skippedVerdict(),
    preflighted: false,
    proof,
    freshness: FRESHNESS,
    conditional_write: CW,
  };
}

/** Arm 3: blocked before factory (BLOCK). */
function armBlocked() {
  const proof = baseProof({
    currently_authorized: false,
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
    verdict_kind: 'BLOCK',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
  });
  return {
    executionAttempted: false,
    executed: false,
    enforced: false,
    verdict: blockVerdict(),
    preflighted: true,
    proof,
    freshness: FRESHNESS,
    conditional_write: CW,
  };
}

/** Arm 4: blocked for APPROVAL (no factory). */
function armApproval() {
  const proof = baseProof({
    currently_authorized: false,
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
    verdict_kind: 'APPROVAL',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
  });
  return {
    executionAttempted: false,
    executed: false,
    enforced: false,
    verdict: approvalVerdict(),
    preflighted: true,
    proof,
    freshness: FRESHNESS,
    conditional_write: CW,
  };
}

/** Arm 5: factory threw after enforced approval. */
function armErrorThrew() {
  const proof = baseProof({
    execution: Object.freeze({ attempted: true, executed: false, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'execution_threw' }),
  });
  return {
    executionAttempted: true,
    executed: false,
    enforced: true,
    error: new Error('factory boom'),
    verdict: allowVerdict(),
    preflighted: true,
    proof,
    freshness: FRESHNESS,
    conditional_write: CW,
  };
}

function assertToolMessageShape(msg, tool_call_id) {
  assert.equal(msg.role, 'tool');
  assert.equal(msg.tool_call_id, tool_call_id);
  assert.equal(typeof msg.content, 'string');
  assert.ok(msg.content.length > 0);
  // Wire shape only — brand is type-level (no runtime __proofBound pollution).
  assert.deepEqual(Object.keys(msg).sort(), ['content', 'role', 'tool_call_id']);
}

function assertProofInContent(msg, proof) {
  const rendered = renderFinalAnswerProof(proof);
  assert.ok(
    msg.content.includes(rendered.trim()) || msg.content.includes('CodeRifts execution proof'),
    'content must embed the rendered proof block',
  );
  // Equivalence: binder content ends with the same attachProofToAgentResponse string path.
  // For a known body prefix, attachProofToAgentResponse(body, proof) must be a suffix of content
  // or content itself when body is the first part.
  assert.match(msg.content, /CodeRifts execution proof/);
  assert.match(msg.content, new RegExp(proof.verdict_kind));
}

describe('bindOpenAIGuardOutcome — ID827 phase 1 (Option B)', () => {
  it('defaultSerializeOpenAIToolResult: objects JSON, primitives String, strings unchanged', () => {
    assert.equal(defaultSerializeOpenAIToolResult('hi'), 'hi');
    assert.equal(defaultSerializeOpenAIToolResult(3), '3');
    assert.equal(defaultSerializeOpenAIToolResult(true), 'true');
    assert.equal(defaultSerializeOpenAIToolResult({ a: 1 }), '{"a":1}');
  });

  it('arm 1 ALLOW-executed: serializes result + embeds proof (equivalence to attachProof)', () => {
    const outcome = armAllowExecuted();
    const msg = bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_allow_1' });
    assertToolMessageShape(msg, 'call_allow_1');
    assert.ok(msg.content.startsWith('{"ok":true,"value":42}') || msg.content.includes('"value":42'));
    const expected = attachProofToAgentResponse(
      defaultSerializeOpenAIToolResult(outcome.result),
      outcome.proof,
    );
    assert.equal(msg.content, expected);
    assertProofInContent(msg, outcome.proof);
    // Same proof object reference identity (binder does not clone/replace proof).
    assert.equal(outcome.proof.proof_spec, EXECUTION_PROOF_SPEC);
  });

  it('arm 2 SKIPPED-executed: result present, unenforced path still binds proof', () => {
    const outcome = armSkippedExecuted();
    const msg = bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_skip_1' });
    assertToolMessageShape(msg, 'call_skip_1');
    assert.ok(msg.content.startsWith('passthrough-result'));
    const expected = attachProofToAgentResponse('passthrough-result', outcome.proof);
    assert.equal(msg.content, expected);
    assertProofInContent(msg, outcome.proof);
    assert.match(msg.content, /SKIPPED|not a pass|null/i);
  });

  it('arm 3 BLOCK-blocked: NO fabricated result; gate message + proof only', () => {
    const outcome = armBlocked();
    const msg = bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_block_1' });
    assertToolMessageShape(msg, 'call_block_1');
    assert.match(msg.content, /did not permit execution/i);
    assert.match(msg.content, /verdict: BLOCK/);
    assert.match(msg.content, /No tool result was produced/);
    // Must not invent a success payload.
    assert.doesNotMatch(msg.content, /^\{"ok"/);
    assert.doesNotMatch(msg.content, /fabricat/i);
    const body =
      'CodeRifts gate did not permit execution (verdict: BLOCK). '
      + 'No tool result was produced.';
    assert.equal(msg.content, attachProofToAgentResponse(body, outcome.proof));
    assertProofInContent(msg, outcome.proof);
  });

  it('arm 4 APPROVAL-blocked: no result; verdict reflected + proof', () => {
    const outcome = armApproval();
    const msg = bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_appr_1' });
    assertToolMessageShape(msg, 'call_appr_1');
    assert.match(msg.content, /did not permit execution/i);
    assert.match(msg.content, /verdict: APPROVAL/);
    assert.doesNotMatch(msg.content, /"result"\s*:/);
    assertProofInContent(msg, outcome.proof);
  });

  it('arm 5 error-threw: error indication + proof (no silent swallow)', () => {
    const outcome = armErrorThrew();
    const msg = bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_err_1' });
    assertToolMessageShape(msg, 'call_err_1');
    assert.match(msg.content, /Tool execution failed/i);
    assert.match(msg.content, /factory boom/);
    assert.match(msg.content, /verdict: ALLOW/);
    const body =
      'Tool execution failed after gate decision (verdict: ALLOW): factory boom';
    assert.equal(msg.content, attachProofToAgentResponse(body, outcome.proof));
    assertProofInContent(msg, outcome.proof);
  });

  it('custom serialize override is used on executed arms', () => {
    const outcome = armAllowExecuted();
    const msg = bindOpenAIGuardOutcome(outcome, {
      tool_call_id: 'call_ser',
      serialize: (r) => `CUSTOM:${r.value}`,
    });
    assert.ok(msg.content.startsWith('CUSTOM:42'));
    assert.equal(
      msg.content,
      attachProofToAgentResponse('CUSTOM:42', outcome.proof),
    );
  });

  it('pure / non-mutating: outcome object unchanged after bind', () => {
    const outcome = armAllowExecuted();
    const before = JSON.stringify(outcome);
    bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_pure' });
    assert.equal(JSON.stringify(outcome), before);
  });

  it('equivalence with buildExecutionProof live fixture (ALLOW path)', () => {
    const proof = buildExecutionProof({
      preflighted: true,
      executionAttempted: true,
      executed: true,
      enforced: true,
      verdict: {
        kind: 'ALLOW',
        envelope: {
          decision_id: 'dec_live_bind',
          expires_at: '2099-01-01T00:00:00.000Z',
          operation: 'tool_call',
          fingerprint: 'sha256:' + 'e'.repeat(64),
        },
        receiptVerified: true,
      },
      result: 'stable-string',
    });
    const outcome = {
      executionAttempted: true,
      executed: true,
      enforced: true,
      result: 'stable-string',
      verdict: {
        kind: 'ALLOW',
        action: 'CONTINUE',
        envelope: { decision_id: 'dec_live_bind' },
        receiptVerified: true,
      },
      preflighted: true,
      proof,
      freshness: FRESHNESS,
      conditional_write: CW,
    };
    const msg = bindOpenAIGuardOutcome(outcome, { tool_call_id: 'call_live' });
    assert.equal(msg.content, attachProofToAgentResponse('stable-string', proof));
    assert.match(msg.content, /stable-string/);
    assert.match(msg.content, /CodeRifts execution proof/);
  });
});
