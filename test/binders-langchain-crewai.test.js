'use strict';

/**
 * I-1272 — bindLangChainToolOutcome + bindCrewAIToolOutcome.
 *
 * Mirrors test/langgraph-bind-outcome.test.js: the same five outcome arms, the same
 * assertions, and one extra per binder for the field that is not in the other four —
 * LangChain's `artifact` (proof kept off the model's context) and CrewAI's
 * `result_as_answer` (a refusal is the answer, not an observation to reason around).
 *
 * The invariant that keeps six binders honest: the STRING each one emits is
 * byte-identical to attachProofToAgentResponse over the same outcome. A binder that
 * drifts from that is inventing its own rendering.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  bindLangChainToolOutcome,
  defaultSerializeLangChainToolResult,
  LANGCHAIN_ARTIFACT_SPEC,
  bindCrewAIToolOutcome,
  defaultSerializeCrewAIToolResult,
  bindLangGraphGuardOutcome,
  attachProofToAgentResponse,
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
    decision_id: 'dec_bind1',
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
    result: 'bind-skip',
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
    error: new Error('bind factory fail'),
    verdict: { kind: 'ALLOW', action: 'CONTINUE', envelope: {}, receiptVerified: true },
    preflighted: true, proof, freshness: FRESHNESS, conditional_write: CW,
  };
}

// ── bindLangChainToolOutcome ─────────────────────────────────────────────────
describe('bindLangChainToolOutcome — content_and_artifact', () => {
  it('defaultSerializeLangChainToolResult', () => {
    assert.equal(defaultSerializeLangChainToolResult(9), '9');
    assert.equal(defaultSerializeLangChainToolResult({ x: 1 }), '{"x":1}');
    assert.equal(defaultSerializeLangChainToolResult('s'), 's');
  });

  it('arm 1 ALLOW-executed + optional name', () => {
    const o = armAllow();
    const out = bindLangChainToolOutcome(o, { tool_call_id: 'tc_allow', name: 'edit_file' });
    assert.equal(out.tool_call_id, 'tc_allow');
    assert.equal(out.name, 'edit_file');
    assert.equal(
      out.content,
      attachProofToAgentResponse(defaultSerializeLangChainToolResult(o.result), o.proof),
    );
    assert.match(out.content, /CodeRifts execution proof/);
  });

  it('arm 2 SKIPPED-executed', () => {
    const o = armSkipped();
    const out = bindLangChainToolOutcome(o, { tool_call_id: 'tc_skip' });
    assert.equal(out.content, attachProofToAgentResponse('bind-skip', o.proof));
    assert.ok(!('name' in out), 'name is absent when not supplied');
  });

  it('arm 3 BLOCK: no fabricated result', () => {
    const o = armBlock();
    const out = bindLangChainToolOutcome(o, { tool_call_id: 'tc_block' });
    assert.match(out.content, /did not permit execution/i);
    assert.match(out.content, /verdict: BLOCK/);
    assert.doesNotMatch(out.content, /^\{"ok"/);
    assert.equal(out.artifact.executed, false);
  });

  it('arm 4 APPROVAL', () => {
    const o = armApproval();
    const out = bindLangChainToolOutcome(o, { tool_call_id: 'tc_appr' });
    assert.match(out.content, /verdict: APPROVAL/);
    assert.match(out.content, /No tool result was produced/);
    assert.equal(out.artifact.verdict, 'APPROVAL');
  });

  it('arm 5 error-threw', () => {
    const o = armError();
    const out = bindLangChainToolOutcome(o, { tool_call_id: 'tc_err' });
    assert.match(out.content, /Tool execution failed after gate decision/);
    assert.match(out.content, /bind factory fail/);
    assert.equal(out.artifact.executed, false);
    assert.equal(out.artifact.enforced, true);
  });

  it('THE POINT OF THIS BINDER: the structured proof rides in artifact, not in content', () => {
    const o = armBlock();
    const out = bindLangChainToolOutcome(o, { tool_call_id: 'tc_a', attachProof: false });
    // content is the bare body — nothing of the proof reaches the model
    assert.doesNotMatch(out.content, /CodeRifts execution proof/);
    // and the proof is still there, whole, for the auditor
    assert.equal(out.artifact.artifact_spec, LANGCHAIN_ARTIFACT_SPEC);
    assert.equal(out.artifact.final_answer_proof, o.proof);
    assert.equal(out.artifact.final_answer_proof.proof_spec, EXECUTION_PROOF_SPEC);
  });

  it('the artifact is present on EVERY arm — opting out of proof text never drops it', () => {
    for (const arm of [armAllow, armSkipped, armBlock, armApproval, armError]) {
      const o = arm();
      for (const attachProof of [true, false]) {
        const out = bindLangChainToolOutcome(o, { tool_call_id: 't', attachProof });
        assert.equal(out.artifact.final_answer_proof, o.proof);
        assert.equal(out.artifact.artifact_spec, LANGCHAIN_ARTIFACT_SPEC);
      }
    }
  });

  it('EQUIVALENCE: content matches bindLangGraphGuardOutcome on every arm', () => {
    for (const arm of [armAllow, armSkipped, armBlock, armApproval, armError]) {
      const o = arm();
      const lc = bindLangChainToolOutcome(o, { tool_call_id: 'x' });
      const lg = bindLangGraphGuardOutcome(o, { tool_call_id: 'x' });
      assert.equal(lc.content, lg.content, 'two binders, one rendering');
    }
  });

  it('pure and non-mutating', () => {
    const o = armAllow();
    const before = JSON.stringify(o.proof);
    bindLangChainToolOutcome(o, { tool_call_id: 'x' });
    assert.equal(JSON.stringify(o.proof), before);
  });
});

// ── bindCrewAIToolOutcome ────────────────────────────────────────────────────
describe('bindCrewAIToolOutcome — result + result_as_answer', () => {
  it('defaultSerializeCrewAIToolResult', () => {
    assert.equal(defaultSerializeCrewAIToolResult(9), '9');
    assert.equal(defaultSerializeCrewAIToolResult({ x: 1 }), '{"x":1}');
  });

  it('arm 1 ALLOW-executed: an ordinary observation, the agent keeps working', () => {
    const o = armAllow();
    const out = bindCrewAIToolOutcome(o, { tool_name: 'edit_file' });
    assert.equal(out.tool_name, 'edit_file');
    assert.equal(out.result_as_answer, false);
    assert.equal(
      out.result,
      attachProofToAgentResponse(defaultSerializeCrewAIToolResult(o.result), o.proof),
    );
  });

  it('arm 2 SKIPPED-executed also keeps result_as_answer false', () => {
    const o = armSkipped();
    const out = bindCrewAIToolOutcome(o, { tool_name: 't' });
    assert.equal(out.result_as_answer, false);
    assert.equal(out.result, attachProofToAgentResponse('bind-skip', o.proof));
  });

  it('arm 3 BLOCK: no fabricated result, AND the refusal IS the final answer', () => {
    const o = armBlock();
    const out = bindCrewAIToolOutcome(o, { tool_name: 't' });
    assert.match(out.result, /did not permit execution/i);
    assert.match(out.result, /verdict: BLOCK/);
    assert.doesNotMatch(out.result, /^\{"ok"/);
    assert.equal(out.result_as_answer, true, 'a gate refusal is not an observation to reason around');
  });

  it('arm 4 APPROVAL is also a final answer', () => {
    const o = armApproval();
    const out = bindCrewAIToolOutcome(o, { tool_name: 't' });
    assert.match(out.result, /verdict: APPROVAL/);
    assert.equal(out.result_as_answer, true);
  });

  it('arm 5 error-threw: a failure must not be reasoned into a success', () => {
    const o = armError();
    const out = bindCrewAIToolOutcome(o, { tool_name: 't' });
    assert.match(out.result, /Tool execution failed after gate decision/);
    assert.equal(out.result_as_answer, true);
  });

  it('result_as_answer is TRUE on exactly the arms the guard did not permit', () => {
    const rows = [
      [armAllow, false], [armSkipped, false],
      [armBlock, true], [armApproval, true], [armError, true],
    ];
    for (const [arm, expected] of rows) {
      const o = arm();
      assert.equal(bindCrewAIToolOutcome(o, { tool_name: 't' }).result_as_answer, expected);
    }
  });

  it('the structured proof rides alongside on every arm', () => {
    for (const arm of [armAllow, armSkipped, armBlock, armApproval, armError]) {
      const o = arm();
      for (const attachProof of [true, false]) {
        const out = bindCrewAIToolOutcome(o, { tool_name: 't', attachProof });
        assert.equal(out.final_answer_proof, o.proof);
      }
    }
  });

  it('EQUIVALENCE: result matches bindLangGraphGuardOutcome on every arm', () => {
    for (const arm of [armAllow, armSkipped, armBlock, armApproval, armError]) {
      const o = arm();
      const cw = bindCrewAIToolOutcome(o, { tool_name: 'x' });
      const lg = bindLangGraphGuardOutcome(o, { tool_call_id: 'x' });
      assert.equal(cw.result, lg.content, 'two binders, one rendering');
    }
  });

  it('JSON-serialisable: the Python side receives this as JSON', () => {
    const o = armBlock();
    const out = bindCrewAIToolOutcome(o, { tool_name: 't' });
    const round = JSON.parse(JSON.stringify(out));
    assert.equal(round.result, out.result);
    assert.equal(round.result_as_answer, true);
    assert.equal(round.tool_name, 't');
  });

  it('pure and non-mutating', () => {
    const o = armAllow();
    const before = JSON.stringify(o.proof);
    bindCrewAIToolOutcome(o, { tool_name: 'x' });
    assert.equal(JSON.stringify(o.proof), before);
  });
});
