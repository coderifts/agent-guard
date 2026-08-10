'use strict';

/**
 * Present-but-unrecognised execution_action ≠ missing action.
 *
 * The SDK ladder treated an unknown present action as absent and mapped from decision —
 * reinventing permission. The guard ladder halts with EXECUTION_ACTION_UNRECOGNISED.
 * Missing action still maps. Known mismatch keeps DECISION_INCONSISTENT (distinct code).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  readDecision,
  evaluateEnvelope,
  guardToolCall,
  computeBodyHash,
  computeArtifactDigest,
} = require('../dist/cjs/index.js');

const ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0', after: 'openapi: 3.0.1' }];
const TRIGGER = { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS };
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);

const CLOSED = new Set(['CONTINUE', 'CONTINUE_WITH_MONITORING', 'REQUEST_APPROVAL', 'STOP']);

/** Minimal offline subject shape used by the app adapter-acceptance agent-guard subject. */
function agentGuardSubjectShape(response) {
  const rd = readDecision(response);
  const ea = rd.executionAction;
  if (rd.reason === 'EXECUTION_ACTION_UNRECOGNISED') return { outcome: 'halt', reason: rd.reason };
  if (ea !== 'CONTINUE' && ea !== 'CONTINUE_WITH_MONITORING'
      && ea !== 'REQUEST_APPROVAL' && ea !== 'STOP') {
    return { outcome: 'halt', reason: 'not_closed' };
  }
  const envelope = {
    decision: response.decision,
    execution_action: response.execution_action,
    safe_for_agent: response.safe_for_agent,
    analysis_complete: true,
  };
  const gate = evaluateEnvelope(response, envelope, ea, null);
  if (gate.verdict === 'fail-closed') return { outcome: 'halt', reason: gate.cause };
  if (gate.verdict === 'block-strict') {
    return { outcome: gate.decision === 'REQUIRE_APPROVAL' ? 'request_approval' : 'halt' };
  }
  if (gate.kind === 'MONITOR' || ea === 'CONTINUE_WITH_MONITORING') {
    return { outcome: 'proceed_with_monitoring' };
  }
  if (ea === 'CONTINUE' || gate.kind === 'ALLOW') return { outcome: 'proceed' };
  return { outcome: 'halt' };
}

function envelope(o = {}) {
  const { __token, __noReceipt, ...rest } = o;
  const env = {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: 'sha256:' + 'a'.repeat(64), input_fingerprint: 'sha256:' + 'b'.repeat(64),
    analysis_complete: true, artifact_digest: LOCAL_DIGEST, operation: 'tool_call',
    ...rest,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  if (!__noReceipt) env.receipt = { token: __token || 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  return env;
}
function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function client(env) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      return { decision: env.decision, execution_action: env.execution_action, decision_result: env };
    },
    async verifyReceipt() {
      return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) };
    },
  };
}

describe('readDecision — present unknown vs missing action', () => {
  it('unknown PRESENT action + valid decision → EXECUTION_ACTION_UNRECOGNISED (does not map to CONTINUE)', () => {
    const rd = readDecision({
      decision: 'ALLOW',
      safe_for_agent: true,
      execution_action: 'PROCEED_ANYWAY',
    });
    assert.equal(rd.reason, 'EXECUTION_ACTION_UNRECOGNISED');
    assert.equal(rd.executionAction, 'PROCEED_ANYWAY');
    assert.equal(rd.decision, 'ALLOW');
    assert.notEqual(rd.executionAction, 'CONTINUE', 'must not reinvent CONTINUE from decision');
  });

  it('unknown PRESENT action on envelope → same code; envelope retained; no decision map', () => {
    const env = envelope({ execution_action: 'QUARANTINE' });
    const rd = readDecision({ decision: 'ALLOW', execution_action: 'QUARANTINE', decision_result: env });
    assert.equal(rd.reason, 'EXECUTION_ACTION_UNRECOGNISED');
    assert.equal(rd.executionAction, 'QUARANTINE');
    assert.ok(rd.envelope, 'envelope still attached for diagnostics');
    assert.notEqual(rd.executionAction, 'CONTINUE');
  });

  it('MISSING action + decision ALLOW → still maps to CONTINUE (legacy path unchanged)', () => {
    const rd = readDecision({ decision: 'ALLOW' });
    assert.equal(rd.reason, undefined);
    assert.equal(rd.executionAction, 'CONTINUE');
    assert.equal(rd.decision, 'ALLOW');
  });

  it('MISSING action + decision BLOCK → maps to STOP', () => {
    const rd = readDecision({ decision: 'BLOCK' });
    assert.equal(rd.executionAction, 'STOP');
    assert.equal(rd.reason, undefined);
  });

  it('known CONTINUE is returned as-is (no false unrecognised)', () => {
    const rd = readDecision({ decision: 'ALLOW', execution_action: 'CONTINUE' });
    assert.equal(rd.executionAction, 'CONTINUE');
    assert.equal(rd.reason, undefined);
  });
});

describe('evaluateEnvelope — two distinct codes', () => {
  it('unknown action → EXECUTION_ACTION_UNRECOGNISED (not DECISION_INCONSISTENT)', () => {
    const gate = evaluateEnvelope(
      { decision: 'ALLOW', execution_action: 'PROCEED_ANYWAY' },
      { decision: 'ALLOW', execution_action: 'PROCEED_ANYWAY', safe_for_agent: true, analysis_complete: true },
      'PROCEED_ANYWAY',
      null,
    );
    assert.equal(gate.verdict, 'fail-closed');
    assert.equal(gate.cause, 'EXECUTION_ACTION_UNRECOGNISED');
  });

  it('known mismatch ALLOW + STOP → DECISION_INCONSISTENT or block-strict, NOT unrecognised', () => {
    // STOP implies BLOCK → stricter wins → block-strict
    const gate = evaluateEnvelope(
      { decision: 'ALLOW', execution_action: 'STOP' },
      { decision: 'ALLOW', execution_action: 'STOP', safe_for_agent: true, analysis_complete: true },
      'STOP',
      null,
    );
    if (gate.verdict === 'fail-closed') {
      assert.equal(gate.cause, 'DECISION_INCONSISTENT');
      assert.notEqual(gate.cause, 'EXECUTION_ACTION_UNRECOGNISED');
    } else {
      assert.equal(gate.verdict, 'block-strict');
    }
  });

  it('consistent known ALLOW+CONTINUE still allows', () => {
    const gate = evaluateEnvelope(
      { decision: 'ALLOW', execution_action: 'CONTINUE' },
      { decision: 'ALLOW', execution_action: 'CONTINUE', safe_for_agent: true, analysis_complete: true },
      'CONTINUE',
      null,
    );
    assert.equal(gate.verdict, 'allow');
    assert.equal(gate.kind, 'ALLOW');
  });
});

describe('guardToolCall — end-to-end unknown action halts with own code', () => {
  it('envelope execution_action=PROCEED_ANYWAY + decision ALLOW → not executed, EXECUTION_ACTION_UNRECOGNISED', async () => {
    const env = envelope({ execution_action: 'PROCEED_ANYWAY' });
    let executed = false;
    const outcome = await guardToolCall(
      TRIGGER,
      async () => { executed = true; return 'SIDE'; },
      { client: client(env) },
    );
    assert.equal(executed, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.cause, 'EXECUTION_ACTION_UNRECOGNISED');
  });

  it('known mismatch still uses DECISION_INCONSISTENT path (or block), not unrecognised', async () => {
    // ALLOW + STOP with receipt: stricter STOP → block-strict kind BLOCK, or fail-closed
    const env = envelope({ decision: 'ALLOW', execution_action: 'STOP', safe_for_agent: true });
    const outcome = await guardToolCall(
      TRIGGER,
      async () => 'SIDE',
      { client: client(env) },
    );
    assert.equal(outcome.executed, false);
    if (outcome.verdict.kind === 'UNAVAILABLE') {
      assert.notEqual(outcome.verdict.cause, 'EXECUTION_ACTION_UNRECOGNISED');
    } else {
      assert.ok(outcome.verdict.kind === 'BLOCK' || outcome.verdict.kind === 'APPROVAL');
    }
  });
});

describe('AA-UNRECOGNISED-ACTION against agent-guard subject shape', () => {
  it('suite case: ALLOW + PROCEED_ANYWAY → halt (acceptance floor)', () => {
    // Mirrors test/adapter-acceptance/cases.v1.json AA-UNRECOGNISED-ACTION
    const response = {
      decision: 'ALLOW',
      safe_for_agent: true,
      execution_action: 'PROCEED_ANYWAY',
    };
    const result = agentGuardSubjectShape(response);
    assert.equal(result.outcome, 'halt');
    assert.ok(
      result.reason === 'EXECUTION_ACTION_UNRECOGNISED' || result.reason === 'not_closed',
      `expected unrecognised halt, got ${JSON.stringify(result)}`,
    );
    // And the raw read must not expose a closed action invented from decision.
    const rd = readDecision(response);
    assert.ok(!CLOSED.has(rd.executionAction) || rd.reason === 'EXECUTION_ACTION_UNRECOGNISED');
  });
});
