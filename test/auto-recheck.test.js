/**
 * S6 auto-recheck loop — BLOCK + remediation_transaction → host applyFix → re-preflight.
 * Frozen guardToolCall is unchanged; wrap layer + withCodeRifts opt-in.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  withCodeRifts,
  guardToolCall,
  runAutoRecheckLoop,
  clampMaxAttempts,
  AUTO_RECHECK_MAX_CAP,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  renderFinalAnswerProof,
  EXECUTION_PROOF_SPEC,
  resolveArtifacts,
} = require('../dist/cjs/index.js');

const ART_BLOCK = [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0\npaths: {}', after: 'openapi: 3.0.0\npaths: { /x: { get: {} } }' }];
const ART_FIXED = [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0\npaths: {}', after: 'openapi: 3.0.0\npaths: { /x: { get: { responses: { "200": { description: ok } } } } }' }];
const OP = 'tool_call';
const FP_BLOCK = computeCanonicalBundleFingerprint(ART_BLOCK, { operation: OP });
const FP_FIXED = computeCanonicalBundleFingerprint(ART_FIXED, { operation: OP });
assert.notEqual(FP_BLOCK, FP_FIXED);

function signedFor(env) {
  return { fp: env.fingerprint, bh: computeBodyHash(env) };
}

function envelope(execution_action, decision, opts = {}) {
  const env = {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: opts.decision_id || 'dec_1',
    correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    fingerprint: opts.fingerprint,
    input_fingerprint: opts.fingerprint,
    safe_for_agent: decision === 'ALLOW' || decision === 'WARN',
    analysis_complete: true,
    operation: OP,
    receipt: { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' },
  };
  if (decision === 'BLOCK') {
    env.remediation_transaction = opts.tx || {
      required_changes: [{ code: 'add_response' }],
      resubmission: {
        reference_fingerprint: opts.fingerprint,
        fingerprint_profile: 'crbundle.v1',
        modified_is_not_permission: true,
      },
      next_preflight_required: true,
      recheck_scope: { targets: ['/x'], precise: true },
      escalation: { path: 'human_review', when: 'changes_infeasible_or_disputed' },
    };
  }
  return env;
}

function seqClient(responses) {
  let i = 0;
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) {
      return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
    },
    async preflightChangeSet() {
      const resp = responses[Math.min(i, responses.length - 1)]();
      i += 1;
      lastEnv = resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv
        ? { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(lastEnv) }
        : { valid: true, status: 'VERIFIED_CURRENT' };
    },
    get calls() { return i; },
  };
}

function blockResp(id, fp) {
  const env = envelope('STOP', 'BLOCK', { decision_id: id, fingerprint: fp });
  return { decision: 'BLOCK', execution_action: 'STOP', decision_result: env };
}
function allowResp(id, fp) {
  const env = envelope('CONTINUE', 'ALLOW', { decision_id: id, fingerprint: fp });
  return { decision: 'ALLOW', execution_action: 'CONTINUE', decision_result: env };
}

describe('clampMaxAttempts', () => {
  it('hard cap 3; below 1 disables', () => {
    assert.equal(AUTO_RECHECK_MAX_CAP, 3);
    assert.equal(clampMaxAttempts(2), 2);
    assert.equal(clampMaxAttempts(99), 3);
    assert.equal(clampMaxAttempts(0), 0);
    assert.equal(clampMaxAttempts(-1), 0);
  });
});

describe('S6 auto-recheck', () => {
  it('BLOCK→applyFix→ALLOW: trail 2 entries, factory runs on final ALLOW, fixed_after_block fed', async () => {
    const client = seqClient([
      () => blockResp('dec_block', FP_BLOCK),
      () => allowResp('dec_allow', FP_FIXED),
    ]);
    let factoryRan = 0;
    const events = [];
    let applyCalls = 0;
    const { tools } = withCodeRifts({
      tools: [{
        name: 'edit_file',
        mutationClass: 'mutating',
        execute: async () => { factoryRan += 1; return 'ok'; },
      }],
      client,
      operation: OP,
      onEvent: (e) => events.push(e),
      autoRecheck: {
        maxAttempts: 2,
        applyFix: async (_tx, ctx) => {
          applyCalls += 1;
          ctx.call.artifacts = ART_FIXED;
          return true;
        },
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(applyCalls, 1);
    assert.equal(factoryRan, 1, 'factory runs on the final ALLOW, not the BLOCK');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.verdict.kind, 'ALLOW');
    assert.equal(outcome.verdict.envelope.decision_id, 'dec_allow');
    assert.ok(Array.isArray(outcome.recheck_trail));
    assert.equal(outcome.recheck_trail.length, 2);
    assert.equal(outcome.recheck_trail[0].decision_id, 'dec_block');
    assert.equal(outcome.recheck_trail[0].execution_action, 'STOP');
    assert.equal(outcome.recheck_trail[1].decision_id, 'dec_allow');
    assert.equal(outcome.recheck_trail[1].execution_action, 'CONTINUE');
    assert.equal(outcome.fixed_after_block.value, true);
    assert.equal(outcome.fixed_after_block.attempt_count, 1);
    assert.deepEqual(outcome.proof.recheck_trail, outcome.recheck_trail);
    assert.ok(events.some((e) => e.type === 'recheck_attempt' && e.attempt === 1));
    assert.equal(client.calls, 2);
  });

  it('applyFix false → original BLOCK; factory never runs', async () => {
    const client = seqClient([() => blockResp('dec_block', FP_BLOCK)]);
    let factoryRan = 0;
    const { tools } = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => { factoryRan += 1; return 'x'; } }],
      client,
      operation: OP,
      autoRecheck: {
        maxAttempts: 2,
        applyFix: async () => false,
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(factoryRan, 0);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.kind, 'BLOCK');
    assert.equal(outcome.verdict.envelope.decision_id, 'dec_block');
    assert.equal(outcome.recheck_stop_reason, 'apply_fix_declined');
    assert.equal(client.calls, 1, 'no re-preflight when applyFix is false');
  });

  it('attempts exhausted stays BLOCK', async () => {
    const client = seqClient([
      () => blockResp('dec_b1', FP_BLOCK),
      () => blockResp('dec_b2', FP_FIXED),
    ]);
    const { tools } = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'x' }],
      client,
      operation: OP,
      autoRecheck: {
        maxAttempts: 1,
        applyFix: async (_tx, ctx) => {
          ctx.call.artifacts = ART_FIXED;
          return true;
        },
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.kind, 'BLOCK');
    assert.equal(outcome.recheck_trail.length, 2);
    assert.equal(outcome.recheck_stop_reason, 'exhausted');
    assert.equal(outcome.fixed_after_block.value, null);
    assert.equal(client.calls, 2);
  });

  it('no-progress stop: same fingerprint twice', async () => {
    const client = seqClient([
      () => blockResp('dec_b1', FP_BLOCK),
      () => blockResp('dec_b2', FP_BLOCK),
    ]);
    const { tools } = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'x' }],
      client,
      operation: OP,
      autoRecheck: {
        maxAttempts: 2,
        applyFix: async () => true,
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(outcome.executed, false);
    assert.equal(outcome.recheck_stop_reason, 'no_progress');
    assert.equal(outcome.recheck_trail.length, 2);
    assert.equal(outcome.recheck_trail[0].fingerprint, outcome.recheck_trail[1].fingerprint);
    assert.equal(client.calls, 2, 'stops after the duplicate fp; no third preflight');
  });

  it('applyFix throw is isolated; original BLOCK stands', async () => {
    const client = seqClient([() => blockResp('dec_block', FP_BLOCK)]);
    const { tools } = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'x' }],
      client,
      operation: OP,
      autoRecheck: {
        maxAttempts: 2,
        applyFix: async () => { throw new Error('host boom'); },
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.kind, 'BLOCK');
    assert.equal(outcome.verdict.envelope.decision_id, 'dec_block');
    assert.equal(outcome.recheck_stop_reason, 'apply_fix_threw');
    assert.equal(client.calls, 1);
  });

  it('default OFF: no extra preflight, no trail, no behaviour change', async () => {
    const client = seqClient([() => blockResp('dec_block', FP_BLOCK)]);
    const { tools } = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'x' }],
      client,
      operation: OP,
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(outcome.verdict.kind, 'BLOCK');
    assert.equal(outcome.recheck_trail, undefined);
    assert.equal(outcome.fixed_after_block, undefined);
    assert.equal(client.calls, 1);
  });

  it('proof line renders re-preflighted N× after remediation', () => {
    const text = renderFinalAnswerProof({
      proof_spec: EXECUTION_PROOF_SPEC,
      preflighted: true,
      decision_id: 'dec_allow',
      receipt: { verified: true, status: 'VERIFIED_CURRENT', expires_at: '2099-01-01T00:00:00Z' },
      binds_to: { operation: OP, change_fp: FP_FIXED },
      currently_authorized: true,
      execution: { attempted: true, executed: true, enforced: true },
      verdict_kind: 'ALLOW',
      execution_result_hash: { status: 'not_hashed', reason: 'not_executed' },
      limits: {
        does_not_claim_change_safe: true,
        does_not_claim_host_cannot_bypass: true,
        does_not_claim_absent_field_is_compliance: true,
        change_fp_is_what_was_checked_not_what_executed: true,
        calls_outside_guarded_path_invisible: true,
        execution_result_hash_is_not_artifact_match_proof: true,
        conditional_write_is_host_asserted_not_cas_verified: true,
        commit_observation_is_observed_at_t3_not_atomic: true,
      },
      commit_observation: { status: 'not_observed', observed_at: '', host_attestation: 'absent' },
      recheck_trail: [
        { attempt: 0, decision_id: 'dec_block', fingerprint: FP_BLOCK, execution_action: 'STOP' },
        { attempt: 1, decision_id: 'dec_allow', fingerprint: FP_FIXED, execution_action: 'CONTINUE' },
      ],
    });
    assert.match(text, /re-preflighted 1× after remediation; final decision dec_allow/);
  });

  it('determinism: bundle fingerprint preimage untouched (same artifacts → same fp before/after loop module load)', () => {
    const again = computeCanonicalBundleFingerprint(ART_BLOCK, { operation: OP });
    assert.equal(again, FP_BLOCK);
    assert.equal(computeCanonicalBundleFingerprint(ART_FIXED, { operation: OP }), FP_FIXED);
  });

  it('runAutoRecheckLoop without autoRecheck equals a single guardToolCall', async () => {
    const client = seqClient([() => blockResp('dec_block', FP_BLOCK)]);
    const call = { toolName: 'Edit', arguments: {}, artifacts: ART_BLOCK };
    const factory = async () => 'nope';
    const config = { client, operation: OP };
    const a = await guardToolCall(call, factory, config);
    const b = await runAutoRecheckLoop({
      call,
      factory,
      config,
      rebind: () => call,
    });
    assert.equal(a.verdict.kind, b.verdict.kind);
    assert.equal(a.executed, b.executed);
    assert.equal(b.recheck_trail, undefined);
  });

  it('execute receives host-fixed artifacts, not the BLOCK-era args', async () => {
    const client = seqClient([
      () => blockResp('dec_block', FP_BLOCK),
      () => allowResp('dec_allow', FP_FIXED),
    ]);
    let seenArgs = null;
    const { tools } = withCodeRifts({
      tools: [{
        name: 'edit_file',
        mutationClass: 'mutating',
        execute: async (args) => { seenArgs = args; return 'ok'; },
      }],
      client,
      operation: OP,
      autoRecheck: {
        maxAttempts: 1,
        applyFix: async (_tx, ctx) => {
          ctx.call.artifacts = ART_FIXED;
          return true;
        },
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(outcome.verdict.kind, 'ALLOW');
    assert.equal(outcome.executed, true);
    assert.equal(seenArgs.artifacts, ART_FIXED, 'factory args.artifacts is the remediating change set');
  });

  it('resolve() reuse: resolveInput supplies fresh artifacts after applyFix', async () => {
    const resolveInput = {
      baseRef: 'base',
      headRef: 'head',
      changedFiles: ['openapi.yaml'],
      blobs: {
        'base:openapi.yaml': ART_FIXED[0].before,
        'head:openapi.yaml': ART_FIXED[0].after,
      },
    };
    const resolved = resolveArtifacts(resolveInput);
    assert.ok(resolved.artifacts && resolved.artifacts.length > 0, 'resolve() must produce artifacts');
    const FP_RESOLVED = computeCanonicalBundleFingerprint(resolved.artifacts, { operation: OP });
    const client = seqClient([
      () => blockResp('dec_block', FP_BLOCK),
      () => allowResp('dec_allow', FP_RESOLVED),
    ]);
    let resolveCalls = 0;
    const { tools } = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoRecheck: {
        maxAttempts: 1,
        applyFix: async () => true,
        resolveInput: () => {
          resolveCalls += 1;
          return resolveInput;
        },
      },
    });
    const outcome = await tools[0].execute({ artifacts: ART_BLOCK });
    assert.equal(resolveCalls, 1, 'resolveInput runs after applyFix, before re-preflight');
    assert.equal(outcome.verdict.kind, 'ALLOW');
    assert.equal(outcome.fixed_after_block.value, true);
  });
});
