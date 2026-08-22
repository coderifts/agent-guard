'use strict';

/**
 * ID842 step 1 + 3a — TOCTOU / execution-time fingerprint recheck.
 *
 * (a) receipt authorizes A; current still A → match, execution proceeds (flag true)
 * (b) receipt authorizes A; current is A′ → BLOCKED executed:false EXECUTION_STATE_DRIFT
 * (c) primitive is pure (same inputs → same verdict)
 * Plus: guard@8 default true — stale envelope fp DOES block (EXECUTION_STATE_DRIFT).
 * Opt-down: 'warn' emits and runs unenforced; false skips the recheck.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  guardToolCall,
  computeBodyHash,
  checkExecutionTimeFingerprint,
  computeCanonicalBundleFingerprint,
  authorizedFingerprintFromEnvelope,
  EXECUTION_TIME_FP_REASONS,
  isUnmeasurableExecutionStateReason,
  EXECUTION_STATE_UNMEASURABLE_NOTE,
} = require('../dist/cjs/index.js');

const ARTIFACTS_A = [
  { id: 'a', type: 'openapi', before: 'openapi: 3.0.0\ninfo: {title: A}', after: 'openapi: 3.0.1\ninfo: {title: A}' },
];
const ARTIFACTS_A_PRIME = [
  { id: 'a', type: 'openapi', before: 'openapi: 3.0.0\ninfo: {title: A}', after: 'openapi: 3.0.1\ninfo: {title: A-DRIFTED}' },
];

/** Context the guard folds into preflight (and into the T2 recheck). */
const OP = 'tool_call';
const ENV = undefined;
const CTX = { operation: OP, environment: ENV };

const FP_A = computeCanonicalBundleFingerprint(ARTIFACTS_A, CTX);
const FP_A_PRIME = computeCanonicalBundleFingerprint(ARTIFACTS_A_PRIME, CTX);
assert.notEqual(FP_A, FP_A_PRIME, 'fixture A and A′ must produce different fingerprints');

function signedFor(env) {
  return { fp: env.fingerprint, bh: computeBodyHash(env) };
}

function envelope(artifactsFp, o = {}) {
  const { __token, __noReceipt, ...rest } = o;
  const env = {
    spec_version: 'decision-result.v1.1',
    decision: 'ALLOW',
    safe_for_agent: true,
    execution_action: 'CONTINUE',
    decision_id: 'dec_etfp_1',
    correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    // Authorize path: fingerprint === input_fingerprint === crbundle.v1 of authorized artifacts.
    fingerprint: artifactsFp,
    input_fingerprint: artifactsFp,
    analysis_complete: true,
    operation: OP,
    ...rest,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  if (!__noReceipt) {
    env.receipt = { token: __token || 'tok_etfp', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  }
  return env;
}

function client(env) {
  return {
    async authorizeChangeSet(r) {
      return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
    },
    async preflightChangeSet() {
      return { decision: env.decision, execution_action: env.execution_action, decision_result: env };
    },
    async verifyReceipt() {
      return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) };
    },
  };
}

async function run(callArtifacts, authorizedFp, cfg = {}) {
  let executed = false;
  const events = [];
  const env = envelope(authorizedFp);
  const call = {
    toolName: 'apply_openapi',
    arguments: {},
    artifacts: callArtifacts,
  };
  const userOnEvent = cfg.onEvent;
  const outcome = await guardToolCall(
    call,
    async () => {
      executed = true;
      return 'SIDE_EFFECT';
    },
    {
      client: client(env),
      operation: OP,
      environment: ENV,
      ...cfg,
      onEvent: (e) => {
        events.push(e);
        if (typeof userOnEvent === 'function') userOnEvent(e);
      },
    },
  );
  return { outcome, executed, events };
}

function driftEvents(events) {
  return events.filter((e) => e && e.type === 'execution_state_drift_observed');
}

function unmeasurableEvents(events) {
  return events.filter((e) => e && e.type === 'execution_state_unmeasurable');
}

// ── Pure primitive ──────────────────────────────────────────────────────────────
describe('checkExecutionTimeFingerprint pure primitive', () => {
  it('(c) pure: same inputs → same verdict; no network', () => {
    const args = {
      artifacts: ARTIFACTS_A,
      context: CTX,
      authorizedFingerprint: FP_A,
    };
    const v1 = checkExecutionTimeFingerprint(args);
    const v2 = checkExecutionTimeFingerprint(args);
    assert.deepEqual(v1, v2);
    assert.equal(v1.match, true);
    assert.equal(v1.reason, EXECUTION_TIME_FP_REASONS.MATCH);
  });

  it('match when current === authorized', () => {
    const v = checkExecutionTimeFingerprint({
      artifacts: ARTIFACTS_A,
      context: CTX,
      envelope: { fingerprint: FP_A },
    });
    assert.equal(v.match, true);
    assert.equal(v.current_fingerprint, FP_A);
  });

  it('drift: A authorized, A′ current → fingerprint_stale_at_execute', () => {
    const v = checkExecutionTimeFingerprint({
      artifacts: ARTIFACTS_A_PRIME,
      context: CTX,
      authorizedFingerprint: FP_A,
    });
    assert.equal(v.match, false);
    assert.equal(v.reason, EXECUTION_TIME_FP_REASONS.FINGERPRINT_STALE_AT_EXECUTE);
    assert.equal(v.current_fingerprint, FP_A_PRIME);
    assert.equal(v.authorized_fingerprint, FP_A);
    assert.equal(isUnmeasurableExecutionStateReason(v.reason), false, 'stale is real drift (loud)');
  });

  it('empty artifacts → missing_artifacts (unmeasurable)', () => {
    const v = checkExecutionTimeFingerprint({
      artifacts: [],
      authorizedFingerprint: FP_A,
    });
    assert.equal(v.match, false);
    assert.equal(v.reason, EXECUTION_TIME_FP_REASONS.MISSING_ARTIFACTS);
    assert.equal(isUnmeasurableExecutionStateReason(v.reason), true);
  });

  it('no authorized fingerprint → missing_authorized_fingerprint (unmeasurable)', () => {
    const v = checkExecutionTimeFingerprint({
      artifacts: ARTIFACTS_A,
      context: CTX,
      envelope: {},
    });
    assert.equal(v.match, false);
    assert.equal(v.reason, EXECUTION_TIME_FP_REASONS.MISSING_AUTHORIZED_FINGERPRINT);
    assert.equal(isUnmeasurableExecutionStateReason(v.reason), true);
  });

  it('authorizedFingerprintFromEnvelope prefers fingerprint', () => {
    assert.equal(
      authorizedFingerprintFromEnvelope({
        fingerprint: 'sha256:aa',
        input_fingerprint: 'sha256:bb',
      }),
      'sha256:aa',
    );
  });

  it('crbundle.v1 is stable and context-sensitive', () => {
    const a = computeCanonicalBundleFingerprint(ARTIFACTS_A, { operation: 'tool_call' });
    const b = computeCanonicalBundleFingerprint(ARTIFACTS_A, { operation: 'merge' });
    assert.notEqual(a, b);
    assert.match(a, /^sha256:[0-9a-f]{64}$/);
  });
});

// ── Guard wire (after decide, before executeFactory) ────────────────────────────
describe('execution-time fingerprint guard wire (TOCTOU)', () => {
  it('default true: stale envelope fingerprint DOES block (EXECUTION_STATE_DRIFT)', async () => {
    const { outcome, executed } = await run(ARTIFACTS_A, 'sha256:' + 'f'.repeat(64), {
      // requireExecutionStateMatch omitted → default true (guard@8)
    });
    assert.equal(executed, false, 'factory must NOT run on observed drift');
    assert.equal(outcome.executed, false);
    assert.equal(outcome.executionAttempted, false);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.cause, 'EXECUTION_STATE_DRIFT');
    assert.equal(outcome.verdict.action, 'STOP');
  });

  it('(a) flag ON + receipt authorizes A + current A → execution proceeds', async () => {
    const { outcome, executed } = await run(ARTIFACTS_A, FP_A, {
      requireExecutionStateMatch: true,
    });
    assert.equal(executed, true, 'factory must run when state matches');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.verdict.kind, 'ALLOW');
  });

  it('(b) flag ON + receipt authorizes A + current A′ → BLOCKED EXECUTION_STATE_DRIFT', async () => {
    // Receipt is for artifacts A (T1); call carries A′ (T2 drift).
    const { outcome, executed } = await run(ARTIFACTS_A_PRIME, FP_A, {
      requireExecutionStateMatch: true,
    });
    assert.equal(executed, false, 'factory must NOT run on drift');
    assert.equal(outcome.executed, false);
    assert.equal(outcome.executionAttempted, false);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.cause, 'EXECUTION_STATE_DRIFT');
    assert.equal(outcome.verdict.resolution, 'CLOSED');
    assert.equal(outcome.verdict.action, 'STOP');
  });

  it('flag explicitly false proceeds on drift but is not enforced', async () => {
    const { outcome, executed } = await run(ARTIFACTS_A, 'sha256:' + 'e'.repeat(64), {
      requireExecutionStateMatch: false,
    });
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false, 'T2 off is not an enforced run');
  });

  // ── ID842 step 3a — warn mode (emit-and-proceed); loud vs quiet split ─────
  it("warn + real drift → loud execution_state_drift_observed; runs unenforced", async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A_PRIME, FP_A, {
      requireExecutionStateMatch: 'warn',
    });
    assert.equal(executed, true, 'warn mode must NOT block the factory');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false, 'observed mismatch is not an enforced run');
    assert.equal(outcome.verdict.kind, 'ALLOW');
    const drifts = driftEvents(events);
    assert.equal(drifts.length, 1, 'exactly one loud drift event');
    assert.equal(unmeasurableEvents(events).length, 0, 'real drift must not also emit quiet');
    // Shape regression-lock (byte-identical keys/values for real-drift cases)
    assert.deepEqual(
      {
        type: drifts[0].type,
        decisionId: drifts[0].decisionId,
        current_fingerprint: drifts[0].current_fingerprint,
        authorized_fingerprint: drifts[0].authorized_fingerprint,
        reason: drifts[0].reason,
      },
      {
        type: 'execution_state_drift_observed',
        decisionId: 'dec_etfp_1',
        current_fingerprint: FP_A_PRIME,
        authorized_fingerprint: FP_A,
        reason: EXECUTION_TIME_FP_REASONS.FINGERPRINT_STALE_AT_EXECUTE,
      },
    );
    assert.equal(typeof drifts[0].at, 'string');
    assert.equal('note' in drifts[0], false, 'loud event must not gain a note field');
  });

  it('warn + missing artifacts → quiet ONLY, no loud, execution proceeds', async () => {
    // hasAnalyzableContent runs before preflight; vanish artifacts during preflight so T2 sees [].
    const real = [
      { id: 'a', type: 'openapi', before: 'openapi: 3.0.0\ninfo: {title: A}', after: 'openapi: 3.0.1\ninfo: {title: A}' },
    ];
    let vanished = false;
    const vanishing = new Proxy(real, {
      get(t, p, r) {
        if (vanished && p === 'length') return 0;
        return Reflect.get(t, p, r);
      },
    });
    const events = [];
    let executed = false;
    const env = envelope(FP_A);
    const outcome = await guardToolCall(
      { toolName: 'apply_openapi', arguments: {}, artifacts: vanishing },
      async () => {
        executed = true;
        return 'SIDE_EFFECT';
      },
      {
        client: {
          async authorizeChangeSet(r) {
            return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
          },
          async preflightChangeSet() {
            vanished = true; // after hasAnalyzableContent; before T2 recheck
            return { decision: env.decision, execution_action: env.execution_action, decision_result: env };
          },
          async verifyReceipt() {
            return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) };
          },
        },
        operation: OP,
        environment: ENV,
        requireExecutionStateMatch: 'warn',
        onEvent: (e) => events.push(e),
      },
    );
    assert.equal(executed, true, 'unmeasurable must not block');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false);
    assert.equal(driftEvents(events).length, 0, 'must not emit loud drift for unmeasurable');
    const quiet = unmeasurableEvents(events);
    assert.equal(quiet.length, 1);
    assert.equal(quiet[0].type, 'execution_state_unmeasurable');
    assert.equal(quiet[0].reason, EXECUTION_TIME_FP_REASONS.MISSING_ARTIFACTS);
    assert.equal(quiet[0].note, EXECUTION_STATE_UNMEASURABLE_NOTE);
    assert.equal(quiet[0].current_fingerprint, null);
    assert.equal(quiet[0].authorized_fingerprint, FP_A);
    assert.equal(quiet[0].decisionId, 'dec_etfp_1');
  });

  it('warn + missing authorized fingerprint → quiet ONLY, no loud, execution proceeds', async () => {
    const events = [];
    let executed = false;
    // Receipt bind needs fingerprint present; strip after preflight_result so T2 sees no authorized fp.
    const env = envelope(FP_A);
    const outcome = await guardToolCall(
      { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS_A },
      async () => {
        executed = true;
        return 'SIDE_EFFECT';
      },
      {
        client: client(env),
        operation: OP,
        environment: ENV,
        requireExecutionStateMatch: 'warn',
        onEvent: (e) => {
          events.push(e);
          if (e.type === 'preflight_result') {
            delete env.fingerprint;
            delete env.input_fingerprint;
            delete env.verdict_fingerprint;
          }
        },
      },
    );
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false);
    assert.equal(driftEvents(events).length, 0, 'must not emit loud drift');
    const quiet = unmeasurableEvents(events);
    assert.equal(quiet.length, 1);
    assert.equal(quiet[0].type, 'execution_state_unmeasurable');
    assert.equal(quiet[0].reason, EXECUTION_TIME_FP_REASONS.MISSING_AUTHORIZED_FINGERPRINT);
    assert.equal(quiet[0].note, EXECUTION_STATE_UNMEASURABLE_NOTE);
    assert.equal(quiet[0].current_fingerprint, null);
    assert.equal(quiet[0].authorized_fingerprint, null);
  });

  it('warn + match → executes, no loud and no quiet event', async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A, FP_A, {
      requireExecutionStateMatch: 'warn',
    });
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(driftEvents(events).length, 0, 'match must not emit loud drift');
    assert.equal(unmeasurableEvents(events).length, 0, 'match must not emit quiet');
  });

  it('enforce (true) + drift → still BLOCKED (regression: warn split did not weaken enforce)', async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A_PRIME, FP_A, {
      requireExecutionStateMatch: true,
    });
    assert.equal(executed, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'EXECUTION_STATE_DRIFT');
    assert.equal(driftEvents(events).length, 0, 'enforce path does not emit warn events');
    assert.equal(unmeasurableEvents(events).length, 0);
  });

  it('enforce (true) + missing authorized fingerprint → EXECUTION_STATE_UNMEASURABLE (cannot assert)', async () => {
    const events = [];
    let executed = false;
    const env = envelope(FP_A);
    const outcome = await guardToolCall(
      { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS_A },
      async () => {
        executed = true;
        return 'SIDE_EFFECT';
      },
      {
        client: client(env),
        operation: OP,
        environment: ENV,
        requireExecutionStateMatch: true,
        onEvent: (e) => {
          events.push(e);
          if (e.type === 'preflight_result') {
            delete env.fingerprint;
            delete env.input_fingerprint;
            delete env.verdict_fingerprint;
          }
        },
      },
    );
    assert.equal(executed, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'EXECUTION_STATE_UNMEASURABLE');
    assert.equal(driftEvents(events).length, 0);
    assert.equal(unmeasurableEvents(events).length, 0);
  });

  it('explicit false opt-down + drift → executes unenforced, NO loud/quiet events', async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A_PRIME, FP_A, {
      requireExecutionStateMatch: false,
    });
    assert.equal(executed, true, 'false opt-down still proceeds on drift');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false, 'T2 was not checked — enforced must not be true');
    assert.equal(driftEvents(events).length, 0);
    assert.equal(unmeasurableEvents(events).length, 0);
    assert.equal(
      events.filter((e) => e.type === 'execution_state_check_disabled').length,
      1,
      'honesty breadcrumb: T2 was explicitly off',
    );
  });
});
