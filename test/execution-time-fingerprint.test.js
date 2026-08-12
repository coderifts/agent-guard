'use strict';

/**
 * ID842 step 1 + 3a — TOCTOU / execution-time fingerprint recheck.
 *
 * (a) receipt authorizes A; current still A → match, execution proceeds (flag true)
 * (b) receipt authorizes A; current is A′ → BLOCKED executed:false EXECUTION_STATE_DRIFT
 * (c) primitive is pure (same inputs → same verdict)
 * Plus: flag default OFF does not change behavior (even with stale envelope fp).
 * Step 3a: 'warn' emits execution_state_drift_observed on mismatch but still executes.
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
  it('default OFF: stale envelope fingerprint does NOT block (no default flip)', async () => {
    // Envelope authorizes garbage; current is A — without the flag this still executes
    // (existing behavior: host is not forced to re-measure at T2).
    const { outcome, executed } = await run(ARTIFACTS_A, 'sha256:' + 'f'.repeat(64), {
      // requireExecutionStateMatch omitted → default false
    });
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
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

  it('flag explicitly false behaves like default OFF', async () => {
    const { outcome, executed } = await run(ARTIFACTS_A, 'sha256:' + 'e'.repeat(64), {
      requireExecutionStateMatch: false,
    });
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
  });

  // ── ID842 step 3a — warn mode (emit-and-proceed) ──────────────────────────
  it("warn + drift → executes (executed:true) and emits execution_state_drift_observed", async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A_PRIME, FP_A, {
      requireExecutionStateMatch: 'warn',
    });
    assert.equal(executed, true, 'warn mode must NOT block the factory');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true, 'warn still runs the enforced path; it only softens the T2 gate');
    assert.equal(outcome.verdict.kind, 'ALLOW');
    const drifts = driftEvents(events);
    assert.equal(drifts.length, 1, 'exactly one drift event');
    assert.equal(drifts[0].type, 'execution_state_drift_observed');
    assert.equal(drifts[0].current_fingerprint, FP_A_PRIME);
    assert.equal(drifts[0].authorized_fingerprint, FP_A);
    assert.equal(drifts[0].reason, EXECUTION_TIME_FP_REASONS.FINGERPRINT_STALE_AT_EXECUTE);
    assert.equal(typeof drifts[0].at, 'string');
    assert.equal(drifts[0].decisionId, 'dec_etfp_1');
  });

  it('warn + match → executes, no drift event', async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A, FP_A, {
      requireExecutionStateMatch: 'warn',
    });
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(driftEvents(events).length, 0, 'match must not emit drift telemetry');
  });

  it('enforce (true) + drift → still BLOCKED (regression: warn did not weaken enforce)', async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A_PRIME, FP_A, {
      requireExecutionStateMatch: true,
    });
    assert.equal(executed, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'EXECUTION_STATE_DRIFT');
    assert.equal(
      driftEvents(events).length,
      0,
      'enforce path blocks via closedIntegrity; does not emit the warn-only event',
    );
  });

  it('off/default + drift → executes, NO drift event (unchanged)', async () => {
    const { outcome, executed, events } = await run(ARTIFACTS_A_PRIME, FP_A, {
      // requireExecutionStateMatch omitted
    });
    assert.equal(executed, true);
    assert.equal(outcome.executed, true);
    assert.equal(driftEvents(events).length, 0);

    const r2 = await run(ARTIFACTS_A_PRIME, FP_A, { requireExecutionStateMatch: false });
    assert.equal(r2.executed, true);
    assert.equal(driftEvents(r2.events).length, 0);
  });
});
