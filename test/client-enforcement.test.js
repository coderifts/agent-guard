'use strict';

/**
 * Client-enforcement pack (Grok CE-* matrix) — P0-b/c: the guard mirrors §106/§111/§115 client-side.
 * Every substitution/inconsistency/degraded/no-receipt vector → FAIL-CLOSED (not executed). The two
 * positive controls (CE-EP-02/05/07) still fail-closed. The happy path (fully-valid bound consistent
 * non-degraded safe envelope) STILL EXECUTES. And the hard invariant: enforced:false ⟺ not executed
 * on a contract-triggering path.
 */

const { test, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { guardToolCall, computeBodyHash, computeArtifactDigest, computeCanonicalBundleFingerprint } = require('../dist/cjs/index.js');

// The contract-triggering call the guard preflights; ARTIFACTS is what it sends.
const ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0', after: 'openapi: 3.0.1' }];
const TRIGGER = { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS };
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);
const LOCAL_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });

function envelope(o = {}) {
  const { __token, __noReceipt, ...rest } = o;
  const env = {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: LOCAL_FP, input_fingerprint: LOCAL_FP,
    analysis_complete: true, artifact_digest: LOCAL_DIGEST, operation: 'tool_call',
    ...rest,
  };
  // JSON envelopes never carry `undefined` (absent keys are absent); strip so canonical body-hash works.
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  if (!__noReceipt) env.receipt = { token: __token || 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  return env;
}
function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }

/** Mock client: preflight returns `resp` (envelope wrapped), verifyReceipt binds to that envelope. */
function client(env, { response, verify } = {}) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { return response || { decision: env.decision, execution_action: env.execution_action, decision_result: env }; },
    async verifyReceipt() { return verify || { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; },
  };
}
async function run(env, opts = {}, cfg = {}) {
  let executed = false;
  const outcome = await guardToolCall(TRIGGER, async () => { executed = true; return 'SIDE_EFFECT'; }, { client: client(env, opts), ...cfg });
  return { outcome, executed };
}
const failClosed = (r) => r.executed === false && r.outcome.executed === false && r.outcome.enforced === false;

// ── Surface 2 — envelope parsing / consistency ────────────────────────────────────────────────────
describe('CE-EP — decision↔action consistency, safe_for_agent, receipt presence', () => {
  it('CE-EP-01: decision=BLOCK + execution_action=CONTINUE → fail-closed (stricter wins)', async () => {
    const env = envelope({ decision: 'BLOCK', execution_action: 'CONTINUE', safe_for_agent: false });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.kind, 'BLOCK');
  });

  it('CE-EP-02 (control): decision=ALLOW + execution_action=STOP → still blocked (not executed)', async () => {
    const env = envelope({ decision: 'ALLOW', execution_action: 'STOP', __noReceipt: true });
    const r = await run(env);
    assert.ok(failClosed(r), 'the STOP/stricter path still blocks');
  });

  it('CE-EP-03: safe_for_agent=false + CONTINUE → fail-closed (§115)', async () => {
    const env = envelope({ safe_for_agent: false });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'DECISION_INCONSISTENT');
  });

  it('CE-EP-04: missing decision + CONTINUE → fail-closed', async () => {
    const env = envelope({ decision: undefined });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'DECISION_INCONSISTENT');
  });

  it('CE-EP-05 (control): non-string execution_action → no envelope → SCHEMA_INVALID (not executed)', async () => {
    const r = await run(envelope(), { response: { decision_result: { execution_action: 1 } } });
    assert.ok(failClosed(r));
  });

  it('CE-EP-06: ALLOW/CONTINUE with NO receipt → fail-closed (RECEIPT_MISSING), factory never runs', async () => {
    const env = envelope({ __noReceipt: true });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'RECEIPT_MISSING');
  });

  it('CE-EP-07 (control): top-level action only, no decision_result → SCHEMA_INVALID (not executed)', async () => {
    const r = await run(envelope(), { response: { decision: 'ALLOW', execution_action: 'CONTINUE' } });
    assert.ok(failClosed(r));
  });

  it('CE-EP-08: verifyReceipts:false + CONTINUE → fail-closed (RECEIPT_MISSING)', async () => {
    const r = await run(envelope(), {}, { verifyReceipts: false });
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'RECEIPT_MISSING');
  });
});

// ── Surface 3 — artifact flow ───────────────────────────────────────────────────────────────────
describe('CE-AF — artifact_digest local bind', () => {
  it('CE-AF-03: envelope.artifact_digest ≠ local digest of sent artifacts → fail-closed', async () => {
    const env = envelope({ artifact_digest: 'sha256:' + '0'.repeat(64) }); // digest of DIFFERENT (clean) specs
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'ARTIFACT_MISMATCH');
  });

  it('CE-AF-04: a swapped-artifacts response (analyzed ≠ sent) is caught by the digest bind', async () => {
    // Server "analyzed" clean specs (digest set accordingly) but we sent ARTIFACTS → mismatch.
    const cleanDigest = computeArtifactDigest([{ id: 'a', type: 'openapi', before: 'clean', after: 'clean' }]);
    const env = envelope({ artifact_digest: cleanDigest });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'ARTIFACT_MISMATCH');
  });

  it('CE-AF-02: an honest server BLOCK on a degenerate change (after removed) still blocks', async () => {
    // The digest binds; the server honestly returns BLOCK for the removal → block-strict.
    const env = envelope({ decision: 'BLOCK', execution_action: 'STOP', safe_for_agent: false, __noReceipt: true });
    const r = await run(env);
    assert.ok(failClosed(r));
  });
});

// ── Surface 4 — chain coherence + degraded ─────────────────────────────────────────────────────────
describe('CE-CC — chain coherence + §111 degraded', () => {
  it('CE-CC-01: top-level BLOCK but envelope CONTINUE → fail-closed (stricter/decision-required)', async () => {
    const env = envelope({ decision: undefined }); // envelope has no decision, only CONTINUE
    const r = await run(env, { response: { decision: 'BLOCK', execution_action: 'STOP', decision_result: env } });
    assert.ok(failClosed(r));
  });

  it('CE-CC-01b: top-level BLOCK strictly beats an envelope ALLOW/CONTINUE', async () => {
    const env = envelope({ decision: 'ALLOW', execution_action: 'CONTINUE' });
    const r = await run(env, { response: { decision: 'BLOCK', execution_action: 'STOP', decision_result: env } });
    assert.ok(failClosed(r), 'the outer BLOCK wins');
    assert.equal(r.outcome.verdict.kind, 'BLOCK');
  });

  it('CE-CC-02: degraded / analysis_complete=false ALLOW+CONTINUE → fail-closed (§111)', async () => {
    const env = envelope({ analysis_complete: false, degraded_reasons: [{ code: 'engine_unavailable' }] });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'ANALYSIS_DEGRADED');
  });

  it('CE-CC-02b: coverage_gap=true → fail-closed', async () => {
    const env = envelope({ coverage_gap: true });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'ANALYSIS_DEGRADED');
  });

  it('CE-CC-04: MONITOR without monitoring declaration+sink → fail-closed (MONITORING_UNWIRED)', async () => {
    const env = envelope({ decision: 'WARN', execution_action: 'CONTINUE_WITH_MONITORING' });
    const r = await run(env);
    assert.ok(failClosed(r));
    assert.equal(r.outcome.verdict.cause, 'MONITORING_UNWIRED');
  });

  it('CE-CC-03 (intentional opt-in, documented): default failPolicy=closed fails closed on unavailable', async () => {
    const netFail = { async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { throw Object.assign(new Error('fetch failed'), { name: 'TypeError' }); }, async verifyReceipt() { return { valid: false }; } };
    let executed = false;
    const o = await guardToolCall(TRIGGER, async () => { executed = true; }, { client: netFail, retries: 0 });
    assert.equal(executed, false, 'closed (default) does not execute; failPolicy:open is the documented opt-in residual');
  });
});

// ── The enforced⟺executed INVARIANT + happy path (no over-block) ──────────────────────────────────
describe('enforced ⟺ executed invariant + happy path', () => {
  const refusalVectors = [
    ['EP-01', () => envelope({ decision: 'BLOCK', execution_action: 'CONTINUE', safe_for_agent: false })],
    ['EP-03', () => envelope({ safe_for_agent: false })],
    ['EP-04', () => envelope({ decision: undefined })],
    ['EP-06', () => envelope({ __noReceipt: true })],
    ['AF-03', () => envelope({ artifact_digest: 'sha256:' + '0'.repeat(64) })],
    ['CC-02', () => envelope({ analysis_complete: false })],
    ['CC-04', () => envelope({ decision: 'WARN', execution_action: 'CONTINUE_WITH_MONITORING' })],
  ];
  for (const [id, mk] of refusalVectors) {
    it(`invariant ${id}: enforced:false ⟹ NOT executed (contract path)`, async () => {
      const r = await run(mk());
      if (r.outcome.enforced === false) assert.equal(r.executed, false, `${id}: not-enforcing must mean not-executing`);
    });
  }

  it('HAPPY PATH: fully-valid bound consistent non-degraded safe ALLOW → STILL EXECUTES (enforced:true)', async () => {
    const r = await run(envelope()); // default = ALLOW/CONTINUE/safe/complete/digest-bound/bound-receipt
    assert.equal(r.executed, true, 'no over-block — a good envelope still runs');
    assert.equal(r.outcome.executed, true);
    assert.equal(r.outcome.enforced, true);
    assert.equal(r.outcome.result, 'SIDE_EFFECT');
  });

  it('HAPPY PATH (MONITOR + declared + onEvent): still executes enforced:true', async () => {
    const env = envelope({ decision: 'WARN', execution_action: 'CONTINUE_WITH_MONITORING' });
    let executed = false;
    const o = await guardToolCall(TRIGGER, async () => { executed = true; return 'SIDE_EFFECT'; }, {
      client: client(env),
      monitoringSinkWired: true,
      onEvent: () => {},
    });
    assert.equal(executed, true);
    assert.equal(o.enforced, true);
  });
});
