'use strict';

/**
 * P0 receipt-substitution acceptance (the ChatGPT-specified suite).
 *
 * The guard must BIND a receipt to THIS envelope before executing: a valid receipt from a DIFFERENT
 * decision must NOT authenticate a forged envelope. Binding = local recomputation of the canonical
 * decision body hash (+ fingerprint + operation/environment/audience scope + VERIFIED_CURRENT status).
 * Every substitution variant → refused (no execution, enforced:false); a correctly-bound receipt →
 * still executes (no over-block).
 */

const { test, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { guardToolCall, bindReceiptToEnvelope, computeBodyHash } = require('../dist/cjs/index.js');

// ── helpers ───────────────────────────────────────────────────────────────────────────────────────
function makeEnvelope(o = {}) {
  const { __token, ...rest } = o;
  const env = {
    spec_version: 'decision-result.v1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'corr_1',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', summary: 'ok',
    blocking_reasons: [], warnings: [], required_action: null, next_actions: [],
    fingerprint: 'sha256:' + 'a'.repeat(64), input_fingerprint: 'sha256:' + 'b'.repeat(64),
    decision_body_hash: null, report_url: null, evidence_quality: 'HIGH', confidence: 90,
    evidence: [], analysis_complete: true, operation: 'tool_call', environment: 'prod', audience: null,
    ...rest,
  };
  env.receipt = { token: __token || 'tok', format_version: 'v4', key_id: 'k1', issued_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z' };
  return env;
}
/** What the server signs into the receipt for `env` (bh excludes receipt + decision_body_hash). */
function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }

/** A guardToolCall run: mock client returns `envelope` from preflight, `vr` from verifyReceipt. */
async function runGuard(envelope, vr, config = {}) {
  let executed = false;
  const client = {
    async preflightChangeSet() { return { decision_result: envelope, decision: envelope.decision, execution_action: envelope.execution_action }; },
    async verifyReceipt() { return vr; },
  };
  const outcome = await guardToolCall(
    { toolName: 'apply_openapi', artifacts: [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }] },
    async () => { executed = true; return 'SIDE_EFFECT_EXECUTED'; },
    { client, environment: 'prod', operation: 'tool_call', ...config },
  );
  return { outcome, executed };
}
const refused = (r) => r.executed === false && r.outcome.executed === false && r.outcome.enforced === false;

// ── PART 4 — the exact ChatGPT reproduction ───────────────────────────────────────────────────────
describe('PART 4 — the exploit: real BLOCK receipt in a forged ALLOW envelope', () => {
  it('guard REFUSES (no SIDE_EFFECT_EXECUTED, enforced:false, RECEIPT_ENVELOPE_MISMATCH)', async () => {
    const realBlock = makeEnvelope({ decision: 'BLOCK', safe_for_agent: false, execution_action: 'STOP', fingerprint: 'sha256:' + 'd'.repeat(64), __token: 'REAL_BLOCK_TOKEN' });
    const signed = signedFor(realBlock); // the receipt genuinely signed the BLOCK decision
    const forgedAllow = makeEnvelope({ decision: 'ALLOW', execution_action: 'CONTINUE', fingerprint: signed.fp, decision_body_hash: signed.bh, __token: 'REAL_BLOCK_TOKEN' });
    const { outcome, executed } = await runGuard(forgedAllow, { valid: true, status: 'VERIFIED_CURRENT', payload: signed });
    assert.equal(executed, false, 'the side effect must NOT run');
    assert.notEqual(outcome.result, 'SIDE_EFFECT_EXECUTED');
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });
});

// ── PART 3 — substitution variants (unit-level on the binding, precise causes) ─────────────────────
describe('PART 3 — bindReceiptToEnvelope refuses every substitution variant', () => {
  const base = makeEnvelope();
  const goodSigned = signedFor(base);

  it('happy path: correctly-bound receipt → ok', () => {
    const r = bindReceiptToEnvelope(base, { valid: true, status: 'VERIFIED_CURRENT', payload: goodSigned }, { operation: 'tool_call', environment: 'prod' });
    assert.equal(r.ok, true);
  });

  it('modified decision (BLOCK receipt → ALLOW envelope) → mismatch', () => {
    const block = makeEnvelope({ decision: 'BLOCK', execution_action: 'STOP', fingerprint: 'sha256:' + 'e'.repeat(64) });
    const forged = makeEnvelope({ decision: 'ALLOW', execution_action: 'CONTINUE', fingerprint: block.fingerprint, decision_body_hash: computeBodyHash(block) });
    const r = bindReceiptToEnvelope(forged, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(block) }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('modified execution_action → body-hash mismatch', () => {
    const orig = makeEnvelope({ execution_action: 'CONTINUE_WITH_MONITORING' });
    const forged = makeEnvelope({ execution_action: 'CONTINUE' }); // rewritten
    const r = bindReceiptToEnvelope(forged, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(orig) }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('replay: receipt for a DIFFERENT input (different fp) → mismatch', () => {
    const other = makeEnvelope({ fingerprint: 'sha256:' + 'c'.repeat(64), input_fingerprint: 'sha256:' + '1'.repeat(64) });
    const r = bindReceiptToEnvelope(base, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(other) }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('different operation (merge receipt at deploy) → mismatch', () => {
    const merge = makeEnvelope({ operation: 'merge' });
    const r = bindReceiptToEnvelope(merge, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(merge) }, { operation: 'deploy' });
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('different environment → mismatch', () => {
    const env = makeEnvelope({ environment: 'staging' });
    const r = bindReceiptToEnvelope(env, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }, { environment: 'prod' });
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('different audience → mismatch', () => {
    const env = makeEnvelope({ audience: 'team-a' });
    const r = bindReceiptToEnvelope(env, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }, { audience: 'team-b' });
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('expired receipt (status VERIFIED_EXPIRED) → mismatch', () => {
    const r = bindReceiptToEnvelope(base, { valid: true, status: 'VERIFIED_EXPIRED', payload: goodSigned }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('superseded receipt (status VERIFIED_SUPERSEDED) → mismatch', () => {
    const r = bindReceiptToEnvelope(base, { valid: true, status: 'VERIFIED_SUPERSEDED', payload: goodSigned }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('bad signature (valid:false) → RECEIPT_UNVERIFIED (distinct from mismatch)', () => {
    const r = bindReceiptToEnvelope(base, { valid: false, status: 'INVALID_SIGNATURE', payload: goodSigned }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_UNVERIFIED');
  });

  it('explicit fingerprint mismatch (payload.fp != envelope.fingerprint) → mismatch', () => {
    const r = bindReceiptToEnvelope(base, { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: 'sha256:' + '0'.repeat(64), bh: goodSigned.bh } }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('explicit body-hash mismatch (payload.bh != local) → mismatch', () => {
    const r = bindReceiptToEnvelope(base, { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: goodSigned.fp, bh: 'sha256:' + 'f'.repeat(64) } }, {});
    assert.equal(r.ok, false); assert.equal(r.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });
});

// ── PART 3 — end-to-end refusals + the happy path (no over-block) ──────────────────────────────────
describe('PART 3 — guardToolCall end-to-end', () => {
  it('happy path: a correctly-bound ALLOW receipt STILL EXECUTES (enforced:true)', async () => {
    const env = makeEnvelope();
    const { outcome, executed } = await runGuard(env, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) });
    assert.equal(executed, true, 'the bound receipt executes');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true, 'enforced:true on a bound receipt');
    assert.equal(outcome.result, 'SIDE_EFFECT_EXECUTED');
  });

  it('modified execution_action end-to-end → refused', async () => {
    const orig = makeEnvelope({ execution_action: 'CONTINUE_WITH_MONITORING' });
    const forged = makeEnvelope({ execution_action: 'CONTINUE' });
    const { outcome, executed } = await runGuard(forged, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(orig) });
    assert.ok(refused({ outcome, executed }));
    assert.equal(outcome.verdict.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('merge receipt at deploy (operation mismatch) end-to-end → refused', async () => {
    const merge = makeEnvelope({ operation: 'merge' });
    const { outcome, executed } = await runGuard(merge, { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(merge) }, { operation: 'deploy' });
    assert.ok(refused({ outcome, executed }));
    assert.equal(outcome.verdict.cause, 'RECEIPT_ENVELOPE_MISMATCH');
  });

  it('expired receipt end-to-end → refused', async () => {
    const env = makeEnvelope();
    const { outcome, executed } = await runGuard(env, { valid: true, status: 'VERIFIED_EXPIRED', payload: signedFor(env) });
    assert.ok(refused({ outcome, executed }));
  });
});
