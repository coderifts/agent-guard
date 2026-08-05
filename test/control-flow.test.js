'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { guardToolCall, computeBodyHash } = require('../dist/cjs/index.js');

// P0 receipt-binding: a mock verifyReceipt must now return a receipt BOUND to the envelope — the
// signed fp/bh matching the locally-recomputed body hash. `signedFor` mirrors what the server signs.
function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

// ── fixtures ────────────────────────────────────────────────────────────────────
const TRIGGER = { toolName: 'Edit', arguments: {}, artifacts: [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }] };
const SKIP = { toolName: 'Read', arguments: { path: 'README.md' } };
const RESULT = { ok: true };
const okFactory = async () => RESULT;
const throwFactory = async () => { throw new Error('boom'); };

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: 'dec_1', correlation_id: 'c', evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    // P0: envelope carries a fingerprint so the receipt binding has something to bind.
    fingerprint: opts.fingerprint || ('sha256:' + 'a'.repeat(64)),
    input_fingerprint: 'sha256:' + 'b'.repeat(64),
    receipt: opts.noReceipt ? undefined : { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function response(execution_action, decision, opts) {
  return { decision, decision_result: envelope(execution_action, decision, opts) };
}
function mockClient({ preflight, verify } = {}) {
  let lastEnv = null; // the envelope the preflight returned — the receipt must bind to IT.
  return {
    async preflightChangeSet() {
      const resp = preflight ? preflight() : response('CONTINUE', 'ALLOW');
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      if (verify) return verify();
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

// ── SKIPPED ──────────────────────────────────────────────────────────────────────
test('SKIPPED: non-contract call executes enforced:false, preflighted:false', async () => {
  const o = await guardToolCall(SKIP, okFactory, { client: mockClient() });
  assert.equal(o.verdict.kind, 'SKIPPED');
  assert.equal(o.executionAttempted, true);
  assert.equal(o.executed, true);
  assert.equal(o.enforced, false);
  assert.equal(o.preflighted, false);
  assert.deepEqual(o.result, RESULT);
});

// ── ALLOW enforced ────────────────────────────────────────────────────────────────
test('ALLOW + verified receipt => enforced:true, executed', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, { client: mockClient() });
  assert.equal(o.verdict.kind, 'ALLOW');
  assert.equal(o.enforced, true);
  assert.equal(o.executed, true);
  assert.equal(o.preflighted, true);
  assert.equal(o.verdict.receiptVerified, true);
});

// ── BLOCK / APPROVAL: no execution ──────────────────────────────────────────────
test('BLOCK: factory NEVER runs (executionAttempted:false)', async () => {
  let ran = false;
  const o = await guardToolCall(TRIGGER, async () => { ran = true; return RESULT; }, { client: mockClient({ preflight: () => response('STOP', 'BLOCK') }) });
  assert.equal(o.verdict.kind, 'BLOCK');
  assert.equal(ran, false);
  assert.equal(o.executionAttempted, false);
  assert.equal(o.executed, false);
  assert.equal(o.enforced, false);
});
test('APPROVAL: non-executable, factory never runs', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ preflight: () => response('REQUEST_APPROVAL', 'REQUIRE_APPROVAL') }) });
  assert.equal(o.verdict.kind, 'APPROVAL');
  assert.equal(o.executionAttempted, false);
});

// ── MONITOR: host declaration + onEvent agreement ─────────────────────────────────
// monitoringSinkWired is a host ASSERTION (not delivery proof). Gate opens only when
// monitoringSinkWired === true AND typeof onEvent === 'function'. Absent declaration = unwired
// (closes the () => {} alone hole; breaks onEvent-only callers until they declare).
const monitorClient = () => mockClient({ preflight: () => response('CONTINUE_WITH_MONITORING', 'WARN') });

test('MONITOR + declared and wired (monitoringSinkWired + onEvent) => enforced:true', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, {
    client: monitorClient(),
    monitoringSinkWired: true,
    onEvent: () => {},
  });
  assert.equal(o.verdict.kind, 'MONITOR');
  assert.equal(o.enforced, true);
  assert.equal(o.executed, true);
});

test('MONITOR + declared but no callback => FAIL-CLOSED (contradiction) — MONITORING_UNWIRED', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, {
    client: monitorClient(),
    monitoringSinkWired: true,
    // no onEvent
  });
  assert.equal(o.executed, false);
  assert.equal(o.enforced, false);
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'MONITORING_UNWIRED');
});

// Choice: absent monitoringSinkWired = unwired even when onEvent is present.
test('MONITOR + callback but not declared (onEvent only) => FAIL-CLOSED — absent declaration is unwired', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, {
    client: monitorClient(),
    onEvent: () => {}, // would have unlocked the gate under the old !!onEvent check
  });
  assert.equal(o.executed, false);
  assert.equal(o.enforced, false);
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'MONITORING_UNWIRED');
});

// P0-c (CE-CC-04 + enforced⟺executed invariant): MONITOR with neither declaration nor sink
// FAILS CLOSED (does NOT execute).
test('MONITOR + neither declaration nor callback => FAIL-CLOSED — MONITORING_UNWIRED', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, { client: monitorClient() });
  assert.equal(o.executed, false);
  assert.equal(o.enforced, false);
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'MONITORING_UNWIRED');
});

// ── observeOnly ────────────────────────────────────────────────────────────────────
test('observeOnly: executes but never enforces', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, { client: mockClient(), observeOnly: true, onEvent: () => {} });
  assert.equal(o.executed, true);
  assert.equal(o.enforced, false);
  assert.equal(o.verdict.kind, 'ALLOW');
});

// ── fail-closed (availability, closed policy) ──────────────────────────────────────
test('transport NETWORK error + closed policy => STOP, factory never runs', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ preflight: () => { throw Object.assign(new Error('fetch failed'), { name: 'TypeError' }); } }) });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.resolution, 'CLOSED');
  assert.equal(o.verdict.action, 'STOP');
  assert.equal(o.executionAttempted, false);
});

// ── fail-open (availability, open policy) ──────────────────────────────────────────
test('NETWORK error + open policy => OPEN_PASSTHROUGH executes enforced:false', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, { client: mockClient({ preflight: () => { throw Object.assign(new Error('fetch failed'), { name: 'TypeError' }); } }), failPolicy: 'open' });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.resolution, 'OPEN_PASSTHROUGH');
  assert.equal(o.executed, true);
  assert.equal(o.enforced, false);
});

// ── integrity ALWAYS closed even under open ───────────────────────────────────────
test('413 PAYLOAD_TOO_LARGE (integrity) + open policy => CLOSED (never permissive)', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ preflight: () => { throw Object.assign(new Error('too large'), { status: 413, name: 'ApiError' }); } }), failPolicy: 'open' });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'PAYLOAD_TOO_LARGE');
  assert.equal(o.verdict.resolution, 'CLOSED');
  assert.equal(o.executionAttempted, false);
});
test('422 REQUEST_REJECTED (integrity) + open policy => CLOSED', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ preflight: () => { throw Object.assign(new Error('unprocessable'), { status: 422, name: 'ApiError' }); } }), failPolicy: 'open' });
  assert.equal(o.verdict.cause, 'REQUEST_REJECTED');
  assert.equal(o.verdict.resolution, 'CLOSED');
  assert.equal(o.executionAttempted, false);
});

// ── detector error => fail-closed ─────────────────────────────────────────────────
test('detector throw => fail-closed (DETECTOR_ERROR), factory never runs', async () => {
  const badDetector = { version: 'x', detect() { throw new Error('detector boom'); } };
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient(), detector: badDetector });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'DETECTOR_ERROR');
  assert.equal(o.executionAttempted, false);
});

// ── receipt verification gates ────────────────────────────────────────────────────
test('receipt fails verification (attack signal) => integrity closed, no execution', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ verify: () => ({ valid: false, status: 'INVALID_SIGNATURE' }) }) });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'RECEIPT_UNVERIFIED');
  assert.equal(o.executionAttempted, false);
});
// P0-b (CE-EP-08 + enforced⟺executed invariant): verifyReceipts:false cannot produce a bound
// receipt on a contract change → cannot enforce → FAILS CLOSED (does NOT execute) — was executed:true.
test('verifyReceipts:false on a contract change => FAIL-CLOSED (not executed) — RECEIPT_MISSING', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, { client: mockClient(), verifyReceipts: false });
  assert.equal(o.executed, false);
  assert.equal(o.enforced, false);
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.cause, 'RECEIPT_MISSING');
});

// ── retry safety (executionAttempted split) ───────────────────────────────────────
test('factory throws AFTER enforced approval => executionAttempted:true, executed:false, enforced:true', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient() });
  assert.equal(o.executionAttempted, true);  // NOT safe to retry — the side effect may have landed
  assert.equal(o.executed, false);
  assert.equal(o.enforced, true);             // audit chain preserved
  assert.ok('error' in o);
});
test('a blocked (never-run) outcome IS safe to retry (executionAttempted:false)', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ preflight: () => response('STOP', 'BLOCK') }) });
  assert.equal(o.executionAttempted, false); // safe to retry after resolving the block
});

// ── transport retry on availability ───────────────────────────────────────────────
test('one NETWORK failure then success (retries:1) => enforced ALLOW', async () => {
  let n = 0;
  const okEnv = envelope('CONTINUE', 'ALLOW');
  const client = {
    async preflightChangeSet() { n++; if (n === 1) throw Object.assign(new Error('fetch failed'), { name: 'TypeError' }); return { decision: 'ALLOW', decision_result: okEnv }; },
    async verifyReceipt() { return boundVerify(okEnv); },
  };
  const o = await guardToolCall(TRIGGER, okFactory, { client, retries: 1 });
  assert.equal(n, 2);
  assert.equal(o.enforced, true);
});

// ── expiry ────────────────────────────────────────────────────────────────────────
test('expired decision cannot be honored => closed', async () => {
  const o = await guardToolCall(TRIGGER, throwFactory, { client: mockClient({ preflight: () => response('CONTINUE', 'ALLOW', { expires_at: new Date(Date.now() - 1000).toISOString() }) }) });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.executionAttempted, false);
});

// ── lkg dormant (binding fields absent => closed) ────────────────────────────────
test('failPolicy:lkg with a cached envelope => UNUSABLE (bindings absent) => closed', async () => {
  const cached = envelope('CONTINUE', 'ALLOW');
  const lkg = { async get() { return cached; }, async put() {} };
  const o = await guardToolCall(TRIGGER, throwFactory, {
    client: mockClient({ preflight: () => { throw Object.assign(new Error('fetch failed'), { name: 'TypeError' }); } }),
    failPolicy: 'lkg', lkg,
  });
  assert.equal(o.verdict.kind, 'UNAVAILABLE');
  assert.equal(o.verdict.resolution, 'CLOSED'); // dormant: no live LKG path in v1
  assert.equal(o.executionAttempted, false);
});

// ── onEvent never throws out ──────────────────────────────────────────────────────
test('onEvent that throws does not break guardToolCall', async () => {
  const o = await guardToolCall(TRIGGER, okFactory, { client: mockClient(), onEvent: () => { throw new Error('sink boom'); } });
  assert.equal(o.executed, true);
});
