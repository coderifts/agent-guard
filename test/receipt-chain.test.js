/**
 * Pure receipt-chain LINKAGE vectors — no network, no filesystem.
 * Tokens are unsigned synthetic bodies; this suite never checks Ed25519.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  verifyReceiptChainLinkage,
  previousReceiptCommitment,
  decodeReceiptBodyPrev,
  RECEIPT_PREV_NULL,
} = require('../dist/cjs/index.js');

/** Build a two-segment token with the given body.prev (sig is ignored by the linkage verifier). */
function tokenWithPrev(prev) {
  const body = Buffer.from(JSON.stringify({
    v: 4, kid: 'test', fp: 'sha256:fp', prev, caller: 'test', ts: '2026-01-01T00:00:00.000Z',
    reg: '', ir: '', expires_at: '2026-01-01T01:00:00.000Z', bh: 'sha256:bh',
  }), 'utf8').toString('base64url');
  return `${body}.fakesig`;
}

function sha256prev(token) {
  return 'sha256:' + createHash('sha256').update(token, 'utf8').digest('hex');
}

describe('verifyReceiptChainLinkage (pure linkage)', () => {
  it('empty list is vacuously ok', () => {
    const r = verifyReceiptChainLinkage([]);
    assert.deepEqual(r, { ok: true, length: 0 });
  });

  it('single root token (prev=null) is ok', () => {
    const t0 = tokenWithPrev(RECEIPT_PREV_NULL);
    const r = verifyReceiptChainLinkage([t0]);
    assert.equal(r.ok, true);
    assert.equal(r.length, 1);
  });

  it('two tokens forming a valid link', () => {
    const t0 = tokenWithPrev(RECEIPT_PREV_NULL);
    const t1 = tokenWithPrev(previousReceiptCommitment(t0));
    assert.equal(previousReceiptCommitment(t0), sha256prev(t0));
    const r = verifyReceiptChainLinkage([t0, t1]);
    assert.equal(r.ok, true);
    assert.equal(r.length, 2);
  });

  it('broken link in the middle, reported by index', () => {
    const t0 = tokenWithPrev(RECEIPT_PREV_NULL);
    const t1 = tokenWithPrev(previousReceiptCommitment(t0));
    // t2 claims a predecessor that is not t1
    const t2 = tokenWithPrev(previousReceiptCommitment(t0));
    const r = verifyReceiptChainLinkage([t0, t1, t2]);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 2);
    assert.equal(r.reason, 'broken_link');
    assert.equal(r.expected, previousReceiptCommitment(t1));
    assert.equal(r.actual, previousReceiptCommitment(t0));
  });

  // THE FEATURE EXISTS FOR THIS CASE: dropping a middle receipt must fail linkage,
  // not pass per-token "looks like a receipt" checks alone.
  it('list with a middle token removed fails at the orphan child (missing link)', () => {
    const t0 = tokenWithPrev(RECEIPT_PREV_NULL);
    const t1 = tokenWithPrev(previousReceiptCommitment(t0));
    const t2 = tokenWithPrev(previousReceiptCommitment(t1));
    // Present [t0, t2] — t2's prev is sha256(t1), not sha256(t0)
    const r = verifyReceiptChainLinkage([t0, t2]);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 1);
    assert.equal(r.reason, 'broken_link');
    assert.equal(r.expected, previousReceiptCommitment(t0));
    assert.equal(r.actual, previousReceiptCommitment(t1));
  });

  // THE FEATURE EXISTS FOR THIS CASE: reordering valid tokens breaks the chain relation.
  it('reordered list fails linkage', () => {
    const t0 = tokenWithPrev(RECEIPT_PREV_NULL);
    const t1 = tokenWithPrev(previousReceiptCommitment(t0));
    const t2 = tokenWithPrev(previousReceiptCommitment(t1));
    const r = verifyReceiptChainLinkage([t0, t2, t1]);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'broken_link');
    // First failure is at index 1 (t2 does not follow t0)
    assert.equal(r.failedAt, 1);
  });

  it('first token with non-null prev is unexpected_predecessor (not broken_link)', () => {
    const orphan = tokenWithPrev(previousReceiptCommitment('some-prior-token'));
    const r = verifyReceiptChainLinkage([orphan]);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 0);
    assert.equal(r.reason, 'unexpected_predecessor');
    assert.equal(r.expected, RECEIPT_PREV_NULL);
  });

  it('malformed token is reported by index', () => {
    const r = verifyReceiptChainLinkage(['not-a-token']);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 0);
    assert.equal(r.reason, 'malformed_token');
  });

  it('decodeReceiptBodyPrev reads prev from a well-formed body', () => {
    const t = tokenWithPrev(RECEIPT_PREV_NULL);
    assert.deepEqual(decodeReceiptBodyPrev(t), { prev: RECEIPT_PREV_NULL });
  });
});

// ── Threading previous_receipt into preflight (stateless read, no cursor) ──────
const { guardToolCall, computeBodyHash } = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

describe('previousReceipt threading (no package-held cursor)', () => {
  const TRIGGER = {
    toolName: 'Edit',
    arguments: {},
    artifacts: [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }],
  };

  function allowClient(capture) {
    let lastEnv = null;
    return {
      async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet(req) {
        capture.req = req;
        lastEnv = {
          spec_version: 'decision-result.v1.1',
          decision: 'ALLOW',
          execution_action: 'CONTINUE',
          decision_id: 'dec_1',
          correlation_id: 'c',
          evaluated_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 900000).toISOString(),
          fingerprint: 'sha256:' + 'a'.repeat(64),
          input_fingerprint: 'sha256:' + 'b'.repeat(64),
          receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
        };
        return { decision: 'ALLOW', decision_result: lastEnv };
      },
      async verifyReceipt() { return boundVerify(lastEnv); },
    };
  }

  it('string previousReceipt is sent as previous_receipt on the preflight body', async () => {
    const capture = {};
    await guardToolCall(TRIGGER, async () => ({ ok: true }), {
      client: allowClient(capture),
      previousReceipt: 'PRIOR_TOKEN_ABC',
    });
    assert.equal(capture.req.previous_receipt, 'PRIOR_TOKEN_ABC');
  });

  it('getter previousReceipt is invoked once per call and not stored by the package', async () => {
    const capture = {};
    let n = 0;
    const getter = () => { n += 1; return n === 1 ? 'FIRST' : 'SECOND'; };
    const client = allowClient(capture);
    await guardToolCall(TRIGGER, async () => ({ ok: true }), { client, previousReceipt: getter });
    assert.equal(capture.req.previous_receipt, 'FIRST');
    assert.equal(n, 1);
    await guardToolCall(TRIGGER, async () => ({ ok: true }), { client, previousReceipt: getter });
    assert.equal(capture.req.previous_receipt, 'SECOND');
    assert.equal(n, 2);
  });

  it('omitted previousReceipt leaves previous_receipt undefined (root)', async () => {
    const capture = {};
    await guardToolCall(TRIGGER, async () => ({ ok: true }), { client: allowClient(capture) });
    assert.equal(capture.req.previous_receipt, undefined);
  });
});
