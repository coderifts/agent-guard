'use strict';

/**
 * 1402 — the audience binding reached the server through NEITHER channel.
 *
 * MEASURED 2026-09-06, read-only, against coderifts-app:
 *   change-set.js:1138          reads TOP-LEVEL `input.audience`, strict /^v:[0-9a-f]{12}$/
 *   (no reference anywhere)     `context.audience` is NOT read
 *   execution-grant-v2.js:166   the ISSUER derives `audience_hash: sha256pref(audience)`
 *   execution-grant-request.v2.producer.json — "`audience_hash` is NOT a request field of its
 *                               own … sending it separately has no effect"
 *
 * The Guard sent `context.audience` (unread) and `audience_hash` (unread). A host that configured
 * an audience got a grant minted under the issuer's sha256('') default and no way to see it.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  guardToolCall, computeBodyHash, computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');
// Module-local, not on the package entry — read it where it lives (same as the parity test).
const { V2_WIRE_FIELDS } = require('../dist/cjs/execution-grant.js');

const ARTS = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
const FP = computeCanonicalBundleFingerprint(ARTS, { operation: 'tool_call' });
const CALL = { toolName: 'Edit', arguments: {}, artifacts: ARTS };
const ok = async () => ({ ok: true });

/** The server's derivation, copied verbatim from execution-grant-v2.js:166. */
const sha256pref = (v) => `sha256:${crypto.createHash('sha256').update(String(v == null ? '' : v)).digest('hex')}`;

function envelope() {
  return {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', execution_action: 'CONTINUE',
    decision_id: 'd', correlation_id: 'c', evaluated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900000).toISOString(),
    fingerprint: FP, input_fingerprint: FP,
    receipt: { token: 't', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}

/** Captures the request the Guard actually puts on the wire. */
async function capture(config = {}) {
  const seen = [];
  let last = null;
  const client = {
    async authorizeChangeSet(r) { return this.preflightChangeSet(r); },
    async preflightChangeSet(r) { seen.push(r); last = envelope(); return { decision: 'ALLOW', decision_result: last }; },
    async verifyReceipt() {
      return { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: last.fingerprint, bh: computeBodyHash(last) } };
    },
  };
  const events = [];
  await guardToolCall(CALL, ok, { client, onEvent: (e) => events.push(e), ...config });
  return { request: seen[0] || {}, events };
}

const AUD = 'v:a1b2c3d4e5f6';

describe('1402 — the audience reaches the field the server reads', () => {
  it('a configured audience is sent TOP-LEVEL', async () => {
    const { request } = await capture({ audience: AUD });
    assert.equal(request.audience, AUD);
  });

  it('and the server would derive the hash the host intended', async () => {
    // The end-to-end property, expressed without a server: apply the server's own derivation to
    // what the Guard sent, and compare with the host's intent. Before the fix these differed —
    // the Guard sent nothing readable, so the issuer hashed the empty string.
    const { request } = await capture({ audience: AUD });
    assert.equal(sha256pref(request.audience), sha256pref(AUD));
    assert.notEqual(sha256pref(request.audience), sha256pref(''),
      'the sha256("") default is what a severed binding produced');
  });

  it('it is sent on a plain authorize too, not only when a grant is requested', async () => {
    // The first version of this fix lived inside the grant branch, and left the binding severed
    // for every call that did not ask for a grant — which is most of them. Caught by this test.
    const withGrant = await capture({ audience: AUD, executionGrant: { grantVersion: 'v2', resolveStateNonce: async () => 'n' } });
    const plain = await capture({ audience: AUD });
    assert.equal(withGrant.request.audience, AUD);
    assert.equal(plain.request.audience, AUD);
  });

  it('the inert audience_hash is no longer sent', async () => {
    const { request } = await capture({ audience: AUD, executionGrant: { grantVersion: 'v2', audienceHash: 'sha256:aa', resolveStateNonce: async () => 'n' } });
    assert.equal(request.audience_hash, undefined, 'the handler never read it');
    assert.equal(V2_WIRE_FIELDS.map(([w]) => w).includes('audience_hash'), false);
  });
});

describe('1402 — a value the server would discard is NAMED, not sent', () => {
  it('a free-form audience is withheld and reported', async () => {
    // Sending it would look like a binding and produce none — the same bug in a smaller size.
    const { request, events } = await capture({ audience: 'acme-prod' });
    assert.equal(request.audience, undefined);
    const named = events.filter((e) => e.type === 'audience_not_bindable');
    assert.equal(named.length, 1, 'silence here would hide a misconfiguration');
    assert.match(named[0].cause, /v:<12 hex>/);
  });

  it('NON-VACUITY: the form check accepts the measured shape and rejects near-misses', async () => {
    for (const good of ['v:000000000000', 'v:a1b2c3d4e5f6', 'v:ffffffffffff']) {
      assert.equal((await capture({ audience: good })).request.audience, good, good);
    }
    for (const bad of ['v:A1B2C3D4E5F6', 'v:a1b2c3', 'v:a1b2c3d4e5f67', 'a1b2c3d4e5f6', '']) {
      assert.equal((await capture({ audience: bad })).request.audience, undefined, JSON.stringify(bad));
    }
  });

  it('no audience configured sends no field — absence is not an empty string', async () => {
    // An empty audience would hash to sha256(''), which is exactly the value a severed binding
    // produced. Sending it would make "unconfigured" indistinguishable from "broken".
    const { request, events } = await capture({});
    assert.equal('audience' in request, false);
    assert.equal(events.filter((e) => e.type === 'audience_not_bindable').length, 0);
  });
});
