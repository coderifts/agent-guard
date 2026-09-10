'use strict';

/**
 * 1535 — a deny must be actionable, not merely accurate.
 *
 * MEASURED before this existed: the guard's refusal vocabulary is 4 AvailabilityCause + 15
 * IntegrityCause values (src/types.ts) and NONE produced a next step. `deny-remedy.v1` beside it
 * covers three GRANT classes and is pinned to a published schema, so it could not be widened
 * without changing what that pinned document means everywhere it is copied.
 *
 * A deny with no next_action is a dead gate: the bot halts, a human is summoned, and the protocol
 * becomes a support ticket.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { buildDenyTeaching, mappedCauses, NEXT_ACTION } = require('../dist/cjs/index.js');

describe('deny-teaching.v1 — every refusal carries reason + next_action + payload shape', () => {
  it('the three shapes are always present, whatever the cause', () => {
    for (const cause of [...mappedCauses(), 'A_CAUSE_NOBODY_HAS_SEEN']) {
      const t = buildDenyTeaching(cause, 'human sentence');
      assert.equal(t.v, 'coderifts.deny.v1', cause);
      assert.equal(t.reason, cause.toUpperCase(), cause);
      assert.ok(Object.values(NEXT_ACTION).includes(t.next_action), `${cause}: ${t.next_action}`);
      assert.equal(typeof t.payload_shape, 'object', cause);
      assert.equal(typeof t.retryable, 'boolean', cause);
      // The human sentence is KEPT. The block is the contract; the sentence is what a person reads.
      assert.equal(t.human, 'human sentence', cause);
    }
  });

  it('an action that needs a call names the call and its fields', () => {
    for (const cause of mappedCauses()) {
      const t = buildDenyTeaching(cause, 'x');
      if (t.next_action === NEXT_ACTION.ESCALATE_HUMAN) continue;
      assert.equal(t.payload_shape.tool, 'preflight_change_set',
        `${cause} sends the caller somewhere without naming the tool`);
      assert.ok(Object.keys(t.payload_shape).length >= 2,
        `${cause}: a next_action whose payload shape is one key teaches nothing`);
    }
  });

  it('ESCALATE_HUMAN carries no payload — it is not a call', () => {
    const t = buildDenyTeaching('CONFIG_ERROR', 'x');
    assert.equal(t.next_action, NEXT_ACTION.ESCALATE_HUMAN);
    assert.deepEqual(t.payload_shape, {});
    assert.equal(t.retryable, false);
  });

  it('an UNMAPPED cause escalates rather than guessing', () => {
    // The alternative — defaulting to the nearest class — sends a bot to a call that does not
    // address why it was refused, and it looks like an answer.
    const t = buildDenyTeaching('SOME_FUTURE_CAUSE', 'x');
    assert.equal(t.next_action, NEXT_ACTION.ESCALATE_HUMAN);
  });

  it('ONLY the transient class is retryable', () => {
    // A REPREFLIGHT is a DIFFERENT call, not a retry. Marking it retryable would invite a bot to
    // resend the request that was just refused, forever.
    for (const cause of mappedCauses()) {
      const t = buildDenyTeaching(cause, 'x');
      assert.equal(t.retryable, t.next_action === NEXT_ACTION.RETRY_SAME, cause);
    }
  });

  it('the guard\'s whole refusal vocabulary is mapped — no cause falls through silently', () => {
    // Read out of types.ts rather than restated here: a second copy of the vocabulary would drift
    // from the one the guard actually emits, and this test would police a list nothing uses.
    const types = fs.readFileSync(path.join(__dirname, '..', 'src', 'types.ts'), 'utf8');
    const grab = (name) => {
      const m = new RegExp(`export type ${name} =([\\s\\S]*?);`).exec(types);
      assert.ok(m, `${name} is gone from types.ts — this test no longer measures the real vocabulary`);
      return [...m[1].matchAll(/'([A-Z_]+)'/g)].map((x) => x[1]);
    };
    const causes = [...grab('AvailabilityCause'), ...grab('IntegrityCause')];
    assert.ok(causes.length >= 15, `only ${causes.length} causes parsed`);
    const mapped = new Set(mappedCauses());
    const unmapped = causes.filter((c) => !mapped.has(c));
    assert.deepEqual(unmapped, [],
      `these causes reach a caller with no next step: ${unmapped.join(', ')}`);
  });
});

/**
 * 1534 — the citable pair on the surface a model actually reads.
 */
describe('surfaceEnvelopeFields lifts the citable pair', () => {
  const { surfaceEnvelopeFields } = require('../dist/cjs/index.js');

  it('grant_id and receipt_digest reach the block', () => {
    const out = surfaceEnvelopeFields({
      decision_id: 'dec_1', decision: 'ALLOW', execution_action: 'CONTINUE',
      execution_grant: { grant_id: 'grt_9' },
      receipt: { token: 't', digest: 'sha256:abc' },
    });
    assert.equal(out.grant_id, 'grt_9');
    assert.equal(out.receipt_digest, 'sha256:abc');
  });

  it('a flat grant_id is read too — producers differ', () => {
    const out = surfaceEnvelopeFields({ decision_id: 'd', grant_id: 'grt_flat' });
    assert.equal(out.grant_id, 'grt_flat');
  });

  it('ABSENT, not null, when there is no grant — the two are different facts', () => {
    // A caller must be able to tell "no grant was issued" from "a grant was issued and I lost
    // its id". A null-filled key erases that distinction.
    const out = surfaceEnvelopeFields({ decision_id: 'd', decision: 'ALLOW' });
    assert.equal('grant_id' in out, false);
    assert.equal('receipt_digest' in out, false);
  });

  it('nothing is computed here — a digest is lifted or absent', () => {
    // Hashing the token locally could produce a digest that differs from the one the gate quotes,
    // and two digests for one receipt is worse than one missing digest.
    const out = surfaceEnvelopeFields({ decision_id: 'd', receipt: { token: 'a-real-token' } });
    assert.equal('receipt_digest' in out, false);
  });
});
