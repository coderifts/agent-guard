'use strict';

/**
 * AUDIT P1 / RES-1 — the V2 fields reach the wire.
 *
 * MEASURED before writing: guard.ts's request builder set only
 * `include_execution_grant` and `state_nonce`, so the V2 binding the config
 * demands never left the process.
 *
 * ALSO MEASURED, and it corrects the brief's premise: the SDK's
 * PreflightChangeSetRequest declares NEITHER these fields NOR `state_nonce`
 * (node_modules/@coderifts/sdk/dist/esm/types.d.ts:205-221 is exactly
 * preflight_mode, artifacts, context, previous_receipt, idempotency_key,
 * include_execution_grant). The guard builds its own request literal and posts
 * it as `unknown`, so the wire shape is guard-local — which is why these fields
 * can be sent without touching SDK types, and why nothing here should claim the
 * SDK endorses them.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { v2WireFields, V2_WIRE_FIELDS } = require('../dist/cjs/execution-grant.js');

const ALL_WIRE = V2_WIRE_FIELDS.map(([wire]) => wire);
const full = {
  enabled: true,
  grantVersion: 'v2',
  executorId: 'exec-7',
  adapterId: 'pg',
  targetUri: 'postgres://articles',
  tenantId: 't-1',
  policyHash: 'sha256:pp',
  audienceHash: 'sha256:aa',
  expectedStateToken: 'st-1',
};

describe('AUDIT P1 / RES-1 — the V2 field set on the authorize request', () => {
  it('a fully configured v2 grant sends every V2 field, in the wire spelling', () => {
    const r = v2WireFields({ executionGrant: full });
    assert.deepEqual(Object.keys(r.fields).sort(), [...ALL_WIRE].sort());
    assert.deepEqual(r.absent, []);
    assert.equal(r.fields.executor_id, 'exec-7');
    assert.equal(r.fields.target_uri, 'postgres://articles');
    // 1402: audience_hash left this list. The server never read it — it derives the hash from
    // `audience`, which the Guard now sends top-level (guard.ts). Asserting its ABSENCE here is
    // what stops it being re-added as a field that looks bound and is not.
    assert.equal('audience_hash' in r.fields, false);
  });

  it('an UNCONFIGURED field is NAMED absent, never sent as a placeholder', () => {
    const r = v2WireFields({ executionGrant: { enabled: true, grantVersion: 'v2', executorId: 'exec-7' } });
    assert.deepEqual(Object.keys(r.fields), ['executor_id']);
    assert.deepEqual(r.absent.sort(), ['adapter_id', 'expected_state_token', 'policy_hash', 'target_uri', 'tenant_id']);
    for (const k of r.absent) {
      assert.ok(!(k in r.fields), `${k} was sent despite being unconfigured`);
    }
  });

  it('an EMPTY STRING is absent, not an empty value on the wire', () => {
    // An empty executor_id is indistinguishable from a real one that happens to
    // be blank, and the server would bind it. Absent is the honest answer.
    const r = v2WireFields({
      executionGrant: { ...full, executorId: '', targetUri: '', tenantId: '   ' ? '' : '' },
    });
    assert.ok(!('executor_id' in r.fields));
    assert.ok(!('target_uri' in r.fields));
    assert.ok(r.absent.includes('executor_id'));
    assert.ok(r.absent.includes('target_uri'));
  });

  it('a non-string value is absent, not coerced', () => {
    const r = v2WireFields({ executionGrant: { ...full, executorId: 42, adapterId: null } });
    assert.ok(!('executor_id' in r.fields));
    assert.ok(!('adapter_id' in r.fields));
    assert.ok(r.absent.includes('executor_id'));
    assert.ok(r.absent.includes('adapter_id'));
  });

  it('a v1 grant sends NO V2 fields even when they are configured', () => {
    // The fields describe a v2 binding. Attaching them to a v1 request would
    // assert a shape the grant does not have.
    const r = v2WireFields({ executionGrant: { ...full, grantVersion: 'v1' } });
    assert.deepEqual(r.fields, {});
    assert.deepEqual(r.absent.sort(), [...ALL_WIRE].sort());
  });

  it('no grant config at all sends nothing and names everything absent', () => {
    for (const c of [null, undefined, {}, { executionGrant: null }]) {
      const r = v2WireFields(c);
      assert.deepEqual(r.fields, {});
      assert.deepEqual(r.absent.sort(), [...ALL_WIRE].sort());
    }
  });

  it('every wire name is snake_case and distinct from its config key', () => {
    // The two spellings are deliberate: config is camelCase, the wire is not.
    // A single list defines both so they cannot drift.
    for (const [wire, key] of V2_WIRE_FIELDS) {
      assert.match(wire, /^[a-z]+(_[a-z]+)+$/, `${wire} is not snake_case`);
      assert.match(key, /^[a-z]+[A-Z]/, `${key} is not camelCase`);
    }
    assert.equal(new Set(ALL_WIRE).size, ALL_WIRE.length, 'duplicate wire name');
  });
});

// ── 1198: ONE CANONICAL SOURCE ───────────────────────────────────────────────
/**
 * The V2 identity used to live in two places with nothing reconciling them:
 * the TOP LEVEL of the withCodeRifts input (→ the ATOMIC construction check and
 * the posture tuple) and the nested executionGrant config (→ the authorize
 * request). A field set only at the top level never reached the wire; set in
 * both with different values, each half believed a different identity.
 *
 * 6bca531 called the wire-side absence "honest named-absent". The 1196 lesson
 * applies here too: named-absent is honest only while the value genuinely does
 * not exist. Once the config supplies it, absence is a binding gap.
 */
describe('AUDIT 1198 — the V2 identity has ONE source', () => {
  const { resolveV2Fields, V2_FIELD_KEYS } = require('../dist/cjs/execution-grant.js');

  it('a TOP-LEVEL field reaches the wire — the gap this closes', () => {
    // Before 1198 this returned {} : v2WireFields read executionGrant only.
    const r = v2WireFields({
      executorId: 'exec-7',
      targetUri: 'postgres://articles',
      executionGrant: { enabled: true, grantVersion: 'v2' },
    });
    assert.equal(r.fields.executor_id, 'exec-7');
    assert.equal(r.fields.target_uri, 'postgres://articles');
    assert.ok(!r.absent.includes('executor_id'));
  });

  it('the deprecated nested spelling still reaches the wire', () => {
    const r = v2WireFields({ executionGrant: { enabled: true, grantVersion: 'v2', adapterId: 'pg' } });
    assert.equal(r.fields.adapter_id, 'pg');
  });

  it('both spellings AGREEING is fine and yields one value', () => {
    const r = resolveV2Fields({
      executorId: 'exec-7',
      executionGrant: { executorId: 'exec-7', adapterId: 'pg' },
    });
    assert.deepEqual(r, { executorId: 'exec-7', adapterId: 'pg' });
  });

  it('both spellings DISAGREEING throws, naming BOTH values', () => {
    // Preferring one silently is what made the split invisible.
    assert.throws(
      () => resolveV2Fields({ executorId: 'exec-A', executionGrant: { executorId: 'exec-B' } }),
      (e) => e.code === 'V2_FIELDS_CONFLICT'
        && /top-level "exec-A" vs executionGrant\.executorId "exec-B"/.test(e.message)
        && /Set each field ONCE/.test(e.message),
    );
  });

  it('a disagreement on ANY of the six throws, not just the first three', () => {
    for (const key of V2_FIELD_KEYS) {
      assert.throws(
        () => resolveV2Fields({ [key]: 'a', executionGrant: { [key]: 'b' } }),
        // Substring, not a hand-escaped regex: the message format is the
        // contract here, and an escaping slip in the TEST would read as a
        // missing reconciliation in the CODE.
        (e) => e.code === 'V2_FIELDS_CONFLICT' && e.message.includes(`${key}: top-level`),
        `${key} does not reconcile`,
      );
    }
  });

  it('every conflicting field is listed, not only the first', () => {
    try {
      resolveV2Fields({
        executorId: 'a', adapterId: 'c',
        executionGrant: { executorId: 'b', adapterId: 'd' },
      });
      assert.fail('did not throw');
    } catch (e) {
      assert.match(e.message, /executorId:/);
      assert.match(e.message, /adapterId:/);
    }
  });

  it('an UNSUPPLIED field stays named-absent — the honest case is unchanged', () => {
    // 6bca531's named-absent is still correct where the Guard genuinely cannot
    // know the value. What changed is that a SUPPLIED value can no longer be
    // reported absent.
    const r = v2WireFields({ executorId: 'exec-7', executionGrant: { enabled: true, grantVersion: 'v2' } });
    assert.deepEqual(r.absent.sort(), ['adapter_id', 'expected_state_token', 'policy_hash', 'target_uri', 'tenant_id']);
    for (const k of r.absent) assert.ok(!(k in r.fields));
  });

  it('an empty string on one side is not a conflict — it is unsupplied', () => {
    // Only non-empty strings count as supplied, so '' vs 'x' takes 'x' rather
    // than throwing on a field nobody actually set twice.
    assert.deepEqual(resolveV2Fields({ executorId: '', executionGrant: { executorId: 'x' } }),
      { executorId: 'x' });
    assert.deepEqual(resolveV2Fields({ executorId: 'x', executionGrant: { executorId: '' } }),
      { executorId: 'x' });
  });

  it('no config at all resolves to nothing and throws nothing', () => {
    for (const c of [null, undefined, {}, { executionGrant: null }]) {
      assert.deepEqual(resolveV2Fields(c), {});
    }
  });
});

describe('expected_state_token joins the wire set (1206 F2)', () => {
  it('a configured expectedStateToken reaches the wire under its server spelling', () => {
    const r = v2WireFields({
      executionGrant: { enabled: true, grantVersion: 'v2', expectedStateToken: 'st-1' },
    });
    assert.equal(r.fields.expected_state_token, 'st-1');
    assert.ok(!r.absent.includes('expected_state_token'));
  });

  it('unconfigured, it is NAMED absent — never sent as an empty string', () => {
    // An empty expected_state_token on the wire is indistinguishable from a real one that
    // happens to be blank, and the server would bind it.
    const r = v2WireFields({ executionGrant: { enabled: true, grantVersion: 'v2', executorId: 'e' } });
    assert.ok(r.absent.includes('expected_state_token'));
    assert.ok(!('expected_state_token' in r.fields));
  });

  it('v1 does not send it — the field describes a v2 binding', () => {
    const r = v2WireFields({ executionGrant: { enabled: true, expectedStateToken: 'st-1' } });
    assert.deepEqual(r.fields, {});
    assert.ok(r.absent.includes('expected_state_token'));
  });

  it('it goes through the SAME one-source resolution as the other six', () => {
    // Top-level and nested must not diverge; a conflicting pair throws rather than picking one.
    const top = v2WireFields({ expectedStateToken: 'st-top', executionGrant: { enabled: true, grantVersion: 'v2' } });
    assert.equal(top.fields.expected_state_token, 'st-top');
    // Asserted on the CODE, which is the stable contract; the message wording is not.
    assert.throws(
      () => v2WireFields({
        expectedStateToken: 'st-top',
        executionGrant: { enabled: true, grantVersion: 'v2', expectedStateToken: 'st-nested' },
      }),
      (err) => err.code === 'V2_FIELDS_CONFLICT' && /expectedStateToken/.test(err.message),
    );
  });
});
