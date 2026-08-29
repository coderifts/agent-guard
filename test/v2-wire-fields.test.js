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
};

describe('AUDIT P1 / RES-1 — the V2 field set on the authorize request', () => {
  it('a fully configured v2 grant sends every V2 field, in the wire spelling', () => {
    const r = v2WireFields({ executionGrant: full });
    assert.deepEqual(Object.keys(r.fields).sort(), [...ALL_WIRE].sort());
    assert.deepEqual(r.absent, []);
    assert.equal(r.fields.executor_id, 'exec-7');
    assert.equal(r.fields.target_uri, 'postgres://articles');
    assert.equal(r.fields.audience_hash, 'sha256:aa');
  });

  it('an UNCONFIGURED field is NAMED absent, never sent as a placeholder', () => {
    const r = v2WireFields({ executionGrant: { enabled: true, grantVersion: 'v2', executorId: 'exec-7' } });
    assert.deepEqual(Object.keys(r.fields), ['executor_id']);
    assert.deepEqual(r.absent.sort(), ['adapter_id', 'audience_hash', 'policy_hash', 'target_uri', 'tenant_id']);
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
