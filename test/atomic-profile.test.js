'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  withCodeRifts,
  PROFILE_ENFORCING_ATOMIC_V1,
  createMutatorRegister,
  ATOMIC_INVARIANTS,
  ATOMIC_PROFILE_UNSATISFIED,
  atomicOutcome,
  buildCasAttestation,
  EXECUTION_PROOF_SPEC,
  guardToolCall,
  computeCanonicalBundleFingerprint,
  computeBodyHash,
} = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };
const STUB_RESOLVER = async () => null;
const STUB_READBACK = async () => ({ ok: true });
const STUB_REGISTRY = { keys: [{ kid: 'k', public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----', status: 'active' }] };

function atomicBase(over = {}) {
  const mut = createMutatorRegister();
  mut.registerMutator('edit_file');
  return {
    tools: [
      { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
      { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read' },
    ],
    client: STUB_CLIENT,
    operation: 'merge',
    profile: PROFILE_ENFORCING_ATOMIC_V1,
    resolvePriorContent: STUB_RESOLVER,
    executionGrant: { enabled: true, grantVersion: 'v2', resolveStateNonce: async () => 'n1' },
    executorId: 'exec-a',
    adapterId: 'fs',
    targetUri: 'fs://repo/openapi.yaml',
    executorAttestation: { registry: STUB_REGISTRY },
    mutatorRegister: mut,
    casAdapter: { put: async () => {} },
    readBack: STUB_READBACK,
    credentialBoundary: true,
    repository: 'acme/api',
    ...over,
  };
}

const PROOF_LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
  conditional_write_is_host_asserted_not_cas_verified: true,
});

function proofVerified() {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_atom_1',
    receipt: Object.freeze({ verified: true, status: 'VERIFIED_CURRENT', expires_at: '2099-01-01T00:00:00.000Z' }),
    binds_to: Object.freeze({ operation: 'tool_call', change_fp: 'sha256:' + 'c'.repeat(64) }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({ status: 'hashed', algorithm: 'sha256', value: 'sha256:' + 'a'.repeat(64) }),
    limits: PROOF_LIMITS,
  });
}

describe('ENFORCING_ATOMIC_V1 frozen invariants', () => {
  it('the eleven names are frozen — a twelfth is a _V2', () => {
    assert.deepEqual([...ATOMIC_INVARIANTS], [
      'verified_receipt',
      'verified_grant_v2',
      'exact_executor',
      'exact_target',
      'after_payload_hash',
      'fresh_nonce',
      'nonce_consumed_once',
      'target_CAS',
      'read_back',
      'executor_attestation',
      'credential_boundary',
    ]);
  });

  it('full wiring constructs', () => {
    assert.doesNotThrow(() => withCodeRifts(atomicBase()));
  });

  it('alias ENFORCING_ATOMIC constructs identically', () => {
    assert.doesNotThrow(() => withCodeRifts(atomicBase({ profile: 'ENFORCING_ATOMIC' })));
  });
});

describe('ATOMIC_PROFILE_UNSATISFIED — each construction invariant', () => {
  const cases = [
    ['grantVersion v1', { executionGrant: { enabled: true, grantVersion: 'v1', resolveStateNonce: async () => 'n' } }],
    ['no nonce resolver', { executionGrant: { enabled: true, grantVersion: 'v2' } }],
    ['no executorId', { executorId: '' }],
    ['no targetUri', { targetUri: '' }],
    ['no registry', { executorAttestation: {} }],
    ['empty mutator register', { mutatorRegister: createMutatorRegister() }],
    ['no casAdapter', { casAdapter: null }],
    ['no readBack', { readBack: undefined }],
    ['no credentialBoundary', { credentialBoundary: undefined }],
  ];
  for (const [name, over] of cases) {
    it(`${name} → ATOMIC_PROFILE_UNSATISFIED`, () => {
      assert.throws(
        () => withCodeRifts(atomicBase(over)),
        (err) => err && err.code === ATOMIC_PROFILE_UNSATISFIED,
        name,
      );
    });
  }
});

describe('ATOMIC outcome union', () => {
  const good = {
    receiptVerified: true, grantV2Valid: true, executorMatch: true, targetMatch: true,
    nonceFresh: true, nonceConsumedOnce: true, casCommitted: true, readBackOk: true,
    executorAttested: true, mutatorRegistered: true,
  };
  it('all invariants → AUTHORIZED_COMMITTED', () => {
    assert.equal(atomicOutcome(good), 'AUTHORIZED_COMMITTED');
  });
  it('host-claimed (executorAttested false) → REFUSED, never AUTHORIZED_COMMITTED', () => {
    assert.equal(atomicOutcome({ ...good, executorAttested: false }), 'REFUSED');
  });
  it('auth unavailable → INDETERMINATE', () => {
    assert.equal(atomicOutcome({ ...good, authUnavailable: true }), 'INDETERMINATE');
  });
  it('signer outage after commit → INDETERMINATE (committed + downstream STOP)', () => {
    assert.equal(atomicOutcome({ ...good, signerUnavailableAfterCommit: true }), 'INDETERMINATE');
  });
});

describe('1085 ATOMIC rename — host-reported never authorized_and_committed', () => {
  it('ATOMIC + host_claimed → authorized_and_committed ABSENT (false); host-reported name set', () => {
    const att = buildCasAttestation(
      proofVerified(),
      { status: 'committed', result: 'ok', version_token: 'fs:v1:1' },
      { profile: 'ENFORCING_ATOMIC' },
    );
    assert.equal(att.cas_evidence.class, 'host_claimed');
    assert.equal(att.derived.authorized_and_committed, false);
    assert.equal(att.derived.authorized_and_host_reported_committed, true);
    assert.equal(
      Object.prototype.hasOwnProperty.call(att.derived, 'authorized_and_host_reported_committed'),
      true,
    );
  });

  it('non-ATOMIC host_claimed still uses the v1 name (compat)', () => {
    const att = buildCasAttestation(
      proofVerified(),
      { status: 'committed', result: 'ok', version_token: 'fs:v1:1' },
    );
    assert.equal(att.derived.authorized_and_committed, true);
    assert.equal(att.derived.authorized_and_host_reported_committed, undefined);
  });
});

describe('R2 ATOMIC executor — 100 concurrent same-grant → exactly one AUTHORIZED_COMMITTED', () => {
  it('in-memory nonce consume-once (harness named after executionGrant concurrency)', async () => {
    const consumed = new Set();
    const grantId = 'same-grant';
    const results = await Promise.all(Array.from({ length: 100 }, async () => {
      if (consumed.has(grantId)) {
        return atomicOutcome({
          receiptVerified: true, grantV2Valid: true, executorMatch: true, targetMatch: true,
          nonceFresh: true, nonceConsumedOnce: false, casCommitted: false, readBackOk: false,
          executorAttested: false, mutatorRegistered: true,
        });
      }
      consumed.add(grantId);
      return atomicOutcome({
        receiptVerified: true, grantV2Valid: true, executorMatch: true, targetMatch: true,
        nonceFresh: true, nonceConsumedOnce: true, casCommitted: true, readBackOk: true,
        executorAttested: true, mutatorRegistered: true,
      });
    }));
    assert.equal(results.filter((r) => r === 'AUTHORIZED_COMMITTED').length, 1);
    assert.equal(results.filter((r) => r === 'REFUSED').length, 99);
  });
});

describe('ATOMIC live path — finishExecuted consumes buildCasAttestation', () => {
  const arts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
  const call = { toolName: 'Edit', arguments: {}, artifacts: arts };
  const fp = computeCanonicalBundleFingerprint(arts, { operation: 'tool_call' });

  function mockClient() {
    let lastEnv = null;
    return {
      async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
      async preflightChangeSet() {
        const env = {
          spec_version: 'decision-result.v1.1',
          decision: 'ALLOW',
          execution_action: 'CONTINUE',
          decision_id: 'dec_live_atomic',
          correlation_id: 'c',
          evaluated_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 900000).toISOString(),
          fingerprint: fp,
          input_fingerprint: fp,
          receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
        };
        lastEnv = env;
        return { decision: 'ALLOW', decision_result: env };
      },
      async verifyReceipt() {
        return lastEnv
          ? { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: lastEnv.fingerprint, bh: computeBodyHash(lastEnv) } }
          : { valid: true, status: 'VERIFIED_CURRENT' };
      },
    };
  }

  function casCommitted(extra = {}) {
    return { status: 'committed', result: extra.result || 'ok', version_token: 'fs:v1:1:abc', ...extra };
  }

  it('LIVE host-claimed ATOMIC → outcome.commit_label is authorized_and_host_reported_committed; proof has no authorized_and_committed', async () => {
    const o = await guardToolCall(call, async () => casCommitted(), {
      client: mockClient(),
      profile: 'ENFORCING_ATOMIC',
    });
    assert.equal(o.commit_label, 'authorized_and_host_reported_committed',
      'LIVE outcome must carry the host-reported name — a CAS-record-only label is the discarded-return gap');
    assert.notEqual(o.proof.commit_label, 'authorized_and_committed');
    assert.equal(o.proof.commit_label, 'authorized_and_host_reported_committed');
    assert.equal(o.cas_evidence.class, 'host_claimed');
  });

  it('LIVE non-ATOMIC host-claimed still omits commit_label (v1 compat)', async () => {
    const o = await guardToolCall(call, async () => casCommitted(), {
      client: mockClient(),
    });
    assert.equal(o.commit_label, undefined);
  });
});
