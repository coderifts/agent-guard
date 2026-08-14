'use strict';

/**
 * cas-attestation.v1 — binder over GuardExecutionProof + ExecuteIfUnchangedOutcome.
 * Does not re-test proof assembly or FS adapter I/O; uses frozen-shaped fixtures.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildCasAttestation,
  isGuardExecutionProof,
  isExecuteIfUnchangedOutcome,
  CAS_ATTESTATION_SPEC,
  EXECUTION_PROOF_SPEC,
} = require('../dist/cjs/index.js');

const PROOF_LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
  conditional_write_is_host_asserted_not_cas_verified: true,
});

function proofVerified(overrides = {}) {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_cas_1',
    receipt: Object.freeze({
      verified: true,
      status: 'VERIFIED_CURRENT',
      expires_at: '2099-01-01T00:00:00.000Z',
    }),
    binds_to: Object.freeze({
      operation: 'tool_call',
      change_fp: 'sha256:' + 'c'.repeat(64),
    }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({
      status: 'hashed',
      algorithm: 'sha256',
      value: 'sha256:' + 'a'.repeat(64),
    }),
    limits: PROOF_LIMITS,
    ...overrides,
  });
}

function proofUnverified() {
  return proofVerified({
    decision_id: 'dec_cas_unauth',
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
    currently_authorized: false,
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
    verdict_kind: 'BLOCK',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
  });
}

describe('cas-attestation — guards', () => {
  it('isGuardExecutionProof accepts v1 proof_spec', () => {
    assert.equal(isGuardExecutionProof(proofVerified()), true);
    assert.equal(isGuardExecutionProof(null), false);
    assert.equal(isGuardExecutionProof({ proof_spec: 'nope' }), false);
    assert.equal(isGuardExecutionProof({}), false);
  });

  it('isExecuteIfUnchangedOutcome accepts the three branches only', () => {
    assert.equal(isExecuteIfUnchangedOutcome({ status: 'committed', result: 1, version_token: 't1' }), true);
    assert.equal(isExecuteIfUnchangedOutcome({
      status: 'refused', reason: 'stale_version_token', expected_token: 'e', current_token: 'c',
    }), true);
    assert.equal(isExecuteIfUnchangedOutcome({
      status: 'committed_stale_detected',
      reason: 'stale_during_commit',
      result: 1,
      expected_token: 'e',
      post_commit_token: 'p',
    }), true);
    assert.equal(isExecuteIfUnchangedOutcome({ status: 'committed' }), false);
    assert.equal(isExecuteIfUnchangedOutcome({ status: 'other' }), false);
    assert.equal(isExecuteIfUnchangedOutcome(null), false);
  });
});

describe('buildCasAttestation — three outcome branches', () => {
  it('committed: lifts references, version_token, authorized_and_committed when receipt verified', () => {
    const proof = proofVerified();
    const outcome = { status: 'committed', result: 'ok', version_token: 'fs:v1:1:abc' };
    const att = buildCasAttestation(proof, outcome);

    assert.equal(att.attestation_spec, CAS_ATTESTATION_SPEC);
    assert.equal(att.attestation_spec, 'cas-attestation.v1');
    assert.equal(att.references.decision_id, 'dec_cas_1');
    assert.equal(att.references.change_fp, 'sha256:' + 'c'.repeat(64));
    assert.equal(att.references.operation, 'tool_call');
    assert.equal(att.references.receipt_verified, true);
    assert.equal(att.references.execution_result_hash.status, 'hashed');
    assert.equal(att.cas.status, 'committed');
    assert.equal(att.cas.write_ran, true);
    assert.equal(att.cas.version_token, 'fs:v1:1:abc');
    assert.equal(att.cas.expected_token, undefined, 'no invented expected_token on committed');
    assert.equal(att.derived.authorized_and_committed, true);
    assert.equal(att.derived.write_ran, true);
    assert.equal(att.derived.stale_during_commit, false);
    assert.equal(att.derived.refused, false);
    assert.equal(att.limits.does_not_claim_only_write_on_host, true);
    assert.equal(att.limits.does_not_claim_version_token_proves_change_fp_match, true);
    assert.equal(att.limits.does_not_claim_committed_stale_is_safe, true);
  });

  it('refused: NOT committed, expected+current tokens only, no invented version_token', () => {
    const proof = proofVerified();
    const outcome = {
      status: 'refused',
      reason: 'stale_version_token',
      expected_token: 'fs:v1:old',
      current_token: 'fs:v1:new',
    };
    const att = buildCasAttestation(proof, outcome);
    assert.equal(att.cas.status, 'refused');
    assert.equal(att.cas.write_ran, false);
    assert.equal(att.cas.reason, 'stale_version_token');
    assert.equal(att.cas.expected_token, 'fs:v1:old');
    assert.equal(att.cas.current_token, 'fs:v1:new');
    assert.equal(att.cas.version_token, undefined);
    assert.equal(att.cas.post_commit_token, undefined);
    assert.equal(att.derived.authorized_and_committed, false);
    assert.equal(att.derived.write_ran, false);
    assert.equal(att.derived.refused, true);
    assert.equal(att.derived.stale_during_commit, false);
  });

  it('committed_stale_detected: write ran + honesty flags; post_commit_token carried', () => {
    const proof = proofVerified();
    const outcome = {
      status: 'committed_stale_detected',
      reason: 'stale_during_commit',
      result: 'wrote',
      expected_token: 'fs:v1:pre',
      post_commit_token: 'fs:v1:other',
    };
    const att = buildCasAttestation(proof, outcome);
    assert.equal(att.cas.status, 'committed_stale_detected');
    assert.equal(att.cas.write_ran, true);
    assert.equal(att.cas.reason, 'stale_during_commit');
    assert.equal(att.cas.expected_token, 'fs:v1:pre');
    assert.equal(att.cas.post_commit_token, 'fs:v1:other');
    assert.equal(att.cas.version_token, undefined, 'clean committed version_token not invented');
    assert.equal(att.derived.authorized_and_committed, false, 'stale path is not clean authorized_and_committed');
    assert.equal(att.derived.write_ran, true);
    assert.equal(att.derived.stale_during_commit, true);
    assert.equal(att.derived.refused, false);
    assert.equal(att.limits.does_not_claim_committed_stale_is_safe, true);
  });

  it('unverified receipt + committed → authorized_and_committed false', () => {
    const att = buildCasAttestation(
      proofUnverified(),
      { status: 'committed', result: 1, version_token: 't' },
    );
    assert.equal(att.references.receipt_verified, false);
    assert.equal(att.derived.authorized_and_committed, false);
    assert.equal(att.cas.status, 'committed');
  });
});

describe('buildCasAttestation — validation-first rejection', () => {
  it('invalid proof object → TypeError (not a soft pass)', () => {
    assert.throws(
      () => buildCasAttestation(null, { status: 'committed', result: 1, version_token: 't' }),
      (err) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /guard-execution-proof\.v1/);
        return true;
      },
    );
    assert.throws(
      () => buildCasAttestation({ proof_spec: 'other.v1' }, { status: 'committed', result: 1, version_token: 't' }),
      /guard-execution-proof\.v1/,
    );
  });

  it('invalid outcome shape → TypeError', () => {
    assert.throws(
      () => buildCasAttestation(proofVerified(), { status: 'nope' }),
      (err) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /ExecuteIfUnchangedOutcome/);
        return true;
      },
    );
  });
});

describe('buildCasAttestation — immutability', () => {
  it('returned record is frozen (top-level + nested)', () => {
    const att = buildCasAttestation(
      proofVerified(),
      { status: 'committed', result: 'x', version_token: 'tok' },
    );
    assert.ok(Object.isFrozen(att));
    assert.ok(Object.isFrozen(att.references));
    assert.ok(Object.isFrozen(att.cas));
    assert.ok(Object.isFrozen(att.derived));
    assert.ok(Object.isFrozen(att.limits));
    assert.throws(() => {
      att.attestation_spec = 'mutated';
    }, TypeError);
    assert.throws(() => {
      att.derived.write_ran = false;
    }, TypeError);
  });
});
