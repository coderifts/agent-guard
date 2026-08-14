'use strict';

/**
 * remediation-loop-attestation.v1 — pure binder (cas-attestation family pattern).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildRemediationLoopAttestation,
  readRemediationTransaction,
  readPriorBlockRemediation,
  REMEDIATION_LOOP_ATTESTATION_SPEC,
  EXECUTION_PROOF_SPEC,
  CAS_ATTESTATION_SPEC,
  buildCasAttestation,
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

const REF_FP = 'sha256:' + '1'.repeat(64);
const NEW_FP = 'sha256:' + '2'.repeat(64);

function blockEnvelope(over = {}) {
  return {
    decision: 'BLOCK',
    decision_id: 'dec_block_loop_1',
    execution_action: 'STOP',
    fingerprint: REF_FP,
    remediation_transaction: {
      required_changes: [
        { id: 'rc1', target: '/v1/users' },
        { id: 'rc2', target: '/v1/orders' },
      ],
      resubmission: {
        unchanged_input: 'deterministic_block',
        modified_input: 'preflight_required',
        reference_fingerprint: REF_FP,
        fingerprint_profile: 'crbundle.v1',
        modified_is_not_permission: true,
      },
      next_preflight_required: true,
      recheck_scope: { targets: ['/v1/users', '/v1/orders'], precise: true },
      escalation: { path: 'human_review', when: 'changes_infeasible_or_disputed' },
    },
    ...over,
  };
}

function allowProof(change_fp = NEW_FP, decision_id = 'dec_allow_loop_1') {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id,
    receipt: Object.freeze({
      verified: true,
      status: 'VERIFIED_CURRENT',
      expires_at: '2099-01-01T00:00:00.000Z',
    }),
    binds_to: Object.freeze({
      operation: 'tool_call',
      change_fp,
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
  });
}

function casCommitted(proof) {
  return buildCasAttestation(proof, {
    status: 'committed',
    result: 'ok',
    version_token: 'fs:v1:1:deadbeef',
  });
}

describe('readRemediationTransaction / readPriorBlockRemediation', () => {
  it('reads measured remediation_transaction fields from a BLOCK envelope', () => {
    const tx = readRemediationTransaction(blockEnvelope());
    assert.ok(tx);
    assert.equal(tx.resubmission.reference_fingerprint, REF_FP);
    assert.equal(tx.required_changes.length, 2);
    assert.equal(tx.resubmission.modified_is_not_permission, true);

    const block = readPriorBlockRemediation(blockEnvelope());
    assert.equal(block.decision_id, 'dec_block_loop_1');
    assert.equal(block.required_changes_count, 2);
    assert.ok(block.recheck_scope);
  });

  it('rejects ALLOW envelope / missing transaction', () => {
    assert.equal(readPriorBlockRemediation({ decision: 'ALLOW', decision_id: 'x' }), null);
    assert.equal(
      readPriorBlockRemediation({ decision: 'BLOCK', decision_id: 'x' }),
      null,
    );
  });
});

describe('buildRemediationLoopAttestation', () => {
  it('valid BLOCK + ALLOW + cas → loop_committed true, input_changed, frozen', () => {
    const proof = allowProof();
    const cas = casCommitted(proof);
    assert.equal(cas.attestation_spec, CAS_ATTESTATION_SPEC);

    const loop = buildRemediationLoopAttestation(blockEnvelope(), proof, cas);
    assert.equal(loop.attestation_spec, REMEDIATION_LOOP_ATTESTATION_SPEC);
    assert.equal(loop.attestation_spec, 'remediation-loop-attestation.v1');
    assert.equal(loop.references.block.decision_id, 'dec_block_loop_1');
    assert.equal(loop.references.block.reference_fingerprint, REF_FP);
    assert.equal(loop.references.block.required_changes_count, 2);
    assert.equal(loop.references.allow.decision_id, 'dec_allow_loop_1');
    assert.equal(loop.references.allow.change_fp, NEW_FP);
    assert.equal(loop.references.cas.status, 'committed');
    assert.equal(loop.references.cas.authorized_and_committed, true);
    assert.equal(loop.derived.input_changed, true);
    assert.equal(loop.derived.loop_committed, true);
    assert.equal(loop.limits.does_not_claim_patch_addressed_required_changes, true);
    assert.equal(loop.limits.does_not_claim_unchanged_input_is_permission, true);
    assert.ok(Object.isFrozen(loop));
    assert.ok(Object.isFrozen(loop.references));
    assert.ok(Object.isFrozen(loop.derived));
    assert.ok(Object.isFrozen(loop.limits));
  });

  it('missing cas → attests recheck+authorize only; loop_committed false; cas null', () => {
    const loop = buildRemediationLoopAttestation(blockEnvelope(), allowProof(), null);
    assert.equal(loop.references.cas, null);
    assert.equal(loop.derived.loop_committed, false);
    assert.equal(loop.derived.input_changed, true);
  });

  it('unchanged fingerprint → TypeError (refuse closure; modified_is_not_permission)', () => {
    assert.throws(
      () => buildRemediationLoopAttestation(blockEnvelope(), allowProof(REF_FP)),
      (err) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /input_unchanged|modified_is_not_permission/);
        return true;
      },
    );
  });

  it('invalid prior envelope (not BLOCK / no remediation transaction) → TypeError', () => {
    assert.throws(
      () => buildRemediationLoopAttestation({ decision: 'ALLOW', decision_id: 'a' }, allowProof()),
      /BLOCK envelope|remediation_transaction/,
    );
    assert.throws(
      () => buildRemediationLoopAttestation(
        { decision: 'BLOCK', decision_id: 'b' },
        allowProof(),
      ),
      /remediation_transaction/,
    );
  });

  it('invalid allow proof → TypeError', () => {
    assert.throws(
      () => buildRemediationLoopAttestation(blockEnvelope(), { proof_spec: 'nope' }),
      /guard-execution-proof/,
    );
  });

  it('allow proof without change_fp → TypeError', () => {
    const p = allowProof();
    const bad = Object.freeze({
      ...p,
      binds_to: Object.freeze({ operation: 'tool_call', change_fp: null }),
    });
    assert.throws(
      () => buildRemediationLoopAttestation(blockEnvelope(), bad),
      /change_fp/,
    );
  });

  it('invalid casAttestation when provided → TypeError', () => {
    assert.throws(
      () => buildRemediationLoopAttestation(blockEnvelope(), allowProof(), { attestation_spec: 'x' }),
      /cas-attestation\.v1/,
    );
  });

  it('no invented fields on the record', () => {
    const loop = buildRemediationLoopAttestation(blockEnvelope(), allowProof());
    assert.deepEqual(
      Object.keys(loop).sort(),
      ['attestation_spec', 'derived', 'limits', 'references'],
    );
    assert.deepEqual(
      Object.keys(loop.references).sort(),
      ['allow', 'block', 'cas'],
    );
    assert.equal('remediation_of' in loop, false);
    assert.equal('claimed_fixed' in loop, false);
  });
});
