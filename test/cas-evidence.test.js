'use strict';

/**
 * S2-F2a R3 — cas_evidence executor_attested | host_claimed | absent.
 * Observation-side only. Invalid attestation must not upgrade the class.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  buildCasAttestation,
  evaluateCasEvidence,
  extractExecutorAttestationToken,
  EXECUTION_PROOF_SPEC,
  renderFinalAnswerProof,
} = require('../dist/cjs/index.js');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'exec-test-k1';
const PEM = publicKey.export({ type: 'spki', format: 'pem' });
const ATTEST_VERSION = 'cr.exec.attest.v1';
const ENVELOPE_TAG = 'cr.exec.attest.v1';
const SIGNING_PREFIX = 'crexecattest.v1';
const SCOPE = 'sha256:' + 'ab'.repeat(32);
const RD = 'sha256:' + 'cd'.repeat(32);
const JTI = 'jti-1';
const COMMITTED = '2026-06-15T12:00:00Z';

function registry() {
  return {
    keys: [{
      kid: KID,
      public_key_pem: PEM,
      status: 'active',
      valid_from: '2026-01-01T00:00:00Z',
      retired_at: null,
    }],
  };
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signingInput(body) {
  return [
    SIGNING_PREFIX,
    body.executor_kid,
    body.grant_jti,
    body.receipt_digest,
    body.scope_hash,
    body.state_nonce || '',
    body.committed_at,
    body.result_digest || '',
  ].join('|');
}

function issueAttest(over = {}) {
  const body = {
    v: ATTEST_VERSION,
    executor_kid: KID,
    grant_jti: over.grant_jti || JTI,
    receipt_digest: over.receipt_digest || RD,
    scope_hash: over.scope_hash || SCOPE,
    committed_at: COMMITTED,
  };
  const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), privateKey);
  return [ENVELOPE_TAG, body.executor_kid, b64url(Buffer.from(JSON.stringify(body), 'utf8')), b64url(sig)].join('|');
}

const PROOF_LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
  conditional_write_is_host_asserted_not_cas_verified: true,
  commit_observation_is_observed_at_t3_not_atomic: true,
});

function proofVerified(over = {}) {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_cas_ev_1',
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
    commit_observation: Object.freeze({
      status: 'observed_match',
      observed_at: '2026-06-15T12:00:00Z',
      host_attestation: 'host_attested_committed',
    }),
    ...over,
  });
}

function committed(extra = {}) {
  return { status: 'committed', result: extra.result || 'ok', version_token: 'fs:v1:1:abc', ...extra };
}

describe('cas_evidence — evaluateCasEvidence', () => {
  it('valid attestation → executor_attested + fields', () => {
    const tok = issueAttest();
    const ev = evaluateCasEvidence(
      committed({ executor_attestation: tok }),
      { registry: registry() },
    );
    assert.equal(ev.class, 'executor_attested');
    assert.equal(ev.attest_status, 'ATTEST_VALID');
    assert.equal(ev.executor_kid, KID);
    assert.equal(ev.grant_jti, JTI);
  });

  it('token on mutation result.executor_attestation is found', () => {
    const tok = issueAttest();
    assert.equal(
      extractExecutorAttestationToken(committed({ result: { executor_attestation: tok } })),
      tok,
    );
    const ev = evaluateCasEvidence(
      committed({ result: { executor_attestation: tok } }),
      { registry: registry() },
    );
    assert.equal(ev.class, 'executor_attested');
  });

  it('invalid sig → host_claimed + status visible (does not upgrade)', () => {
    const tok = issueAttest();
    const parts = tok.split('|');
    const sig = Buffer.from(parts[3], 'base64url');
    sig[0] ^= 0xff;
    const bad = [...parts.slice(0, 3), sig.toString('base64url')].join('|');
    const ev = evaluateCasEvidence(
      committed({ executor_attestation: bad }),
      { registry: registry() },
    );
    assert.equal(ev.class, 'host_claimed');
    assert.equal(ev.attest_status, 'ATTEST_INVALID_SIGNATURE');
    assert.notEqual(ev.class, 'executor_attested');
  });

  it('unbound (wrong jti) → host_claimed', () => {
    const tok = issueAttest();
    const grantBody = {
      v: 'cr.exec.v1',
      kid: 'gk',
      receipt_digest: RD,
      scope_hash: SCOPE,
      audience: 'v:x',
      operation: 'merge',
      target_id: 't',
      jti: 'other-jti',
      iat: COMMITTED,
      exp: '2099-01-01T00:00:00Z',
    };
    const grant = `${b64url(Buffer.from(JSON.stringify(grantBody), 'utf8'))}.${b64url(Buffer.from('x'))}`;
    const ev = evaluateCasEvidence(
      committed({ executor_attestation: tok, result: { grant } }),
      { registry: registry() },
    );
    assert.equal(ev.class, 'host_claimed');
    assert.equal(ev.attest_status, 'ATTEST_UNBOUND');
  });

  it('no registry configured → host_claimed (no verification, no penalty)', () => {
    const tok = issueAttest();
    const ev = evaluateCasEvidence(committed({ executor_attestation: tok }), {});
    assert.equal(ev.class, 'host_claimed');
    assert.equal(ev.attest_status, null);
  });

  it('refused CAS outcome → absent', () => {
    const ev = evaluateCasEvidence({
      status: 'refused',
      reason: 'stale_version_token',
      expected_token: 'e',
      current_token: 'c',
    }, { registry: registry() });
    assert.equal(ev.class, 'absent');
  });

  it('determinism: same inputs twice → same evidence object fields', () => {
    const tok = issueAttest();
    const outcome = committed({ executor_attestation: tok });
    const a = evaluateCasEvidence(outcome, { registry: registry() });
    const b = evaluateCasEvidence(outcome, { registry: registry() });
    assert.deepEqual(a, b);
  });
});

describe('buildCasAttestation — cas_evidence attached', () => {
  it('committed without token → host_claimed (today\'s host claim)', () => {
    const att = buildCasAttestation(
      proofVerified(),
      committed(),
    );
    assert.equal(att.derived.authorized_and_committed, true);
    assert.equal(att.cas_evidence.class, 'host_claimed');
    assert.equal(att.cas_evidence.attest_status, null);
  });

  it('committed + valid token + registry → executor_attested; authorized_and_committed unchanged', () => {
    const tok = issueAttest();
    const att = buildCasAttestation(
      proofVerified(),
      committed({ executor_attestation: tok }),
      { registry: registry() },
    );
    assert.equal(att.derived.authorized_and_committed, true);
    assert.equal(att.cas_evidence.class, 'executor_attested');
    assert.equal(att.cas_evidence.attest_status, 'ATTEST_VALID');
  });
});

describe('T3 wording snapshots', () => {
  const T3_HOST =
    'host attestation is a host claim layered on the measurement';
  const T3_EXEC = 'committed — executor-attested (ATTEST_VALID, kid exec-test-k1)';
  const T3_LYING = 'committed — host-claimed (attest_status ATTEST_INVALID_SIGNATURE)';

  it('default T3 line keeps host-claim wording', () => {
    const text = renderFinalAnswerProof(proofVerified());
    assert.match(text, new RegExp(T3_HOST));
    assert.equal(text.includes('executor-attested'), false);
  });

  it('executor_attested upgrades the T3 commit line', () => {
    const text = renderFinalAnswerProof(proofVerified({
      cas_evidence: Object.freeze({
        class: 'executor_attested',
        attest_status: 'ATTEST_VALID',
        executor_kid: KID,
        grant_jti: JTI,
      }),
    }));
    assert.match(text, new RegExp(T3_EXEC.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    // Limits list still names the T3-not-atomic residual; the T3 section is what upgraded.
  });

  it('invalid attestation keeps host-claimed wording + visible status', () => {
    const text = renderFinalAnswerProof(proofVerified({
      cas_evidence: Object.freeze({
        class: 'host_claimed',
        attest_status: 'ATTEST_INVALID_SIGNATURE',
        executor_kid: KID,
        grant_jti: JTI,
      }),
    }));
    assert.match(text, new RegExp(T3_LYING.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(text, new RegExp(T3_HOST));
  });
});
