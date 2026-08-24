'use strict';

/**
 * P0-3 — ENFORCING_STRICT final success is authorized_and_committed only with
 * executor_attested CAS evidence that cross-checks grant/receipt (jti + scope_hash +
 * receipt_digest). enforced remains the PRE-WRITE fact. Non-strict is byte-identical.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  guardToolCall,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  buildCasAttestation,
  evaluateCasEvidence,
  renderFinalAnswerProof,
  deriveProofBanner,
  EXECUTION_PROOF_SPEC,
} = require('../dist/cjs/index.js');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'exec-strict-k1';
const PEM = publicKey.export({ type: 'spki', format: 'pem' });
const ATTEST_VERSION = 'cr.exec.attest.v1';
const ENVELOPE_TAG = 'cr.exec.attest.v1';
const SIGNING_PREFIX = 'crexecattest.v1';
const SCOPE = 'sha256:' + 'ab'.repeat(32);
const RD = 'sha256:' + 'cd'.repeat(32);
const JTI = 'jti-strict-1';
const COMMITTED = '2026-06-15T12:00:00Z';

const TRIGGER_ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
const TRIGGER = { toolName: 'Edit', arguments: {}, artifacts: TRIGGER_ARTIFACTS };
const TRIGGER_FP = computeCanonicalBundleFingerprint(TRIGGER_ARTIFACTS, { operation: 'tool_call' });

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: opts.decision_id || 'dec_strict',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint || TRIGGER_FP,
    input_fingerprint: opts.fingerprint || TRIGGER_FP,
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}

function mockClient() {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const env = envelope('CONTINUE', 'ALLOW');
      lastEnv = env;
      return { decision: 'ALLOW', decision_result: env };
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

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

function matchingGrant(over = {}) {
  const grantBody = {
    v: 'cr.exec.v1',
    kid: 'gk',
    receipt_digest: over.receipt_digest || RD,
    scope_hash: over.scope_hash || SCOPE,
    audience: 'v:x',
    operation: 'merge',
    target_id: 't',
    jti: over.jti || JTI,
    iat: COMMITTED,
    exp: '2099-01-01T00:00:00Z',
  };
  return `${b64url(Buffer.from(JSON.stringify(grantBody), 'utf8'))}.${b64url(Buffer.from('x'))}`;
}

function casCommitted(extra = {}) {
  return {
    status: 'committed',
    result: extra.result || 'ok',
    version_token: 'fs:v1:1:abc',
    ...extra,
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
  commit_observation_is_observed_at_t3_not_atomic: true,
});

function proofVerified(over = {}) {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_strict_1',
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

async function runStrict(factory, extraCfg = {}) {
  return guardToolCall(TRIGGER, factory, {
    client: mockClient(),
    profile: 'ENFORCING_STRICT',
    executorAttestation: { registry: registry() },
    ...extraCfg,
  });
}

describe('P0-3 ENFORCING_STRICT — authorized_and_committed requires executor attestation', () => {
  it('strict + valid attestation (jti/scope/receipt_digest match) → authorized_and_committed', async () => {
    const tok = issueAttest();
    const grant = matchingGrant();
    const o = await runStrict(async () => casCommitted({
      executor_attestation: tok,
      grant,
      receipt_digest: RD,
    }));
    assert.equal(o.enforced, true, 'enforced stays the pre-write fact');
    assert.equal(o.executed, true);
    assert.equal(o.cas_evidence.class, 'executor_attested');
    assert.equal(o.commit_label, 'authorized_and_committed');
    assert.equal(o.commit_evidence_reason, undefined);
    assert.equal(o.proof.commit_label, 'authorized_and_committed');
    assert.equal(deriveProofBanner(o.proof), 'AUTHORIZED_AND_COMMITTED');
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /executor-attested/);
    assert.equal(text.includes('commit not proven'), false);
  });

  it('strict + host_claimed (no token) → authorized_not_committed + commit_evidence_missing', async () => {
    const o = await runStrict(async () => casCommitted());
    assert.equal(o.enforced, true);
    assert.equal(o.cas_evidence.class, 'host_claimed');
    assert.equal(o.commit_label, 'authorized_not_committed');
    assert.equal(o.commit_evidence_reason, 'commit_evidence_missing');
    assert.equal(o.proof.commit_label, 'authorized_not_committed');
    assert.equal(o.proof.commit_evidence_reason, 'commit_evidence_missing');
    assert.equal(deriveProofBanner(o.proof), 'AUTHORIZED_NOT_COMMITTED');
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /authorized; commit not proven \(no executor attestation\)/);
  });

  it('strict + absent CAS (plain factory result) → authorized_not_committed + reason', async () => {
    const o = await runStrict(async () => ({ ok: true }));
    assert.equal(o.enforced, true);
    assert.equal(o.cas_evidence.class, 'absent');
    assert.equal(o.commit_label, 'authorized_not_committed');
    assert.equal(o.commit_evidence_reason, 'commit_evidence_missing');
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /authorized; commit not proven \(no executor attestation\)/);
  });

  it('strict + attestation whose jti mismatches → NOT attested (lying never upgrades)', async () => {
    const tok = issueAttest();
    const grant = matchingGrant({ jti: 'other-jti' });
    const o = await runStrict(async () => casCommitted({
      executor_attestation: tok,
      grant,
      receipt_digest: RD,
    }));
    assert.equal(o.cas_evidence.class, 'host_claimed');
    assert.equal(o.cas_evidence.attest_status, 'ATTEST_UNBOUND');
    assert.notEqual(o.cas_evidence.class, 'executor_attested');
    assert.equal(o.commit_label, 'authorized_not_committed');
    assert.equal(o.commit_evidence_reason, 'commit_evidence_missing');
  });

  it('strict + attestation whose scope_hash mismatches → NOT attested', async () => {
    const tok = issueAttest();
    const grant = matchingGrant({ scope_hash: 'sha256:' + 'ff'.repeat(32) });
    const o = await runStrict(async () => casCommitted({
      executor_attestation: tok,
      grant,
      receipt_digest: RD,
    }));
    assert.equal(o.cas_evidence.class, 'host_claimed');
    assert.equal(o.commit_label, 'authorized_not_committed');
  });

  it('strict + valid token but no grant/receipt binding to cross-check → not committed', async () => {
    const tok = issueAttest();
    const o = await runStrict(async () => casCommitted({ executor_attestation: tok }));
    assert.equal(o.cas_evidence.class, 'executor_attested', 'signature-only still executor_attested (9.0.0 class)');
    assert.equal(o.commit_label, 'authorized_not_committed', 'strict success requires the kernel cross-check');
    assert.equal(o.commit_evidence_reason, 'commit_evidence_missing');
  });
});

describe('P0-3 non-strict — byte-identical to 9.0.0', () => {
  it('absent profile: no commit_label; host_claimed committed still authorized_and_committed on CAS record', async () => {
    const o = await guardToolCall(TRIGGER, async () => casCommitted(), {
      client: mockClient(),
    });
    assert.equal(o.enforced, true);
    assert.equal(o.commit_label, undefined);
    assert.equal(o.commit_evidence_reason, undefined);
    assert.equal(o.proof.commit_label, undefined);
    assert.equal(deriveProofBanner(o.proof), 'ENFORCED');
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /host attestation is a host claim layered on the measurement/);
    assert.equal(text.includes('commit not proven'), false);
    assert.equal(text.includes('AUTHORIZED AND COMMITTED'), false);
    assert.equal(text.includes('AUTHORIZED_NOT_COMMITTED'), false);

    const att = buildCasAttestation(proofVerified(), casCommitted());
    assert.equal(att.derived.authorized_and_committed, true);
    assert.equal(att.cas_evidence.class, 'host_claimed');
  });

  it('evaluateCasEvidence class unchanged without profile (valid token → executor_attested)', () => {
    const tok = issueAttest();
    const ev = evaluateCasEvidence(
      casCommitted({ executor_attestation: tok }),
      { registry: registry() },
    );
    assert.equal(ev.class, 'executor_attested');
  });
});

describe('P0-3 buildCasAttestation — strict tightens derived.authorized_and_committed', () => {
  it('non-strict committed + host_claimed → authorized_and_committed true (today)', () => {
    const att = buildCasAttestation(proofVerified(), casCommitted());
    assert.equal(att.derived.authorized_and_committed, true);
  });

  it('strict committed + host_claimed → authorized_and_committed false', () => {
    const att = buildCasAttestation(proofVerified(), casCommitted(), { profile: 'ENFORCING_STRICT' });
    assert.equal(att.derived.authorized_and_committed, false);
    assert.equal(att.cas_evidence.class, 'host_claimed');
  });

  it('strict committed + executor_attested + binding → authorized_and_committed true', () => {
    const tok = issueAttest();
    const grant = matchingGrant();
    const att = buildCasAttestation(
      proofVerified(),
      casCommitted({ executor_attestation: tok, grant, receipt_digest: RD }),
      { registry: registry(), profile: 'ENFORCING_STRICT' },
    );
    assert.equal(att.cas_evidence.class, 'executor_attested');
    assert.equal(att.derived.authorized_and_committed, true);
  });
});

describe('P0-3 proof wording snapshots (strict)', () => {
  const STRICT_NOT_COMMITTED = 'authorized; commit not proven (no executor attestation)';

  it('strict not-committed proof banner + T3 line', () => {
    const text = renderFinalAnswerProof(proofVerified({
      commit_label: 'authorized_not_committed',
      commit_evidence_reason: 'commit_evidence_missing',
      cas_evidence: Object.freeze({
        class: 'host_claimed',
        attest_status: null,
        executor_kid: null,
        grant_jti: null,
      }),
    }));
    assert.match(text, new RegExp(STRICT_NOT_COMMITTED.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(text, /AUTHORIZED_NOT_COMMITTED/);
  });

  it('strict committed proof keeps executor-attested T3 line', () => {
    const text = renderFinalAnswerProof(proofVerified({
      commit_label: 'authorized_and_committed',
      cas_evidence: Object.freeze({
        class: 'executor_attested',
        attest_status: 'ATTEST_VALID',
        executor_kid: KID,
        grant_jti: JTI,
      }),
    }));
    assert.match(text, /AUTHORIZED_AND_COMMITTED/);
    assert.match(text, /executor-attested \(ATTEST_VALID, kid exec-strict-k1\)/);
    assert.equal(text.includes(STRICT_NOT_COMMITTED), false);
  });
});
