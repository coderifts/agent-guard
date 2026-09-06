'use strict';

/**
 * RELEASE-BLOCKING: the same probe must read authorized_and_committed=false in EVERY enforcing
 * profile (1447 / 1459).
 *
 * ── REPRODUCED ON THE PUBLIC 17.2.0 ─────────────────────────────────────────────────────────
 *
 * A valid receipt, a FORGED-signature execution grant, and a REAL attestation from a trusted
 * executor bound to that forged grant's jti and scope:
 *
 *     ENFORCING_STRICT  authorized_and_committed = false
 *     ENFORCING_ATOMIC  authorized_and_committed = true
 *
 * Two profiles of one product, one set of bytes, opposite answers. The Atomic formula was
 * `receipt_verified && committed && class === 'executor_attested'` and never asked whether the
 * grant was signed. An attestation only ever says "I committed the grant with these ids"; it
 * cannot say the ids belonged to a grant anyone authorized.
 *
 * ── WHY A MATRIX AND NOT A CASE ─────────────────────────────────────────────────────────────
 *
 * The bug was a DISAGREEMENT between two profiles, so a test that checks one profile could not
 * have found it and cannot keep it from coming back. Every row runs under every enforcing profile,
 * and the positive control runs there too — without it, "everything is false" would pass.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const cas = require('../dist/cjs/cas-attestation.js');
const sdk = require('@coderifts/sdk');

const PROFILES = ['ENFORCING_STRICT', 'ENFORCING_ATOMIC'];
const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;
const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');

const executor = crypto.generateKeyPairSync('ed25519');
const issuer = crypto.generateKeyPairSync('ed25519');
const other = crypto.generateKeyPairSync('ed25519');
const EK = 'TRUSTED-EXECUTOR';
const IK = 'coderifts-issuer';

const registry = {
  keys: [{
    kid: EK, public_key_pem: executor.publicKey.export({ type: 'spki', format: 'pem' }),
    status: 'active', valid_from: null, retired_at: null,
  }],
};
const issuerKeyring = {
  keys: [{ kid: IK, public_key_pem: issuer.publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }],
};

const JTI = 'jti-matrix-1';
const SCOPE = sha('changeset');
const RD = sha('receipt');

function grantBody(over = {}) {
  return {
    v: 'cr.exec.v1', kid: IK, receipt_digest: RD, scope_hash: SCOPE, audience: 'v:x',
    operation: 'merge', target_id: 't', jti: JTI,
    iat: '2026-01-01T00:00:00Z', exp: '2099-01-01T00:00:00Z', ...over,
  };
}
function signGrant(body, key) {
  const parts = ['crexec.v1', body.kid, body.receipt_digest, body.scope_hash, body.audience,
    body.operation, body.target_id, body.jti, body.iat, body.exp];
  if (body.state_nonce) parts.push(body.state_nonce);
  return `${b64(body)}.${crypto.sign(null, Buffer.from(parts.join('|'), 'utf8'), key).toString('base64url')}`;
}
const REAL_GRANT = signGrant(grantBody(), issuer.privateKey);
const FORGED_GRANT = `${b64(grantBody())}.${Buffer.from('NOT-A-SIGNATURE').toString('base64url')}`;
const WRONG_KEY_GRANT = signGrant(grantBody(), other.privateKey);
// A REAL grant, correctly signed — for a DIFFERENT run. Authentic, and not this one.
const ANOTHER_RUN_GRANT = signGrant(grantBody({ jti: 'jti-another-run', scope_hash: sha('other') }), issuer.privateKey);

function attestation() {
  const body = {
    v: sdk.ATTEST_VERSION, executor_kid: EK, grant_jti: JTI, receipt_digest: RD,
    scope_hash: SCOPE, committed_at: new Date(Date.now() - 1000).toISOString(),
  };
  return [sdk.ATTEST_ENVELOPE_TAG, EK, b64(body),
    crypto.sign(null, Buffer.from(sdk.attestSigningInput(body), 'utf8'), executor.privateKey).toString('base64url'),
  ].join('|');
}
const ATTEST = attestation();

const PROOF = {
  proof_spec: 'guard-execution-proof.v1',
  decision_id: 'd1',
  binds_to: { change_fp: 'fp', operation: 'merge' },
  receipt: { token: 'RECEIPT-TOKEN', verified: true },
  execution_result_hash: { value: sha('r'), algo: 'sha256' },
  receipt_verified: true,
};

function judge(profile, outcomeExtra, optsExtra) {
  const outcome = {
    status: 'committed', version_token: 'vt', executor_attestation: ATTEST, ...outcomeExtra,
  };
  const a = cas.buildCasAttestation(PROOF, outcome, {
    registry, grant_keyring: issuerKeyring, profile, ...optsExtra,
  });
  return a.derived.authorized_and_committed;
}

/** [name, outcome fields, opts override] — every row must be FALSE in every enforcing profile. */
const NEGATIVES = [
  ['forged grant signature', { grant: FORGED_GRANT, receipt_digest: RD }, {}],
  ['grant signed by the WRONG key', { grant: WRONG_KEY_GRANT, receipt_digest: RD }, {}],
  ['a REAL grant from ANOTHER run', { grant: ANOTHER_RUN_GRANT, receipt_digest: RD }, {}],
  ['no grant at all, bare receipt_digest', { receipt_digest: RD }, {}],
  ['no grant at all, bare grant_fields', {}, { grant_fields: { jti: JTI, scope_hash: SCOPE } }],
  ['a real grant with NO issuer keyring', { grant: REAL_GRANT, receipt_digest: RD }, { grant_keyring: null }],
];

describe('authorization matrix — every enforcing profile agrees', () => {
  it('the attestation is genuinely valid, so every row below is about the GRANT', () => {
    const v = sdk.verifyExecutionAttestation(ATTEST, { registry });
    assert.equal(v.valid, true, `${v.status}/${v.reason}`);
  });

  for (const profile of PROFILES) {
    for (const [name, outcomeExtra, optsExtra] of NEGATIVES) {
      it(`${profile}: ${name} → NOT authorized_and_committed`, () => {
        assert.equal(judge(profile, outcomeExtra, optsExtra), false,
          `${profile} granted authorized_and_committed on: ${name}`);
      });
    }

    it(`${profile}: POSITIVE CONTROL — a real issuer grant + a real attestation IS green`, () => {
      // Without this the whole matrix would pass by refusing everything, and "safe" would be
      // indistinguishable from "broken".
      assert.equal(judge(profile, { grant: REAL_GRANT, receipt_digest: RD }, {}), true,
        `${profile} refused a genuinely authorized commit`);
    });
  }

  it('THE DISAGREEMENT ITSELF: both profiles return the same verdict on the same bytes', () => {
    // The bug was not "Atomic is wrong"; it was "two enforcing profiles disagree". This asserts
    // the property directly, so a future divergence fails here even if both answers look plausible.
    for (const [name, outcomeExtra, optsExtra] of [...NEGATIVES,
      ['positive control', { grant: REAL_GRANT, receipt_digest: RD }, {}]]) {
      const answers = PROFILES.map((p) => judge(p, outcomeExtra, optsExtra));
      assert.equal(new Set(answers).size, 1,
        `the profiles disagree on "${name}": ${PROFILES.map((p, i) => `${p}=${answers[i]}`).join(', ')}`);
    }
  });
});
