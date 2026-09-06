'use strict';

/**
 * The guard's verdict IS the core's verdict (1459).
 *
 * The guard used to reach the right answer with a formula of its own. Correct, and bespoke — and a
 * predicate written twice is a predicate that drifts, which is exactly how the Atomic bypass
 * happened: two formulas for one question, disagreeing.
 *
 * This asserts the property directly rather than the current answers: for a shared fixture set,
 * whatever the core says, the guard says. A future edit to either side that changes one and not
 * the other fails here even if both answers look plausible on their own.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const cas = require('../dist/cjs/cas-attestation.js');
const sdk = require('@coderifts/sdk');
const { verifiedExecutionBinding } = require('../src/vendor/verified-execution-binding.js');

const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;
const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');

const executor = crypto.generateKeyPairSync('ed25519');
const issuer = crypto.generateKeyPairSync('ed25519');
const EK = 'EXEC';
const IK = 'ISS';
const JTI = 'jti-parity';
const SCOPE = sha('cs');
const RD = sha('receipt');

const registry = {
  keys: [{
    kid: EK, public_key_pem: executor.publicKey.export({ type: 'spki', format: 'pem' }),
    status: 'active', valid_from: null, retired_at: null,
  }],
};
const issuerKeyring = {
  keys: [{ kid: IK, public_key_pem: issuer.publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }],
};
const ring = new Map(issuerKeyring.keys.map((k) => [k.kid, {
  publicKey: crypto.createPublicKey(k.public_key_pem), status: 'active', retired_at: null, compromised_at: null,
}]));

function grant(over = {}, key = issuer.privateKey) {
  const body = {
    v: 'cr.exec.v1', kid: IK, receipt_digest: RD, scope_hash: SCOPE, audience: 'v:x',
    operation: 'merge', target_id: 't', jti: JTI,
    iat: '2026-01-01T00:00:00Z', exp: '2099-01-01T00:00:00Z', ...over,
  };
  const parts = ['crexec.v1', body.kid, body.receipt_digest, body.scope_hash, body.audience,
    body.operation, body.target_id, body.jti, body.iat, body.exp];
  return `${b64(body)}.${crypto.sign(null, Buffer.from(parts.join('|'), 'utf8'), key).toString('base64url')}`;
}
const REAL = grant();
const FORGED = `${REAL.split('.')[0]}.${Buffer.from('NOPE').toString('base64url')}`;
const OTHER_RUN = grant({ jti: 'jti-other', scope_hash: sha('other') });

const attBody = {
  v: sdk.ATTEST_VERSION, executor_kid: EK, grant_jti: JTI, receipt_digest: RD,
  scope_hash: SCOPE, committed_at: new Date(Date.now() - 1000).toISOString(),
};
const ATTEST = [sdk.ATTEST_ENVELOPE_TAG, EK, b64(attBody),
  crypto.sign(null, Buffer.from(sdk.attestSigningInput(attBody), 'utf8'), executor.privateKey).toString('base64url'),
].join('|');

const PROOF = {
  proof_spec: 'guard-execution-proof.v1', decision_id: 'd',
  binds_to: { change_fp: 'f', operation: 'merge' },
  receipt: { token: 'T', verified: true },
  execution_result_hash: { value: sha('r'), algo: 'sha256' },
  receipt_verified: true,
};

/** The SAME inputs, asked twice: once through the guard, once through the core directly. */
function bothWays(grantToken, { keyring = issuerKeyring, committed = true } = {}) {
  const outcome = {
    status: committed ? 'committed' : 'refused',
    ...(committed ? { version_token: 'vt' } : { reason: 'stale_version_token', expected_token: 'x' }),
    executor_attestation: ATTEST,
    grant: grantToken,
  };
  const guard = cas.buildCasAttestation(PROOF, outcome, {
    registry, grant_keyring: keyring, profile: 'ENFORCING_STRICT',
  });
  const core = verifiedExecutionBinding({
    receipt: { verified: true },
    grant: { token: grantToken || '', keyring: keyring ? ring : null, expectedKid: null },
    attestation: { token: ATTEST, registry, verify: sdk.verifyExecutionAttestation },
    committed,
    required: ['issuer_grant', 'executor_attestation'],
  });
  return { guard: guard.derived.authorized_and_committed, core: core.authorized_and_committed, state: core.state };
}

const CASES = {
  'a real issuer grant': [REAL, {}],
  'a forged signature': [FORGED, {}],
  'a real grant from another run': [OTHER_RUN, {}],
  'no grant at all': ['', {}],
  'a real grant with no keyring': [REAL, { keyring: null }],
  'a real grant, not committed': [REAL, { committed: false }],
};

describe('the guard quotes the core predicate', () => {
  for (const [name, [tok, o]] of Object.entries(CASES)) {
    it(`PARITY: ${name} — the guard and the core agree`, () => {
      const r = bothWays(tok, o);
      assert.equal(r.guard, r.core,
        `the guard says ${r.guard} and the core says ${r.core} (${r.state}) on: ${name}`);
    });
  }

  it('the positive control is TRUE, so parity is not agreement on refusing everything', () => {
    const r = bothWays(REAL, {});
    assert.equal(r.guard, true);
    assert.equal(r.core, true);
    assert.equal(r.state, 'AUTHORIZED_AND_COMMITTED');
  });

  it('the guard SURFACES the core\'s named state, not only a boolean', () => {
    const a = cas.buildCasAttestation(PROOF, {
      status: 'committed', version_token: 'vt', executor_attestation: ATTEST, grant: FORGED,
    }, { registry, grant_keyring: issuerKeyring, profile: 'ENFORCING_ATOMIC' });
    assert.equal(a.derived.authorization_state, 'UNAUTHORIZED');
  });
});
