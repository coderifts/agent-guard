'use strict';

/**
 * The guard authenticates the EXECUTION GRANT, not just the receipt and the attestation (1431).
 *
 * ── WHAT WAS MEASURED, THEN CLOSED ──────────────────────────────────────────────────────────
 *
 * Before this landed, the guard's authentication surface was:
 *
 *   chain receipt          VERIFIED   vendored verify.js, offline, pinned keyring
 *   executor attestation   VERIFIED   SDK verifyExecutionAttestation, pinned executor registry
 *   execution grant        NEVER      `verifyExecutionGrant` appeared nowhere in src/
 *
 * The grant was still USED: the SDK's attestation cross-check DECODES it (`parseGrantFields`) and
 * compares jti / scope_hash / state_nonce against the attestation payload. So a token whose
 * payload copies those three values from the attestation, with the literal string NEM-ALAIRAS
 * where the signature belongs, satisfied the cross-check AND `bindingIntendedSupplied`, and
 * ENFORCING_STRICT reported `authorized_and_committed`.
 *
 * The reproduction is the first test below, and it now asserts the opposite.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const cas = require('../dist/cjs/cas-attestation.js');
const sdk = require('@coderifts/sdk');

const NUL = '\x1f';
const sha = (v) => crypto.createHash('sha256').update(String(v), 'utf8').digest('hex');

/** An executor key + a signed cr.exec.attest.v1 token binding a given jti / scope_hash. */
function attestation({ grant_jti, scope_hash }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const kid = 'TEST-EXECUTOR';
  const body = {
    v: sdk.ATTEST_VERSION,
    executor_kid: kid,
    grant_jti,
    receipt_digest: `sha256:${sha('receipt')}`,
    scope_hash,
    committed_at: new Date(Date.now() - 1000).toISOString(),
  };
  const sig = crypto.sign(null, Buffer.from(sdk.attestSigningInput(body), 'utf8'), privateKey)
    .toString('base64url');
  return {
    registry: {
      keys: [{
        kid,
        public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }),
        status: 'active',
        valid_from: null,
        retired_at: null,
      }],
    },
    token: [sdk.ATTEST_ENVELOPE_TAG, kid, Buffer.from(JSON.stringify(body), 'utf8').toString('base64url'), sig].join('|'),
    body,
  };
}

/** A genuinely signed cr.exec.v1 grant, plus the issuer keyring that verifies it. */
function signedGrant({ jti, scope_hash }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const kid = 'TEST-ISSUER';
  const now = new Date();
  const body = {
    v: 'cr.exec.v1',
    kid,
    receipt_digest: `sha256:${sha('receipt')}`,
    scope_hash,
    audience: 'v:test',
    operation: 'publish',
    target_id: '',
    jti,
    iat: new Date(now.getTime() - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    exp: new Date(now.getTime() + 300000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const input = ['crexec.v1', body.kid, body.receipt_digest, body.scope_hash, body.audience,
    body.operation, body.target_id, body.jti, body.iat, body.exp].join('|');
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), privateKey).toString('base64url');
  return {
    token: `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig}`,
    keyring: {
      keys: [{ kid, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }],
    },
  };
}

const JTI = 'jti-1234';
const SCOPE = `sha256:${sha(`publish${NUL}${NUL}body`)}`;

/** A grant that is NOT signed: the payload copies the attestation's binding fields. */
const FORGED = `${Buffer.from(JSON.stringify({
  v: 'cr.exec.v1', jti: JTI, scope_hash: SCOPE, receipt_digest: `sha256:${sha('receipt')}`,
}), 'utf8').toString('base64url')}.${Buffer.from('NEM-ALAIRAS').toString('base64url')}`;

describe('the guard authenticates the execution grant', () => {
  const att = attestation({ grant_jti: JTI, scope_hash: SCOPE });
  const outcome = { status: 'committed', version_token: 'vt-1', executor_attestation: att.token };
  const good = signedGrant({ jti: JTI, scope_hash: SCOPE });

  it('the attestation itself is genuinely valid — so every result below is about the GRANT', () => {
    const v = sdk.verifyExecutionAttestation(att.token, { registry: att.registry });
    assert.equal(v.valid, true, `${v.status}/${v.reason}`);
    const ev = cas.evaluateCasEvidence(outcome, { registry: att.registry });
    assert.equal(ev.class, 'executor_attested');
  });

  it('REPRODUCED THEN CLOSED: a forged grant is no longer a kernel binding', () => {
    const ev = cas.evaluateCasEvidence(outcome, { registry: att.registry, grant: FORGED });
    // The SDK cross-check still passes — it only decodes — which is exactly why the guard must
    // authenticate separately. This asserts the cross-check is NOT what is protecting us.
    assert.equal(ev.class, 'executor_attested');
    const so = cas.strictCommitObservation(outcome, ev, {
      registry: att.registry, grant: FORGED, grant_keyring: good.keyring,
    });
    assert.equal(so.commit_label, 'authorized_not_committed');
    assert.equal(so.commit_evidence_reason, 'commit_evidence_missing');
  });

  it('POSITIVE: a properly signed grant IS a kernel binding', () => {
    // Without this the fix would be indistinguishable from breaking the feature.
    const ev = cas.evaluateCasEvidence(outcome, { registry: att.registry, grant: good.token });
    assert.equal(ev.class, 'executor_attested');
    const so = cas.strictCommitObservation(outcome, ev, {
      registry: att.registry, grant: good.token, grant_keyring: good.keyring,
    });
    assert.equal(so.commit_label, 'authorized_and_committed');
  });

  it('FAIL-CLOSED: a real grant with NO issuer keyring is not a binding', () => {
    // A stated behaviour change: nothing here can tell a real grant from a copied one without a
    // key, so "we could not check" must not read like "we checked".
    const so = cas.strictCommitObservation(
      outcome,
      cas.evaluateCasEvidence(outcome, { registry: att.registry, grant: good.token }),
      { registry: att.registry, grant: good.token },
    );
    assert.equal(so.commit_label, 'authorized_not_committed');
    assert.equal(cas.authenticateGrant(good.token, null).reason, 'grant_keyring_not_supplied');
  });

  it('MUTATION SUBSET: one byte anywhere in the grant fails authentication', () => {
    // MID-STRING, not the last character. base64url is unpadded, so the final character can
    // encode as few as two significant bits: flipping 'A'→'B' there decoded to the SAME 64 signature
    // bytes and authenticated correctly. That is base64 malleability, not a hole — but a mutation
    // test that mutates nothing proves nothing, so the byte is taken from the middle.
    const flip = (s) => {
      const i = Math.floor(s.length / 2);
      return s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
    };
    const [payload, sig] = good.token.split('.');
    const cases = {
      'signature byte': `${payload}.${flip(sig)}`,
      'payload byte': `${flip(payload)}.${sig}`,
      'truncated to one segment': payload,
      'empty': '',
      'not base64url at all': 'not-a-token',
      'signature replaced by a word': `${payload}.${Buffer.from('NEM-ALAIRAS').toString('base64url')}`,
    };
    for (const [name, token] of Object.entries(cases)) {
      const r = cas.authenticateGrant(token, good.keyring);
      assert.equal(r.authenticated, false, `${name} authenticated`);
      const so = cas.strictCommitObservation(
        outcome,
        cas.evaluateCasEvidence(outcome, { registry: att.registry, grant: token }),
        { registry: att.registry, grant: token, grant_keyring: good.keyring },
      );
      assert.equal(so.commit_label, 'authorized_not_committed', `${name} still counted as a binding`);
    }
  });

  it('REPRODUCED THEN CLOSED (1433): a bare receipt_digest cannot rescue a forged grant', () => {
    // 1431 stopped an unauthenticated grant counting ON ITS OWN. `bindingIntendedSupplied` is an
    // OR, so the same forged token plus a host-asserted `receipt_digest` went straight back to
    // authorized_and_committed. Measured, all four rows, before this closed:
    //
    //   forged grant + issuer keyring          authorized_not_committed   (1431 held)
    //   forged grant + bare receipt_digest     authorized_and_committed   <- the bypass
    //   forged grant + bare grant_fields       authorized_and_committed   <- the bypass
    //   bare receipt_digest alone              authorized_and_committed
    const STRICT = { registry: att.registry, profile: 'ENFORCING_STRICT' };
    const rows = [
      ['forged grant + bare receipt_digest', { grant: FORGED, grant_keyring: good.keyring, receipt_digest: `sha256:${sha('receipt')}` }],
      ['forged grant + bare grant_fields', { grant: FORGED, grant_keyring: good.keyring, grant_fields: { jti: JTI, scope_hash: SCOPE } }],
      ['bare receipt_digest alone', { receipt_digest: `sha256:${sha('receipt')}` }],
      ['bare grant_fields alone', { grant_fields: { jti: JTI, scope_hash: SCOPE } }],
    ];
    for (const [name, extra] of rows) {
      const opts = { ...STRICT, ...extra };
      const so = cas.strictCommitObservation(outcome, cas.evaluateCasEvidence(outcome, opts), opts);
      assert.equal(so.commit_label, 'authorized_not_committed', `${name} still counted`);
      assert.equal(so.commit_evidence_reason, 'commit_evidence_missing');
    }
  });

  it('POSITIVE under STRICT: an authenticated grant is still the one thing that counts', () => {
    // Otherwise the fix would be indistinguishable from disabling the feature.
    const opts = {
      registry: att.registry, profile: 'ENFORCING_STRICT',
      grant: good.token, grant_keyring: good.keyring,
    };
    const so = cas.strictCommitObservation(outcome, cas.evaluateCasEvidence(outcome, opts), opts);
    assert.equal(so.commit_label, 'authorized_and_committed');
  });

  it('ADVISORY (no enforcing profile) is UNCHANGED — host-asserted values still corroborate', () => {
    // Narrowing this too would change a contract nobody complained about. The label outside an
    // enforcing profile does not claim the guard checked a signature, and it still does not.
    const opts = { registry: att.registry, receipt_digest: `sha256:${sha('receipt')}` };
    const so = cas.strictCommitObservation(outcome, cas.evaluateCasEvidence(outcome, opts), opts);
    assert.equal(so.commit_label, 'authorized_and_committed');
  });

  it('MUTATION SUBSET: a grant signed by the WRONG key fails', () => {
    const other = signedGrant({ jti: JTI, scope_hash: SCOPE });
    // Right shape, right fields, a key nobody pinned.
    assert.equal(cas.authenticateGrant(other.token, good.keyring).authenticated, false);
  });

  it('the vendored core verifies the REAL server v2 grant, when it is beside this repo', (t) => {
    const F = path.join(process.env.HOME || '', 'coderifts-conformance', 'fixtures', 'recorded', 'end-to-end', 'transcript.json');
    const K = path.join(process.env.HOME || '', 'receipt-verifier', 'keys', 'coderifts-keys.json');
    if (!fs.existsSync(F) || !fs.existsSync(K)) {
      t.skip('the conformance fixture or the issuer keyring is not beside this repo');
      return;
    }
    const tr = JSON.parse(fs.readFileSync(F, 'utf8'));
    const r = cas.authenticateGrant(
      tr.issuance.execution_grant,
      JSON.parse(fs.readFileSync(K, 'utf8')),
      Date.parse(tr.issuance.grant.not_before) + 1000,
    );
    assert.equal(r.authenticated, true, `${r.status}/${r.reason}`);
    assert.equal(r.status, 'GRANT_CURRENT');
  });
});
