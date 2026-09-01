'use strict';

/**
 * This package's key-status rule agrees with the published verifier's, and a
 * withdrawn key cannot authorize a deploy.
 *
 * Three halves, because none alone is enough. The digest half pins the reference
 * copy in test/fixtures. The parity half runs the same nine registry vectors
 * through BOTH this package's verify path and that reference copy and asserts
 * they reach the same verdict — so a transliteration that drifts fails here
 * rather than in a customer's pipeline. The gate half proves the consequence
 * end-to-end: deployGate must refuse.
 *
 * MEASURED 2026-09-01: resolveKey collapsed every registry status to
 * 'retired' | 'active'. A key marked `revoked` arrived as ACTIVE, and deployGate
 * ALLOWED a production deploy authorized by it, indistinguishably from a healthy
 * key — 5 of these 9 vectors. These vectors are that measurement, kept executable.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { verifyDeployReceiptToken, deployGate, computeBodyHash } = require('../dist/cjs/index.js');

const REF_DIR = path.join(__dirname, 'fixtures', 'reference-core');
const reference = require(path.join(REF_DIR, 'verify.js'));

describe('reference core — digests match the pin', () => {
  const pinned = fs.readFileSync(path.join(REF_DIR, 'VENDOR.sha256'), 'utf8').trim().split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter(([name]) => name.endsWith('.js'));

  it('the pin lists verify.js and arity.js', () => {
    const names = pinned.map(([n]) => n);
    assert.ok(names.includes('verify.js'));
    assert.ok(names.includes('arity.js'));
  });

  for (const [name, digest] of pinned) {
    it(`${name} is byte-identical to its pinned digest`, () => {
      const got = crypto.createHash('sha256').update(fs.readFileSync(path.join(REF_DIR, name))).digest('hex');
      assert.equal(got, digest, `${name} drifted — recopy from receipt-verifier, or update the pin deliberately`);
    });
  }
});

// ── the nine vectors, one minted receipt per signing time ───────────────────
const KID = 'withdrawal-k1';
const ART = `sha256:${'a'.repeat(64)}`;
const FP = `sha256:${'b'.repeat(64)}`;
const kp = crypto.generateKeyPairSync('ed25519');
const PEM = kp.publicKey.export({ type: 'spki', format: 'pem' });
const BOUNDARY = '2026-06-01T00:00:00.000Z';

const ENVELOPE = {
  spec_version: 'decision-result.v1.1', decision: 'ALLOW', execution_action: 'CONTINUE',
  decision_id: 'dec_withdrawal', fingerprint: FP, operation: 'deploy', target_id: ART,
  environment: 'staging', expires_at: '2099-01-01T00:00:00.000Z',
};

function issue(ts) {
  const body = {
    v: 4, kid: KID, fp: FP, prev: 'null', caller: 'vendor-core-test',
    ts, reg: '', ir: '', expires_at: ENVELOPE.expires_at, bh: computeBodyHash(ENVELOPE),
  };
  const si = `crchain.v1|${body.kid}|${body.fp}|${body.prev}|${body.caller}|${body.ts}|${body.reg}|${body.ir}|${body.expires_at}|${body.bh}`;
  const sig = crypto.sign(null, Buffer.from(si, 'utf8'), kp.privateKey);
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
}
const SIGNED_BEFORE = issue('2026-01-01T00:00:00.000Z');
const SIGNED_AFTER = issue('2026-08-01T00:00:00.000Z');
const entry = (o) => ({ kid: KID, alg: 'Ed25519', public_key_pem: PEM, valid_from: null, retired_at: null, ...o });

const VECTORS = [
  ['V1 active key (control)', entry({ status: 'active' }), SIGNED_AFTER, true, 'VERIFIED_CURRENT'],
  ['V2 retired, signed before retired_at', entry({ status: 'retired', retired_at: BOUNDARY }), SIGNED_BEFORE, true, 'RETIRED_KEY_VALID_AT_ISSUE'],
  ['V3 retired, signed after retired_at', entry({ status: 'retired', retired_at: BOUNDARY }), SIGNED_AFTER, false, 'KEY_RETIRED_AFTER_SIGNING'],
  ['V4 retired, no retired_at', entry({ status: 'retired' }), SIGNED_AFTER, false, 'INVALID_SIGNATURE'],
  ['V5 revoked + compromised_at, signed after', entry({ status: 'revoked', compromised_at: BOUNDARY }), SIGNED_AFTER, false, 'REVOKED_KEY'],
  ['V6 revoked + compromised_at, signed before', entry({ status: 'revoked', compromised_at: BOUNDARY }), SIGNED_BEFORE, false, 'REVOKED_KEY_UNDECIDABLE'],
  ['V7 revoked, no compromised_at', entry({ status: 'revoked' }), SIGNED_AFTER, false, 'REVOKED_KEY_UNDECIDABLE'],
  ['V8 active entry carrying revoked_at', entry({ status: 'active', revoked_at: BOUNDARY }), SIGNED_BEFORE, false, 'KEY_REVOKED'],
  ['V9 a status this verifier does not know', entry({ status: 'suspended' }), SIGNED_AFTER, false, 'UNKNOWN_KEY_STATUS'],
];

/** The reference verdict for the same token and the same registry entry. */
function referenceVerdict(keyEntry, token) {
  const keyring = new Map([[KID, {
    publicKey: reference.keyFromPem(keyEntry.public_key_pem),
    status: keyEntry.status ?? null,
    retired_at: keyEntry.retired_at ?? null,
    revoked_at: keyEntry.revoked_at ?? null,
    compromised_at: keyEntry.compromised_at ?? null,
  }]]);
  const r = reference.verifyReceipt(token, { ctx: { keyring, expectedKid: null }, skipBodyHash: true });
  return { valid: r.valid, status: r.status };
}

describe('key-status vectors — this package agrees with the published verifier', () => {
  for (const [label, keyEntry, token, expectValid, expectStatus] of VECTORS) {
    it(`${label} → ${expectValid ? 'accept' : 'reject'} ${expectStatus}`, () => {
      const mine = verifyDeployReceiptToken({ token, registry: { keys: [keyEntry] }, decision_result: ENVELOPE });
      assert.equal(mine.valid, expectValid, `${label}: valid`);
      assert.equal(mine.status, expectStatus, `${label}: status`);

      // The same vector through the reference copy: accept/reject and the status
      // string must both agree, or the transliteration has drifted.
      const ref = referenceVerdict(keyEntry, token);
      assert.equal(mine.valid, ref.valid, `${label}: this package and the reference disagree on accept/reject`);
      assert.equal(mine.status, ref.status, `${label}: this package and the reference disagree on the status`);
    });
  }

  it('the vectors are not vacuous: the control accepts and five withdrawal vectors reject', () => {
    const verdicts = VECTORS.map(([, e, t]) => verifyDeployReceiptToken({ token: t, registry: { keys: [e] }, decision_result: ENVELOPE }).valid);
    assert.equal(verdicts.filter(Boolean).length, 2, 'exactly the active control and the pre-retirement receipt verify');
    assert.equal(verdicts.filter((v) => !v).length, 7);
  });
});

describe('deployGate — a withdrawn key cannot authorize a deploy', () => {
  const gate = (keyEntry, token) => deployGate({
    deployTarget: { environment: 'staging', artifact_id: ART },
    token: { token, decision_result: ENVELOPE, registry: { keys: [keyEntry] } },
    requiredContext: { operation: 'deploy', enforcement: { enforcement: 'ENFORCING', bypass_possible: false } },
  });

  it('control: an active key still deploys (the gate vectors are not vacuous)', () => {
    const g = gate(entry({ status: 'active' }), SIGNED_AFTER);
    assert.equal(g.deploy_allowed, true, g.reason);
    assert.equal(g.reason, 'allow_current_deploy');
  });

  for (const [label, keyEntry, token] of VECTORS.slice(4)) {
    it(`${label} → deploy refused`, () => {
      const g = gate(keyEntry, token);
      assert.equal(g.deploy_allowed, false, `${label} must not deploy`);
      assert.ok(
        g.reason === 'revoked_key' || g.reason === 'unknown_key_status',
        `${label}: expected a withdrawal reason, got ${g.reason}`,
      );
      assert.equal(g.inescapable_deploy, false);
    });
  }

  it('a revoked key is NOT repairable — re-requesting would use the same key', () => {
    const { DEPLOY_REPAIRABLE_REASONS } = require('../dist/cjs/index.js');
    assert.ok(!DEPLOY_REPAIRABLE_REASONS.has('revoked_key'));
    assert.ok(!DEPLOY_REPAIRABLE_REASONS.has('unknown_key_status'));
    // Planned rotation stays repairable — that is a different situation.
    assert.ok(DEPLOY_REPAIRABLE_REASONS.has('retired_key'));
  });
});
