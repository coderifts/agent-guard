'use strict';

/**
 * THE RECEIPT THIS GUARD HANDS THE CORE, AND WHY IT IS NOT ENTITLED TO THE GLOBAL CLAIM (1504).
 *
 * ── MEASURED, per surface, because the three consumers needed DIFFERENT fixes ────────────────
 *
 *   conformance    a prove artifact WITH a one-run evidence root → names the closed profile and
 *                  reaches AUTHORIZED_AND_COMMITTED.
 *   contract-gate  a bundle; it verifies a root in its own shape, so it asks a custom set.
 *   agent-guard    A RUNTIME GUARD ON A TOOL CALL. Measured: `evidenceRoot` appears nowhere in
 *                  this package outside the vendored core. There is no root to hand over, and a
 *                  profile requiring one could never be satisfied here. (this file)
 *
 * So `CUSTOM_REQUIREMENTS_SATISFIED` is the CORRECT answer for this surface — and saying that out
 * loud is the point. A guard that quietly stopped reaching the global claim and a guard that was
 * never entitled to it are indistinguishable from outside, and only one of them is a bug.
 *
 * What this surface DID need: the receipt. `proof.receipt` records the guard's own bind step and
 * carries no token by design, so a caller that holds the bytes can now hand them over
 * (`receipt_token` + `receipt_keyring`) and have the CORE check a signature instead of this
 * package's opinion of one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const core = require('../src/vendor/verified-execution-binding.js');

const KID = 'GUARD-RECEIPT-KEY';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const RING = new Map([[KID, { publicKey, status: null }]]);
const NOW = Date.now();
const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v)).digest('hex')}`;
const canon = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};
const GRANT = (() => {
  const b = {
    v: 'cr.exec.v2', kid: KID, grant_id: 'g-guard', receipt_hash: sha('r'), tenant_id: 't',
    executor_id: 'e', adapter_id: 'a', operation: 'publish', target_uri: 'db://x/y',
    expected_state_token: 's', after_payload_hash: sha('p'), nonce_hash: sha('n'),
    policy_hash: sha('pol'), audience_hash: sha('aud'),
    not_before: new Date(NOW - 1000).toISOString(),
    expires_at: new Date(NOW + 600000).toISOString(), max_attempts: 1,
  };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canon(b)}`, 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(b), 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
})();

describe('this surface holds no evidence root, so the custom lane is correct', () => {
  it('MEASURED: `evidenceRoot` appears nowhere in src/ outside the vendored core', () => {
    // The fact the lane rests on. If a future change gives this guard a root, this test fails and
    // the decision to name a profile gets made deliberately rather than by a re-vendor.
    const srcDir = path.join(__dirname, '..', 'src');
    const hits = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) { if (entry.name !== 'vendor') walk(p); continue; }
        if (!/\.(ts|js)$/.test(entry.name)) continue;
        if (/evidenceRoot|evidence_root/.test(fs.readFileSync(p, 'utf8'))) hits.push(entry.name);
      }
    };
    walk(srcDir);
    assert.deepEqual(hits, [],
      `this guard now references an evidence root (${hits.join(', ')}) — reconsider the lane`);
  });

  it('the guard reads its OWN question, not the global claim', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'cas-attestation.ts'), 'utf8');
    assert.match(src, /r\.requirements_satisfied === true/,
      'the guard reads authorized_and_committed, which a custom set can never reach');
  });

  it('a satisfied custom set is NAMED as one, not as the global claim', () => {
    const r = core.verifiedExecutionBinding({
      receipt: { verified: true },
      grant: { token: GRANT, keyring: RING, expectedKid: null, now: NOW + 1 },
      committed: true,
      required: ['issuer_grant'],
    });
    assert.equal(r.requirements_satisfied, true, r.shortfalls.join('; '));
    assert.equal(r.state, 'CUSTOM_REQUIREMENTS_SATISFIED');
    assert.equal(r.authorized_and_committed, false);
  });
});

describe('the receipt can now be handed over, and is checked when it is', () => {
  it('the surface accepts a receipt token and a keyring', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'cas-attestation.ts'), 'utf8');
    assert.match(src, /receipt_token\?: string \| null;/);
    assert.match(src, /receipt: opts\.receipt_token/,
      'the token is accepted but never handed to the core');
  });

  it('NEGATIVE CONTROL: {verified:true} with no token cannot reach the global claim', () => {
    const r = core.verifiedExecutionBinding({
      receipt: { verified: true },
      grant: { token: GRANT, keyring: RING, expectedKid: null, now: NOW + 1 },
      committed: true,
      profile: 'TRUSTED_EXECUTOR_INTEGRITY_V1',
    });
    assert.equal(r.receipt_caller_asserted, true);
    assert.equal(r.authorized_and_committed, false);
  });

  it('a supplied receipt token that does not verify is refused', () => {
    const r = core.verifiedExecutionBinding({
      receipt: { verified: true, token: 'not-a-receipt', keyring: RING },
      grant: { token: GRANT, keyring: RING, expectedKid: null, now: NOW + 1 },
      committed: true,
      required: ['issuer_grant'],
    });
    assert.equal(r.requirements_satisfied, false);
    assert.equal(r.receipt_caller_asserted, false, 'something WAS checked, and it failed');
  });
});
