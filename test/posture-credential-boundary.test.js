'use strict';

/**
 * 1167 — ENFORCING_ATOMIC_V2 credential_boundary requires a VERIFIED posture receipt.
 *
 * The audit's P0: on V1, `credentialBoundary: true` satisfies the invariant with nothing
 * verifying it (atomic-profile.ts, the frozen two-line check). V2 replaces the assertion with
 * a signature check over a real cr.posture.receipt.v1.
 *
 * The receipt shape here is NOT invented — it mirrors what capability-demo actually signs
 * (demo/src/posture.js:427-437): body { v, executor_kid, deployment_id, measured_at, verdict,
 * facts, drift }, signed over canonicalJson(body), enveloped as
 * `cr.posture.receipt.v1|kid|b64url(preimage)|sig`.
 *
 * Test 2 is the one that matters most in a year: it asserts V1 STILL ACCEPTS the bare form.
 * Anyone "simplifying" by tightening V1 too breaks it, which is exactly the migration the
 * versioned profile names exist to refuse (with-coderifts.ts:228).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  atomicConstructionProblems,
  PROFILE_ENFORCING_ATOMIC_V1,
  PROFILE_ENFORCING_ATOMIC_V2,
  CREDENTIAL_BOUNDARY_BARE_REJECTED,
  verifyPostureReceipt,
  createMutatorRegister,
} = require('../dist/cjs/index.js');

// ── a real Ed25519 keypair; no fixture keys, no network ──────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'posture-k1';
const PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const REGISTRY = { keys: [{ kid: KID, public_key_pem: PEM, status: 'active' }] };
const DEPLOY = 'dep-0001';

/**
 * The credential-boundary tuple (AUDIT P1 / RES-3). One definition for the
 * construction config AND the receipts it must bind: if they could drift apart
 * the binding tests would pass on a coincidence.
 */
const TUPLE = Object.freeze({
  executor_id: 'exec-a',
  adapter_id: 'pg',
  target_uri: 'postgres://t',
});
const NOW = Date.parse('2026-08-29T12:00:00.000Z');

/** posture.js:179-183 — deterministic key order, the producer's own canonicalisation. */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function mintReceipt({
  verdict = 'PASS', deployment_id = DEPLOY, measured_at = new Date(NOW).toISOString(),
  reserved = {},
} = {}) {
  const body = {
    v: 'cr.posture.receipt.v1',
    executor_kid: KID,
    deployment_id,
    measured_at,
    verdict,
    facts: { host_role_dml: [], owner_login: false },
    drift: verdict === 'PASS' ? [] : [{ name: 'host_role gained INSERT on articles' }],
    // The credential-boundary tuple. RE-MEASURED 2026-08-29 against
    // capability-demo demo/src/posture.js: the issuer spreads these into the
    // SIGNED body whenever they carry real content (RESERVED_BODY_FIELDS +
    // presentReservedFields), so they are inside the preimage here too — which
    // is what makes binding them a real check rather than a decoration.
    ...Object.fromEntries(Object.entries(reserved)
      .filter(([, v]) => typeof v === 'string' && v.length > 0)),
  };
  const preimage = canonicalJson(body);
  const signature = crypto.sign(null, Buffer.from(preimage, 'utf8'), privateKey).toString('base64url');
  return [
    'cr.posture.receipt.v1',
    KID,
    Buffer.from(preimage, 'utf8').toString('base64url'),
    signature,
  ].join('|');
}

/** Everything V1/V2 need EXCEPT credential_boundary, so only that invariant is under test. */
const baseInput = () => ({
  executionGrant: { enabled: true, grantVersion: 'v2', resolveStateNonce: () => 'n' },
  executorId: TUPLE.executor_id,
  adapterId: TUPLE.adapter_id,
  targetUri: TUPLE.target_uri,
  executorAttestation: { registry: REGISTRY },
  mutatorRegister: (() => { const m = createMutatorRegister(); m.registerMutator('write'); return m; })(),
  casAdapter: {},
  readBack: () => {},
});

const boundaryProblems = (problems) => problems.filter((p) => p.startsWith('credential_boundary'));

describe('1167 — V2 credential_boundary requires a verified posture receipt', () => {
  it('1. bare `true` on _V2 → ATOMIC_PROFILE_UNSATISFIED with the teaching message', () => {
    const problems = atomicConstructionProblems({
      ...baseInput(), profile: PROFILE_ENFORCING_ATOMIC_V2, credentialBoundary: true,
    });
    assert.ok(problems.includes(CREDENTIAL_BOUNDARY_BARE_REJECTED),
      `expected the teaching message, got: ${JSON.stringify(problems)}`);
    assert.match(CREDENTIAL_BOUNDARY_BARE_REJECTED, /a bare assertion is no longer accepted/);
    assert.match(CREDENTIAL_BOUNDARY_BARE_REJECTED, /_V1 still accepts the bare form and is frozen/);
  });

  it('2. V1 IS FROZEN: bare `true` still satisfies credential_boundary on _V1', () => {
    const problems = atomicConstructionProblems({
      ...baseInput(), profile: PROFILE_ENFORCING_ATOMIC_V1, credentialBoundary: true,
    });
    assert.deepEqual(boundaryProblems(problems), [],
      'tightening V1 would silently move every existing caller — see with-coderifts.ts:228');
  });

  it('3. valid signed receipt, PASS, matching deployment, fresh → no credential_boundary problem', () => {
    const problems = atomicConstructionProblems({
      ...baseInput(),
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: {
        postureReceipt: mintReceipt({ reserved: TUPLE }),
        registry: REGISTRY,
        deploymentId: DEPLOY,
        maxAgeMs: 60_000,
        now: () => NOW + 1_000,
      },
    });
    assert.deepEqual(boundaryProblems(problems), []);
  });

  it('4. one byte corrupted in the signature → POSTURE_INVALID_SIGNATURE', () => {
    const seg = mintReceipt().split('|');
    seg[3] = seg[3].slice(0, -2) + (seg[3].slice(-2) === 'AA' ? 'BB' : 'AA');
    const r = verifyPostureReceipt(seg.join('|'), { registry: REGISTRY });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'POSTURE_INVALID_SIGNATURE');
  });

  it('5. validly signed verdict:FAIL → POSTURE_FAIL (signature valid, posture failed)', () => {
    const r = verifyPostureReceipt(mintReceipt({ verdict: 'FAIL' }), { registry: REGISTRY });
    assert.equal(r.status, 'POSTURE_FAIL',
      'a signed FAIL is a drift artifact — reporting it as INVALID_SIGNATURE would hide a real regression');
    assert.equal(r.reason, 'posture_verdict_not_pass');
    assert.ok(r.payload && Array.isArray(r.payload.drift) && r.payload.drift.length > 0);
  });

  it('6. measured_at older than maxAgeMs → POSTURE_STALE, named as a caller window', () => {
    const r = verifyPostureReceipt(mintReceipt(), {
      registry: REGISTRY, maxAgeMs: 60_000, now: () => NOW + 3_600_000,
    });
    assert.equal(r.status, 'POSTURE_STALE');
    assert.equal(r.reason, 'outside_freshness_window');
    const problems = atomicConstructionProblems({
      ...baseInput(),
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: {
        postureReceipt: mintReceipt({ reserved: TUPLE }),
        registry: REGISTRY,
        deploymentId: DEPLOY,
        maxAgeMs: 60_000,
        now: () => NOW + 3_600_000,
      },
    });
    assert.match(boundaryProblems(problems)[0], /not a receipt-carried expiry/);
    assert.match(boundaryProblems(problems)[0], /signs measured_at and no expires_at/);
  });

  it('7. different deployment_id → POSTURE_UNBOUND', () => {
    const r = verifyPostureReceipt(mintReceipt(), {
      registry: REGISTRY, expectedDeploymentId: 'dep-OTHER',
    });
    assert.equal(r.status, 'POSTURE_UNBOUND');
    assert.equal(r.reason, 'deployment_id_mismatch');
  });

  it('8. unknown kid in the registry → POSTURE_UNKNOWN_KEY', () => {
    const r = verifyPostureReceipt(mintReceipt(), { registry: { keys: [] } });
    assert.equal(r.status, 'POSTURE_UNKNOWN_KEY');
    assert.equal(r.reason, 'unknown_kid');
  });
});

describe('1167 — the honest limits are enforced, not merely documented', () => {
  it('no key supplied at all → the problem names the caller-supplied-key rule', () => {
    const problems = atomicConstructionProblems({
      ...baseInput(),
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: { postureReceipt: mintReceipt({ reserved: TUPLE }) },
    });
    assert.match(boundaryProblems(problems)[0], /registry or .pinnedKeyPem required/);
    assert.match(boundaryProblems(problems)[0], /never fetches one/);
  });

  it('the air-gap pinned-PEM path works without a registry', () => {
    const r = verifyPostureReceipt(mintReceipt(), { pinnedKeyPem: PEM });
    assert.equal(r.valid, true);
    assert.equal(r.status, 'POSTURE_PASS');
  });

  it('absent maxAgeMs means NO age check — not a guard-invented default', () => {
    const ancient = mintReceipt({ measured_at: '2020-01-01T00:00:00.000Z', reserved: TUPLE });
    const r = verifyPostureReceipt(ancient, { registry: REGISTRY });
    assert.equal(r.valid, true, 'a guard-side default would present our policy as the receipt\'s');
    assert.equal(r.age_ms, undefined);
  });

  it('the receipt does NOT carry the four fields V2 must not claim (1174)', () => {
    const r = verifyPostureReceipt(mintReceipt(), { registry: REGISTRY });
    for (const f of ['executor_id', 'adapter_id', 'target_uri', 'policy_hash']) {
      assert.equal(r.payload[f], undefined,
        `${f} is absent from what the producer signs — V2 must not imply it binds it`);
    }
  });
});

// ── AUDIT P1 / RES-3: THE TUPLE IS BOUND, NOT RESERVED ───────────────────────
/**
 * atomic-profile.ts used to state, in its own "what this does not prove" list,
 * that a V2 receipt binds "NOT executor_id, adapter_id, target_uri or
 * policy_hash". Re-measured against capability-demo demo/src/posture.js, the
 * issuer spreads those into the SIGNED body when they carry real content — so
 * the bullet was stale, and binding them is backed by the producer.
 *
 * These pin both halves: the binding refuses a wrong or missing value, AND an
 * expectation nobody stated is NAMED rather than treated as checked.
 */
describe('AUDIT P1 / RES-3 — the credential-boundary tuple is bound', () => {
  const bindAll = {
    registry: REGISTRY,
    expectedDeploymentId: DEPLOY,
    expectedExecutorId: TUPLE.executor_id,
    expectedAdapterId: TUPLE.adapter_id,
    expectedTargetUri: TUPLE.target_uri,
  };

  it('a receipt carrying the tuple verifies and REPORTS what it bound', () => {
    const r = verifyPostureReceipt(mintReceipt({ reserved: TUPLE }), bindAll);
    assert.equal(r.valid, true, `${r.status}/${r.reason}`);
    assert.deepEqual(r.bound.sort(), ['adapter_id', 'executor_id', 'target_uri']);
    // policy_hash was not asked for, so it is named — not silently passed.
    assert.deepEqual(r.not_bound.map((n) => n.field), ['policy_hash']);
    assert.match(r.not_bound[0].reason, /did not state an expected value/);
  });

  for (const field of ['executor_id', 'adapter_id', 'target_uri']) {
    it(`a WRONG ${field} → POSTURE_UNBOUND, never a pass`, () => {
      const r = verifyPostureReceipt(
        mintReceipt({ reserved: { ...TUPLE, [field]: 'someone-else' } }),
        bindAll,
      );
      assert.equal(r.valid, false);
      assert.equal(r.status, 'POSTURE_UNBOUND');
      assert.equal(r.reason, `${field}_mismatch`);
    });

    it(`an ABSENT ${field} the caller asked for → POSTURE_UNBOUND, not a pass`, () => {
      // A missing field is not a matching one. Without this, a receipt that
      // simply omits the tuple would satisfy a caller that demanded it.
      const reserved = { ...TUPLE };
      delete reserved[field];
      const r = verifyPostureReceipt(mintReceipt({ reserved }), bindAll);
      assert.equal(r.valid, false);
      assert.equal(r.status, 'POSTURE_UNBOUND');
      assert.equal(r.reason, `${field}_absent`);
    });
  }

  it('policy_hash binds when stated', () => {
    const withPolicy = { ...TUPLE, policy_hash: 'sha256:pp' };
    const ok = verifyPostureReceipt(mintReceipt({ reserved: withPolicy }),
      { ...bindAll, expectedPolicyHash: 'sha256:pp' });
    assert.equal(ok.valid, true, `${ok.status}/${ok.reason}`);
    assert.ok(ok.bound.includes('policy_hash'));
    assert.deepEqual(ok.not_bound, []);

    const bad = verifyPostureReceipt(mintReceipt({ reserved: withPolicy }),
      { ...bindAll, expectedPolicyHash: 'sha256:OTHER' });
    assert.equal(bad.status, 'POSTURE_UNBOUND');
    assert.equal(bad.reason, 'policy_hash_mismatch');
  });

  it('a caller stating NOTHING binds nothing — and the result says so', () => {
    // The old behaviour, preserved: a bare verify is still a signature check.
    // What changed is that it now reports the tuple it did not prove.
    const r = verifyPostureReceipt(mintReceipt({ reserved: TUPLE }), { registry: REGISTRY });
    assert.equal(r.valid, true);
    assert.deepEqual(r.bound, []);
    assert.deepEqual(
      r.not_bound.map((n) => n.field).sort(),
      ['adapter_id', 'executor_id', 'policy_hash', 'target_uri'],
    );
  });

  it('a receipt for the right deployment but the WRONG executor no longer passes', () => {
    // The gap in one sentence: deployment binding alone let a receipt from
    // another executor inside the same deployment satisfy the boundary.
    const r = verifyPostureReceipt(
      mintReceipt({ reserved: { ...TUPLE, executor_id: 'exec-b' } }),
      { registry: REGISTRY, expectedDeploymentId: DEPLOY, expectedExecutorId: 'exec-a' },
    );
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'executor_id_mismatch');
  });

  it('the V2 fail-closed behaviour still holds alongside the binding', () => {
    // A revoked key, a future measurement and a kid mismatch must still fail —
    // the tuple check must not have become an earlier, softer exit.
    const revoked = verifyPostureReceipt(mintReceipt({ reserved: TUPLE }),
      { ...bindAll, registry: { keys: [{ kid: KID, public_key_pem: PEM, status: 'revoked' }] } });
    assert.equal(revoked.valid, false);
    assert.equal(revoked.status, 'POSTURE_REVOKED_KEY');

    const future = verifyPostureReceipt(
      mintReceipt({ reserved: TUPLE, measured_at: new Date(NOW + 10 * 60_000).toISOString() }),
      { ...bindAll, maxAgeMs: 60_000, now: () => NOW },
    );
    assert.equal(future.valid, false);

    const wrongDeployment = verifyPostureReceipt(
      mintReceipt({ reserved: TUPLE, deployment_id: 'other' }), bindAll,
    );
    assert.equal(wrongDeployment.valid, false);
    assert.equal(wrongDeployment.reason, 'deployment_id_mismatch');
  });
});
