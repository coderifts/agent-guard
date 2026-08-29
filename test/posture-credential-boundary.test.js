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
const NOW = Date.parse('2026-08-29T12:00:00.000Z');

/** posture.js:179-183 — deterministic key order, the producer's own canonicalisation. */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function mintReceipt({ verdict = 'PASS', deployment_id = DEPLOY, measured_at = new Date(NOW).toISOString() } = {}) {
  const body = {
    v: 'cr.posture.receipt.v1',
    executor_kid: KID,
    deployment_id,
    measured_at,
    verdict,
    facts: { host_role_dml: [], owner_login: false },
    drift: verdict === 'PASS' ? [] : [{ name: 'host_role gained INSERT on articles' }],
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
  executorId: 'exec-a',
  adapterId: 'pg',
  targetUri: 'postgres://t',
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
        postureReceipt: mintReceipt(),
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
        postureReceipt: mintReceipt(),
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
      credentialBoundary: { postureReceipt: mintReceipt() },
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
    const ancient = mintReceipt({ measured_at: '2020-01-01T00:00:00.000Z' });
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
