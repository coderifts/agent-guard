'use strict';

/**
 * P0 — ENFORCING_ATOMIC_V2 on the PUBLIC withCodeRifts() entry.
 *
 * The 12 posture-credential-boundary tests never called withCodeRifts(), so they
 * could not catch: (A) ACCEPTED_PROFILES rejecting _V2, (B) the helper not
 * receiving `profile`, (D) verifier fail-open (revoked / future / kid / body v).
 *
 * V1 is byte-frozen: the last test asserts `_V1` + `credentialBoundary: true`
 * still constructs.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  withCodeRifts,
  PROFILE_ENFORCING_ATOMIC_V1,
  PROFILE_ENFORCING_ATOMIC_V2,
  ATOMIC_PROFILE_UNSATISFIED,
  CREDENTIAL_BOUNDARY_BARE_REJECTED,
  createMutatorRegister,
  POSTURE_RECEIPT_V,
} = require('../dist/cjs/index.js');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'posture-k1';
const PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const REGISTRY = { keys: [{ kid: KID, public_key_pem: PEM, status: 'active' }] };
const REVOKED_REGISTRY = { keys: [{ kid: KID, public_key_pem: PEM, status: 'revoked' }] };
const DEPLOY = 'dep-0001';
const NOW = Date.parse('2026-08-29T12:00:00.000Z');

const STUB_CLIENT = { preflight: async () => ({}) };
const STUB_RESOLVER = async () => null;
const STUB_READBACK = async () => ({ ok: true });
const STUB_ATTEST = {
  keys: [{
    kid: 'k',
    public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----',
    status: 'active',
  }],
};

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * The credential-boundary tuple this construction declares (AUDIT P1 / RES-3).
 * One definition for the config AND the receipt, so a binding test cannot pass
 * because the two happened to agree.
 */
const TUPLE = Object.freeze({
  executor_id: 'exec-a',
  adapter_id: 'fs',
  target_uri: 'fs://repo/openapi.yaml',
});

function mintReceipt({
  verdict = 'PASS',
  deployment_id = DEPLOY,
  measured_at = new Date(NOW).toISOString(),
  executor_kid = KID,
  v = POSTURE_RECEIPT_V,
  reserved = TUPLE,
} = {}) {
  const body = {
    v,
    executor_kid,
    deployment_id,
    measured_at,
    verdict,
    facts: { host_role_dml: [], owner_login: false },
    drift: [],
    // Signed by the producer when they carry real content — measured against
    // capability-demo demo/src/posture.js (RESERVED_BODY_FIELDS).
    ...Object.fromEntries(Object.entries(reserved)
      .filter(([, val]) => typeof val === 'string' && val.length > 0)),
  };
  const preimage = canonicalJson(body);
  const signature = crypto.sign(null, Buffer.from(preimage, 'utf8'), privateKey).toString('base64url');
  return [
    POSTURE_RECEIPT_V,
    KID,
    Buffer.from(preimage, 'utf8').toString('base64url'),
    signature,
  ].join('|');
}

function mutators() {
  const m = createMutatorRegister();
  m.registerMutator('edit_file');
  return m;
}

function atomicPublic(over = {}) {
  return {
    tools: [
      { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
      { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read' },
    ],
    client: STUB_CLIENT,
    operation: 'merge',
    resolvePriorContent: STUB_RESOLVER,
    executionGrant: { enabled: true, grantVersion: 'v2', resolveStateNonce: async () => 'n1' },
    executorId: TUPLE.executor_id,
    adapterId: TUPLE.adapter_id,
    targetUri: TUPLE.target_uri,
    executorAttestation: { registry: STUB_ATTEST },
    mutatorRegister: mutators(),
    casAdapter: { put: async () => {} },
    readBack: STUB_READBACK,
    ...over,
  };
}

function v2Boundary(over = {}) {
  return {
    postureReceipt: mintReceipt(),
    registry: REGISTRY,
    deploymentId: DEPLOY,
    maxAgeMs: 60_000,
    now: () => NOW + 1_000,
    ...over,
  };
}

function isUnsatisfied(err) {
  return err && err.code === ATOMIC_PROFILE_UNSATISFIED;
}

function unsatisfiedMessage(fn) {
  try {
    fn();
    assert.fail('expected ATOMIC_PROFILE_UNSATISFIED');
  } catch (err) {
    assert.equal(err.code, ATOMIC_PROFILE_UNSATISFIED, err && err.message);
    return String(err.message);
  }
  return '';
}

describe('P0-A — ENFORCING_ATOMIC_V2 is accepted on withCodeRifts()', () => {
  it('fully-wired V2 + verified posture receipt constructs (no unknown-profile throw)', () => {
    assert.doesNotThrow(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary(),
    })));
  });

  it('V2 does not hit the ACCEPTED_PROFILES unknown-profile path', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: true,
    })));
    assert.doesNotMatch(msg, /must be one of/);
    assert.match(msg, /ATOMIC_PROFILE_UNSATISFIED|a bare assertion is no longer accepted/);
  });
});

describe('P0-B — profile is forwarded; V2 rejects a bare boolean', () => {
  it('V2 + credentialBoundary:true → ATOMIC_PROFILE_UNSATISFIED with the teaching message', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: true,
    })));
    assert.match(msg, new RegExp(CREDENTIAL_BOUNDARY_BARE_REJECTED.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  });
});

describe('P0-D — verifier attack vectors via public withCodeRifts()', () => {
  it('revoked key → refused (POSTURE_REVOKED_KEY)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({ registry: REVOKED_REGISTRY }),
    })));
    assert.match(msg, /POSTURE_REVOKED_KEY|kid_revoked/);
  });

  it('future measured_at → refused (POSTURE_STALE measured_at_in_future)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({
        postureReceipt: mintReceipt({ measured_at: '2035-01-01T00:00:00.000Z' }),
      }),
    })));
    assert.match(msg, /POSTURE_STALE/);
    assert.match(msg, /measured_at_in_future|freshness/);
  });

  it('envelope/body kid mismatch → refused (POSTURE_UNBOUND kid_mismatch)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({
        postureReceipt: mintReceipt({ executor_kid: 'other-kid' }),
      }),
    })));
    assert.match(msg, /POSTURE_UNBOUND/);
    assert.match(msg, /kid_mismatch/);
  });

  it('body v999 → refused (POSTURE_MALFORMED body_version_mismatch)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({
        postureReceipt: mintReceipt({ v: 'cr.posture.receipt.v999' }),
      }),
    })));
    assert.match(msg, /POSTURE_MALFORMED/);
    assert.match(msg, /body_version_mismatch/);
  });

  it('missing deploymentId in V2 → refused (mandatory at V2 call site)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({ deploymentId: undefined }),
    })));
    assert.match(msg, /deploymentId required under ENFORCING_ATOMIC_V2/);
  });

  it('missing maxAgeMs in V2 → refused (mandatory at V2 call site)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({ maxAgeMs: undefined }),
    })));
    assert.match(msg, /maxAgeMs required under ENFORCING_ATOMIC_V2/);
  });

  it('non-finite now() with maxAgeMs set → refused (freshness predicates must not no-op)', () => {
    const msg = unsatisfiedMessage(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary({ now: () => undefined }),
    })));
    assert.match(msg, /POSTURE_STALE/);
    assert.match(msg, /now_unparseable/);
  });

  it('VALID signed fresh deployment-bound active-key posture receipt → V2 constructs', () => {
    const r = withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V2,
      credentialBoundary: v2Boundary(),
    }));
    assert.ok(Array.isArray(r.tools));
    assert.ok(r.tools.length >= 1);
  });
});

describe('V1 regression — byte-frozen credentialBoundary:true', () => {
  it("withCodeRifts({ profile: 'ENFORCING_ATOMIC_V1', credentialBoundary: true }) still works", () => {
    assert.doesNotThrow(() => withCodeRifts(atomicPublic({
      profile: PROFILE_ENFORCING_ATOMIC_V1,
      credentialBoundary: true,
    })));
  });

  it("unsuffixed ENFORCING_ATOMIC + credentialBoundary:true still works", () => {
    assert.doesNotThrow(() => withCodeRifts(atomicPublic({
      profile: 'ENFORCING_ATOMIC',
      credentialBoundary: true,
    })));
  });
});

void isUnsatisfied;
