'use strict';

/**
 * roadmap 1018 remainder — cr.coverage.attest.v1 guard issuance via host sign(bytes).
 *
 * The load-bearing test is the Half-B-absent one: the token must carry UNKNOWN_OUTSIDE_SCOPE and
 * OMIT the totals. A defaulted or zeroed total would be a lie with a signature on it.
 *
 * Verification uses the REAL app kernel (required from the sibling checkout), never a
 * reimplementation — a verifier written here would only prove this file agrees with itself.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const {
  tryIssueCoverageAttestation,
  kidFromCoverageAttestation,
  coverageAttestSigningInput,
  COVERAGE_ATTEST_VERSION,
  COVERAGE_ATTEST_ENVELOPE_TAG,
} = require('../dist/cjs/index.js');

const APP_KERNEL = path.join(process.env.HOME, 'coderifts-app', 'src', 'verdict-core', 'coverage-attestation.js');
let kernel = null;
try { kernel = require(APP_KERNEL); } catch { /* surfaced by the skip below, never silently */ }

function hostKey(kid = 'cov-k1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    kid,
    // The HOST holds the key. The guard only ever receives sign(bytes).
    signer: (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey),
    registry: { keys: [{ kid, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }] },
  };
}
const payloadOf = (token) => JSON.parse(Buffer.from(token.split('|')[2], 'base64url').toString('utf8'));

const HALF_A = { class: 'UNKNOWN_OUTSIDE_SCOPE', governed_calls: 8, tools: ['write_spec'] };
const HALF_B = {
  class: 'INCOMPLETE_OBSERVED', governed_calls: 8, tools: ['write_spec'],
  total_calls: 10, ungoverned_calls: 2, ungoverned_tools: ['patch_file', 'shell'],
};

describe('custody — mirrored from tryIssueMonitoringAttestation', () => {
  it('absent config yields no token (byte-identical to 9.5.0: no field)', async () => {
    assert.equal(await tryIssueCoverageAttestation({ coverage: HALF_B }), undefined);
    assert.equal(await tryIssueCoverageAttestation({ config: null, coverage: HALF_B }), undefined);
  });

  it('config without a signer, kid, or sessionId yields no token', async () => {
    const k = hostKey();
    assert.equal(await tryIssueCoverageAttestation({ config: { kid: 'x', sessionId: 's' }, coverage: HALF_B }), undefined);
    assert.equal(await tryIssueCoverageAttestation({ config: { signer: k.signer, sessionId: 's' }, coverage: HALF_B }), undefined);
    assert.equal(await tryIssueCoverageAttestation({ config: { kid: 'x', signer: k.signer }, coverage: HALF_B }), undefined);
  });

  it('a signer THROW yields no token — never an unsigned one', async () => {
    const cfg = { kid: 'k', sessionId: 's', signer: () => { throw new Error('hsm offline'); } };
    assert.equal(await tryIssueCoverageAttestation({ config: cfg, coverage: HALF_B }), undefined);
  });

  it('a signer returning empty/null yields no token', async () => {
    for (const bad of [() => Buffer.alloc(0), () => null]) {
      assert.equal(await tryIssueCoverageAttestation({ config: { kid: 'k', sessionId: 's', signer: bad }, coverage: HALF_B }), undefined);
    }
  });

  it('the config never carries a raw key — only kid + signer + sessionId', async () => {
    const k = hostKey();
    const cfg = { kid: k.kid, sessionId: 's-1', signer: k.signer };
    assert.deepEqual(Object.keys(cfg).sort(), ['kid', 'sessionId', 'signer']);
    assert.ok(await tryIssueCoverageAttestation({ config: cfg, coverage: HALF_B }));
  });
});

describe('the payload decision — absence is not zero', () => {
  it('Half A only → UNKNOWN_OUTSIDE_SCOPE with the totals OMITTED', async () => {
    const k = hostKey();
    const token = await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: HALF_A });
    const p = payloadOf(token);
    assert.equal(p.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.equal(p.governed_calls, 8);
    assert.equal('total_calls' in p, false, 'a defaulted total would be a signed lie');
    assert.equal('ungoverned_tools' in p, false);
  });

  it('Half B → INCOMPLETE_OBSERVED carrying the ungoverned names', async () => {
    const k = hostKey();
    const token = await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: HALF_B });
    const p = payloadOf(token);
    assert.equal(p.observed_class, 'INCOMPLETE_OBSERVED');
    assert.equal(p.total_calls, 10);
    assert.deepEqual(p.ungoverned_tools, ['patch_file', 'shell']);
  });

  it('guard COMPLETE_OBSERVED maps to envelope INCOMPLETE_OBSERVED — never a signed COMPLETE', async () => {
    const k = hostKey();
    const complete = { class: 'COMPLETE_OBSERVED', governed_calls: 10, tools: ['a'], total_calls: 10, ungoverned_calls: 0, ungoverned_tools: [] };
    const p = payloadOf(await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: complete }));
    assert.equal(p.observed_class, 'INCOMPLETE_OBSERVED');
    assert.equal(p.total_calls, 10);
    assert.deepEqual(p.ungoverned_tools, [], 'the empty list carries the finding, not a COMPLETE claim');
  });

  it('governed > total is refused at mint rather than emitted and rejected downstream', async () => {
    const k = hostKey();
    const bad = { class: 'INCOMPLETE_OBSERVED', governed_calls: 11, tools: [], total_calls: 10, ungoverned_calls: 0, ungoverned_tools: [] };
    assert.equal(await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: bad }), undefined);
  });

  it('a missing or malformed snapshot yields no token', async () => {
    const k = hostKey();
    const cfg = { kid: k.kid, sessionId: 's-1', signer: k.signer };
    for (const cov of [null, undefined, {}, { class: 'UNKNOWN_OUTSIDE_SCOPE' }, { class: 'UNKNOWN_OUTSIDE_SCOPE', governed_calls: -1 }]) {
      assert.equal(await tryIssueCoverageAttestation({ config: cfg, coverage: cov }), undefined);
    }
  });
});

describe('the emitted token verifies against the REAL app kernel', () => {
  it('Half B token → COV_ATTEST_VALID', async (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — cross-repo verification UNPROVEN');
    const k = hostKey();
    const token = await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: HALF_B });
    const r = kernel.verifyCoverageAttestation(token, { registry: k.registry });
    assert.equal(r.valid, true, `kernel rejected: ${r.status}/${r.reason}`);
    assert.equal(r.status, kernel.STATUSES.COV_ATTEST_VALID);
  });

  it('Half A token (totals omitted) → COV_ATTEST_VALID', async (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — cross-repo verification UNPROVEN');
    const k = hostKey();
    const token = await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: HALF_A });
    const r = kernel.verifyCoverageAttestation(token, { registry: k.registry });
    assert.equal(r.valid, true, `kernel rejected: ${r.status}/${r.reason}`);
  });

  it('the guard signing input is byte-identical to the kernel signing input', async (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — mirror UNPROVEN');
    const body = {
      v: COVERAGE_ATTEST_VERSION, kid: 'k', session_id: 's', observed_class: 'INCOMPLETE_OBSERVED',
      governed_calls: 8, total_calls: 10, ungoverned_tools: ['a', 'b'], observed_at: '2026-08-25T00:00:00Z',
    };
    assert.equal(coverageAttestSigningInput(body), kernel.signingInput(body));
  });

  it('a tampered count fails kernel verification', async (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present');
    const k = hostKey();
    const token = await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: HALF_B });
    const seg = token.split('|');
    const p = payloadOf(token); p.governed_calls = 10;
    seg[2] = Buffer.from(JSON.stringify(p), 'utf8').toString('base64url');
    assert.equal(kernel.verifyCoverageAttestation(seg.join('|'), { registry: k.registry }).status, kernel.STATUSES.COV_ATTEST_INVALID_SIGNATURE);
  });
});

describe('envelope shape', () => {
  it('four-segment pipe envelope with the kid readable without verifying', async () => {
    const k = hostKey();
    const token = await tryIssueCoverageAttestation({ config: { kid: k.kid, sessionId: 's-1', signer: k.signer }, coverage: HALF_B });
    assert.equal(token.split('|').length, 4);
    assert.equal(token.split('|')[0], COVERAGE_ATTEST_ENVELOPE_TAG);
    assert.equal(kidFromCoverageAttestation(token), k.kid);
    assert.equal(kidFromCoverageAttestation('nope'), null);
  });
});
