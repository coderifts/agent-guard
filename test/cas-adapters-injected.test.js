'use strict';

/**
 * Injected-I/O CAS adapters (api / db / registry) — token discipline + outcome mapping
 * over executeIfUnchanged. No network/db drivers; host callbacks only.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  // api
  createApiVersionToken,
  writeApiIfUnchanged,
  apiTokenRaw,
  API_VERSION_TOKEN_PREFIX,
  API_ABSENT_TOKEN,
  // db
  createDbVersionToken,
  writeDbIfUnchanged,
  dbTokenRaw,
  DB_VERSION_TOKEN_PREFIX,
  DB_ABSENT_TOKEN,
  // registry
  createRegistryVersionToken,
  writeRegistryIfUnchanged,
  registryTokenRaw,
  REGISTRY_VERSION_TOKEN_PREFIX,
  REGISTRY_ABSENT_TOKEN,
  // attestation integration
  buildCasAttestation,
  CAS_ATTESTATION_SPEC,
  EXECUTION_PROOF_SPEC,
  tokensEqual,
} = require('../dist/cjs/index.js');

const PROOF_LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
  conditional_write_is_host_asserted_not_cas_verified: true,
});

function minimalProof() {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_cas_adapters_1',
    receipt: Object.freeze({
      verified: true,
      status: 'VERIFIED_CURRENT',
      expires_at: '2099-01-01T00:00:00.000Z',
    }),
    binds_to: Object.freeze({
      operation: 'tool_call',
      change_fp: 'sha256:' + 'f'.repeat(64),
    }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({
      status: 'hashed',
      algorithm: 'sha256',
      value: 'sha256:' + 'b'.repeat(64),
    }),
    limits: PROOF_LIMITS,
  });
}

// ── API ──────────────────────────────────────────────────────────────────────
describe('api CAS adapter (ETag / If-Match, host-injected)', () => {
  it('createApiVersionToken: empty → ABSENT; strips weak quotes', () => {
    assert.equal(createApiVersionToken(null), API_ABSENT_TOKEN);
    assert.equal(createApiVersionToken(''), API_ABSENT_TOKEN);
    assert.equal(createApiVersionToken('W/"abc"'), `${API_VERSION_TOKEN_PREFIX}abc`);
    assert.equal(createApiVersionToken('"xyz"'), `${API_VERSION_TOKEN_PREFIX}xyz`);
    assert.equal(apiTokenRaw(createApiVersionToken('"xyz"')), 'xyz');
    assert.equal(apiTokenRaw(API_ABSENT_TOKEN), null);
  });

  it('committed happy path: host reports committed + new_etag', async () => {
    let live = 'etag-1';
    const expected = createApiVersionToken(live);
    let sawIfMatch = null;
    const out = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => live,
      write: ({ if_match }) => {
        sawIfMatch = if_match;
        live = 'etag-2';
        return { status: 'committed', new_etag: 'etag-2', result: { ok: true } };
      },
    });
    assert.equal(out.status, 'committed');
    assert.equal(out.version_token, expected);
    assert.equal(out.result.new_etag, 'etag-2');
    assert.deepEqual(out.result.result, { ok: true });
    assert.equal(sawIfMatch, 'etag-1', 'host receives raw if_match for header — adapter does not send HTTP');
  });

  it('precondition_failed → refused with host current_etag; no invented tokens', async () => {
    let live = 'etag-a';
    const expected = createApiVersionToken(live);
    // Race: host still sees expected on pre-check, write reports 412 with new current
    const out = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => live,
      write: () => ({
        status: 'precondition_failed',
        current_etag: 'etag-b',
      }),
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.reason, 'stale_version_token');
    assert.equal(out.expected_token, expected);
    assert.equal(out.current_token, createApiVersionToken('etag-b'));
    assert.equal(out.version_token, undefined);
    assert.equal(out.post_commit_token, undefined);
  });

  it('precondition_failed without current_etag → current_token null (no invention)', async () => {
    const expected = createApiVersionToken('etag-x');
    const out = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => 'etag-x',
      write: () => ({ status: 'precondition_failed' }),
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.current_token, null);
  });

  it('pre-check mismatch → refused without calling write', async () => {
    let wrote = false;
    const out = await writeApiIfUnchanged({
      expected_token: createApiVersionToken('old'),
      current_etag: () => 'new',
      write: () => {
        wrote = true;
        return { status: 'committed', new_etag: 'x' };
      },
    });
    assert.equal(out.status, 'refused');
    assert.equal(wrote, false);
  });

  it('detect_stale_during_commit: new_etag intended vs live post mismatch → committed_stale_detected', async () => {
    let live = 'e1';
    const expected = createApiVersionToken(live);
    const out = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => live,
      detect_stale_during_commit: true,
      write: () => {
        // Host thought new etag is e2, but concurrent overwrite set e3 before post-check
        live = 'e3';
        return { status: 'committed', new_etag: 'e2', result: 'body' };
      },
    });
    assert.equal(out.status, 'committed_stale_detected');
    assert.equal(out.reason, 'stale_during_commit');
    assert.equal(out.expected_token, expected);
    assert.equal(out.post_commit_token, createApiVersionToken('e3'));
    assert.equal(out.result.new_etag, 'e2');
  });

  it('detect with missing new_etag is a no-op (honest; cannot invent post intent)', async () => {
    let live = 'e1';
    const expected = createApiVersionToken(live);
    const out = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => live,
      detect_stale_during_commit: true,
      write: () => {
        live = 'e-after';
        return { status: 'committed', result: 'ok' }; // no new_etag
      },
    });
    // Without intended post-etag, expected_after re-reads live → match → clean committed
    assert.equal(out.status, 'committed');
    assert.equal(out.result.new_etag, null);
  });
});

// ── DB ───────────────────────────────────────────────────────────────────────
describe('db CAS adapter (optimistic lock, host-injected)', () => {
  it('createDbVersionToken: numbers + absent', () => {
    assert.equal(createDbVersionToken(null), DB_ABSENT_TOKEN);
    assert.equal(createDbVersionToken(7), `${DB_VERSION_TOKEN_PREFIX}7`);
    assert.equal(dbTokenRaw(createDbVersionToken(7)), '7');
  });

  it('committed via rows_affected > 0', async () => {
    let ver = 3;
    const expected = createDbVersionToken(ver);
    let sawExpected = null;
    const out = await writeDbIfUnchanged({
      expected_token: expected,
      current_version: () => ver,
      write: ({ expected_version }) => {
        sawExpected = expected_version;
        ver = 4;
        return { rows_affected: 1, new_version: 4, result: { id: 1 } };
      },
    });
    assert.equal(out.status, 'committed');
    assert.equal(out.version_token, expected);
    assert.equal(out.result.new_version, '4');
    assert.equal(sawExpected, '3');
  });

  it('rows_affected === 0 → refused; no invented current_token when host omitted it', async () => {
    const expected = createDbVersionToken(10);
    const out = await writeDbIfUnchanged({
      expected_token: expected,
      current_version: () => 10,
      write: () => ({ rows_affected: 0 }),
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.reason, 'stale_version_token');
    assert.equal(out.expected_token, expected);
    assert.equal(out.current_token, null);
  });

  it('status:conflict with current_version → refused + current_token', async () => {
    const expected = createDbVersionToken(1);
    const out = await writeDbIfUnchanged({
      expected_token: expected,
      current_version: () => 1,
      write: () => ({ status: 'conflict', current_version: 9 }),
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.current_token, createDbVersionToken(9));
  });

  it('pre-check mismatch → refused without write', async () => {
    let wrote = false;
    const out = await writeDbIfUnchanged({
      expected_token: createDbVersionToken(1),
      current_version: () => 2,
      write: () => {
        wrote = true;
        return { rows_affected: 1 };
      },
    });
    assert.equal(out.status, 'refused');
    assert.equal(wrote, false);
  });

  it('detect_stale_during_commit with new_version mismatch → committed_stale_detected', async () => {
    let ver = 5;
    const expected = createDbVersionToken(ver);
    const out = await writeDbIfUnchanged({
      expected_token: expected,
      current_version: () => ver,
      detect_stale_during_commit: true,
      write: () => {
        ver = 99; // concurrent overwrite after our update
        return { status: 'committed', new_version: 6, result: 'row' };
      },
    });
    assert.equal(out.status, 'committed_stale_detected');
    assert.equal(out.post_commit_token, createDbVersionToken(99));
    assert.equal(out.result.new_version, '6');
  });
});

// ── Registry ─────────────────────────────────────────────────────────────────
describe('registry CAS adapter (compareAndSwap, host-injected)', () => {
  it('createRegistryVersionToken prefix + absent', () => {
    assert.equal(createRegistryVersionToken(null), REGISTRY_ABSENT_TOKEN);
    assert.ok(createRegistryVersionToken('rev-1').startsWith(REGISTRY_VERSION_TOKEN_PREFIX));
    assert.equal(registryTokenRaw(createRegistryVersionToken('rev-1')), 'rev-1');
  });

  it('swapped:true → committed', async () => {
    let tok = 'r1';
    const expected = createRegistryVersionToken(tok);
    let sawExpected = null;
    const out = await writeRegistryIfUnchanged({
      expected_token: expected,
      current_token: () => tok,
      compareAndSwap: ({ expected: exp }) => {
        sawExpected = exp;
        tok = 'r2';
        return { swapped: true, new_token: 'r2', result: { key: 'k' } };
      },
    });
    assert.equal(out.status, 'committed');
    assert.equal(out.version_token, expected);
    assert.equal(out.result.new_token, 'r2');
    assert.equal(sawExpected, 'r1');
  });

  it('swapped:false → refused; current_token from host or null', async () => {
    const expected = createRegistryVersionToken('r1');
    const out = await writeRegistryIfUnchanged({
      expected_token: expected,
      current_token: () => 'r1',
      compareAndSwap: () => ({ swapped: false, current_token: 'r9' }),
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.reason, 'stale_version_token');
    assert.equal(out.current_token, createRegistryVersionToken('r9'));
    assert.equal(out.version_token, undefined);

    const out2 = await writeRegistryIfUnchanged({
      expected_token: expected,
      current_token: () => 'r1',
      compareAndSwap: () => ({ swapped: false }),
    });
    assert.equal(out2.status, 'refused');
    assert.equal(out2.current_token, null);
  });

  it('status:conflict alias shape → refused', async () => {
    const expected = createRegistryVersionToken('a');
    const out = await writeRegistryIfUnchanged({
      expected_token: expected,
      current_token: () => 'a',
      compareAndSwap: () => ({ status: 'conflict', current_token: 'b' }),
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.current_token, createRegistryVersionToken('b'));
  });

  it('detect_stale_during_commit mismatch → committed_stale_detected', async () => {
    let tok = 'g1';
    const expected = createRegistryVersionToken(tok);
    const out = await writeRegistryIfUnchanged({
      expected_token: expected,
      current_token: () => tok,
      detect_stale_during_commit: true,
      compareAndSwap: () => {
        tok = 'g-race';
        return { status: 'committed', new_token: 'g2' };
      },
    });
    assert.equal(out.status, 'committed_stale_detected');
    assert.equal(out.post_commit_token, createRegistryVersionToken('g-race'));
  });
});

// ── Attestation integration (api outcome) ────────────────────────────────────
describe('api adapter outcome → buildCasAttestation', () => {
  it('binds committed api outcome without touching attestation implementation', async () => {
    let live = 'etag-bind';
    const expected = createApiVersionToken(live);
    const cas = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => live,
      write: () => {
        live = 'etag-bind-2';
        return { status: 'committed', new_etag: 'etag-bind-2' };
      },
    });
    assert.equal(cas.status, 'committed');
    const att = buildCasAttestation(minimalProof(), cas);
    assert.equal(att.attestation_spec, CAS_ATTESTATION_SPEC);
    assert.equal(att.cas.status, 'committed');
    assert.equal(att.derived.authorized_and_committed, true);
    assert.equal(att.references.decision_id, 'dec_cas_adapters_1');
    assert.equal(att.cas.version_token, expected);
  });

  it('binds refused api outcome', async () => {
    const expected = createApiVersionToken('e1');
    const cas = await writeApiIfUnchanged({
      expected_token: expected,
      current_etag: () => 'e1',
      write: () => ({ status: 'precondition_failed', current_etag: 'e2' }),
    });
    const att = buildCasAttestation(minimalProof(), cas);
    assert.equal(att.cas.status, 'refused');
    assert.equal(att.derived.write_ran, false);
    assert.equal(att.derived.authorized_and_committed, false);
  });
});

describe('family conventions', () => {
  it('prefixes are distinct and stable', () => {
    assert.equal(API_VERSION_TOKEN_PREFIX, 'api:v1:');
    assert.equal(DB_VERSION_TOKEN_PREFIX, 'db:v1:');
    assert.equal(REGISTRY_VERSION_TOKEN_PREFIX, 'registry:v1:');
    assert.ok(API_ABSENT_TOKEN.startsWith(API_VERSION_TOKEN_PREFIX));
    assert.ok(DB_ABSENT_TOKEN.startsWith(DB_VERSION_TOKEN_PREFIX));
    assert.ok(REGISTRY_ABSENT_TOKEN.startsWith(REGISTRY_VERSION_TOKEN_PREFIX));
  });

  it('tokensEqual re-exported and works across adapter tokens', () => {
    const a = createApiVersionToken('x');
    assert.equal(tokensEqual(a, createApiVersionToken('x')), true);
    assert.equal(tokensEqual(a, createDbVersionToken('x')), false);
  });
});
