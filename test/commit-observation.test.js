'use strict';

/**
 * T3 post-commit observation — A7 (i)–(iv) per adapter + regression (enforced unchanged).
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  guardToolCall,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  hashObservedContent,
  writeFileIfUnchanged,
  createFsVersionToken,
  writeApiIfUnchanged,
  createApiVersionToken,
  writeDbIfUnchanged,
  createDbVersionToken,
  writeRegistryIfUnchanged,
  createRegistryVersionToken,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: opts.decision_id || 'dec_t3',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint,
    input_fingerprint: opts.fingerprint,
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}

function mockClient({ fingerprint, onAuthorize } = {}) {
  let lastEnv = null;
  let authorizes = 0;
  return {
    authorizes: () => authorizes,
    async authorizeChangeSet(r) {
      authorizes += 1;
      if (onAuthorize) onAuthorize(r);
      return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
    },
    async preflightChangeSet() {
      const env = envelope('CONTINUE', 'ALLOW', { fingerprint });
      lastEnv = env;
      return { decision: 'ALLOW', decision_result: env };
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

function callFor(artifacts, extra = {}) {
  return {
    toolName: 'Edit',
    arguments: extra.arguments || {},
    artifacts,
    filesTouched: extra.filesTouched,
  };
}

async function run(artifacts, factory, cfg = {}, extra = {}) {
  const fp = computeCanonicalBundleFingerprint(artifacts, { operation: 'tool_call' });
  const client = cfg.client || mockClient({ fingerprint: fp, onAuthorize: cfg.onAuthorize });
  const events = [];
  const outcome = await guardToolCall(
    callFor(artifacts, extra),
    factory,
    { client, onEvent: (e) => events.push(e), ...cfg },
  );
  return { outcome, events, client };
}

let tmpRoot;
before(async () => {
  tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'coderifts-t3-'));
});
after(async () => {
  if (tmpRoot) await fsp.rm(tmpRoot, { recursive: true, force: true });
});

describe('T3 regression — no reader', () => {
  it('existing TRIGGER-style call → not_observed; enforced:true unchanged', async () => {
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome, events } = await run(artifacts, async () => ({ ok: true }));
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'not_observed');
    assert.equal(outcome.commit_observation.host_attestation, 'absent');
    assert.equal(outcome.proof.commit_observation.status, 'not_observed');
    assert.equal(outcome.proof.limits.commit_observation_is_observed_at_t3_not_atomic, true);
    assert.equal(outcome.proof.execution.enforced, true);
    assert.ok(!events.some((e) => e.type === 'commit_observed_drift'));
  });

  it('requireCommitObservation:false → not_observed + commit_observation_check_disabled; enforced:true', async () => {
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome, events } = await run(
      artifacts,
      async () => ({ ok: true }),
      { requireCommitObservation: false },
    );
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'not_observed');
    assert.ok(events.some((e) => e.type === 'commit_observation_check_disabled'));
    assert.ok(!events.some((e) => e.type === 'commit_observed_drift'));
  });

  it('blocked call → not_observed; factory did not run', async () => {
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const fp = computeCanonicalBundleFingerprint(artifacts, { operation: 'tool_call' });
    let ran = false;
    const client = {
      async authorizeChangeSet(r) { return this.preflightChangeSet(r); },
      async preflightChangeSet() {
        const env = envelope('STOP', 'BLOCK', { fingerprint: fp });
        this._env = env;
        return { decision: 'BLOCK', decision_result: env };
      },
      async verifyReceipt() { return boundVerify(this._env); },
    };
    const outcome = await guardToolCall(
      callFor(artifacts),
      async () => { ran = true; return 'x'; },
      { client },
    );
    assert.equal(ran, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.commit_observation.status, 'not_observed');
  });
});

describe('T3 FS adapter (content fingerprint)', () => {
  it('(i) observed_match — disk equals authorized after; enforced:true', async () => {
    const p = path.join(tmpRoot, 'match.txt');
    await fsp.writeFile(p, 'before', 'utf8');
    const artifacts = [{ id: 'f', type: 'openapi', before: 'before', after: 'after-match' }];
    const { outcome } = await run(
      artifacts,
      async () => {
        const tok = await createFsVersionToken(p);
        return writeFileIfUnchanged({ path: p, expected_token: tok, content: 'after-match' });
      },
      {},
      { arguments: { path: p, contents: 'after-match' } },
    );
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_match');
    assert.equal(outcome.commit_observation.observed_fp, hashObservedContent('after-match'));
    assert.equal(outcome.commit_observation.expected_fp, hashObservedContent('after-match'));
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
    assert.equal(await fsp.readFile(p, 'utf8'), 'after-match');
  });

  it('(ii) observed_drift — racer between write and T3; enforced unchanged; blast via preflight', async () => {
    const p = path.join(tmpRoot, 'drift.txt');
    await fsp.writeFile(p, 'before', 'utf8');
    const artifacts = [{ id: 'f', type: 'openapi', before: 'before', after: 'after-auth' }];
    let sawObservedAfter = false;
    const { outcome, events, client } = await run(
      artifacts,
      async () => {
        const tok = await createFsVersionToken(p);
        const out = await writeFileIfUnchanged({ path: p, expected_token: tok, content: 'after-auth' });
        await fsp.writeFile(p, 'racer', 'utf8');
        return out;
      },
      {
        onAuthorize: (r) => {
          const arts = r && r.artifacts;
          if (Array.isArray(arts) && arts[0] && arts[0].after === 'racer') sawObservedAfter = true;
        },
      },
      { arguments: { path: p, contents: 'after-auth' } },
    );
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.commit_observation.host_attestation, 'conflict');
    assert.equal(outcome.commit_observation.observed_fp, hashObservedContent('racer'));
    assert.equal(outcome.commit_observation.expected_fp, hashObservedContent('after-auth'));
    assert.ok(outcome.commit_observation.blast);
    assert.equal(outcome.commit_observation.blast.compared, 'content');
    assert.ok(events.some((e) => e.type === 'commit_observed_drift'));
    assert.ok(client.authorizes() >= 2, 'preflight-on-drift is an extra authorize');
    assert.equal(sawObservedAfter, true);
  });

  it('(iii) host attestation present + match', async () => {
    const p = path.join(tmpRoot, 'attest-match.txt');
    await fsp.writeFile(p, 'b', 'utf8');
    const artifacts = [{ id: 'f', type: 'openapi', before: 'b', after: 'c' }];
    const { outcome } = await run(
      artifacts,
      async () => {
        const tok = await createFsVersionToken(p);
        return writeFileIfUnchanged({ path: p, expected_token: tok, content: 'c' });
      },
      {},
      { arguments: { path: p } },
    );
    assert.equal(outcome.commit_observation.status, 'observed_match');
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
    assert.equal(outcome.enforced, true);
  });

  it('(iv) host attestation committed + observed drift → conflict', async () => {
    const p = path.join(tmpRoot, 'conflict.txt');
    await fsp.writeFile(p, 'b', 'utf8');
    const artifacts = [{ id: 'f', type: 'openapi', before: 'b', after: 'c' }];
    const { outcome } = await run(
      artifacts,
      async () => {
        const tok = await createFsVersionToken(p);
        const out = await writeFileIfUnchanged({ path: p, expected_token: tok, content: 'c' });
        assert.equal(out.status, 'committed');
        await fsp.writeFile(p, 'other', 'utf8');
        return out;
      },
      {},
      { arguments: { path: p } },
    );
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.commit_observation.host_attestation, 'conflict');
  });
});

describe('T3 API adapter (token-only)', () => {
  it('(i) observed_token_match', async () => {
    let live = 'e1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => {
      const expected = createApiVersionToken(live);
      return writeApiIfUnchanged({
        expected_token: expected,
        current_etag: () => live,
        write: () => {
          live = 'e2';
          return { status: 'committed', new_etag: 'e2', result: { ok: true } };
        },
      });
    });
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_token_match');
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
    assert.equal(outcome.commit_observation.token, createApiVersionToken('e2'));
  });

  it('(ii) observed_drift — racer after write before post-read', async () => {
    let live = 'e1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome, events } = await run(artifacts, async () => writeApiIfUnchanged({
      expected_token: createApiVersionToken('e1'),
      current_etag: () => live,
      write: () => {
        live = 'e-racer';
        return { status: 'committed', new_etag: 'e2', result: { ok: true } };
      },
    }));
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.commit_observation.blast.compared, 'token');
    assert.ok(events.some((e) => e.type === 'commit_observed_drift'));
  });

  it('(iii) host attestation present + token match', async () => {
    let live = 'v1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeApiIfUnchanged({
      expected_token: createApiVersionToken(live),
      current_etag: () => live,
      write: () => {
        live = 'v2';
        return { status: 'committed', new_etag: 'v2' };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_token_match');
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
    assert.equal(outcome.enforced, true);
  });

  it('(iv) host committed + observed token drift → conflict', async () => {
    let live = 'v1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeApiIfUnchanged({
      expected_token: createApiVersionToken(live),
      current_etag: () => live,
      write: () => {
        live = 'v-other';
        return { status: 'committed', new_etag: 'v2' };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.commit_observation.host_attestation, 'conflict');
    assert.equal(outcome.enforced, true);
  });
});

describe('T3 DB adapter (token-only)', () => {
  it('(i) observed_token_match', async () => {
    let ver = 1;
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeDbIfUnchanged({
      expected_token: createDbVersionToken(ver),
      current_version: () => ver,
      write: () => {
        ver = 2;
        return { status: 'committed', new_version: 2, result: { id: 1 } };
      },
    }));
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_token_match');
    assert.equal(outcome.commit_observation.token, createDbVersionToken(2));
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
  });

  it('(ii) observed_drift', async () => {
    let ver = 1;
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeDbIfUnchanged({
      expected_token: createDbVersionToken(ver),
      current_version: () => ver,
      write: () => {
        ver = 99;
        return { status: 'committed', new_version: 2 };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.enforced, true);
  });

  it('(iii) host attestation + match', async () => {
    let ver = 5;
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeDbIfUnchanged({
      expected_token: createDbVersionToken(ver),
      current_version: () => ver,
      write: () => {
        ver = 6;
        return { rows_affected: 1, new_version: 6 };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_token_match');
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
  });

  it('(iv) committed + drift → conflict', async () => {
    let ver = 5;
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeDbIfUnchanged({
      expected_token: createDbVersionToken(ver),
      current_version: () => ver,
      write: () => {
        ver = 7;
        return { status: 'committed', new_version: 6 };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.commit_observation.host_attestation, 'conflict');
    assert.equal(outcome.enforced, true);
  });
});

describe('T3 Registry adapter (token-only)', () => {
  it('(i) observed_token_match', async () => {
    let tok = 'r1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeRegistryIfUnchanged({
      expected_token: createRegistryVersionToken(tok),
      current_token: () => tok,
      compareAndSwap: () => {
        tok = 'r2';
        return { swapped: true, new_token: 'r2' };
      },
    }));
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.commit_observation.status, 'observed_token_match');
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
  });

  it('(ii) observed_drift', async () => {
    let tok = 'r1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeRegistryIfUnchanged({
      expected_token: createRegistryVersionToken(tok),
      current_token: () => tok,
      compareAndSwap: () => {
        tok = 'r-racer';
        return { swapped: true, new_token: 'r2' };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.enforced, true);
  });

  it('(iii) host attestation + match', async () => {
    let tok = 'g1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeRegistryIfUnchanged({
      expected_token: createRegistryVersionToken(tok),
      current_token: () => tok,
      compareAndSwap: () => {
        tok = 'g2';
        return { status: 'committed', new_token: 'g2' };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_token_match');
    assert.equal(outcome.commit_observation.host_attestation, 'host_attested_committed');
  });

  it('(iv) committed + drift → conflict', async () => {
    let tok = 'g1';
    const artifacts = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
    const { outcome } = await run(artifacts, async () => writeRegistryIfUnchanged({
      expected_token: createRegistryVersionToken(tok),
      current_token: () => tok,
      compareAndSwap: () => {
        tok = 'g-other';
        return { swapped: true, new_token: 'g2' };
      },
    }));
    assert.equal(outcome.commit_observation.status, 'observed_drift');
    assert.equal(outcome.commit_observation.host_attestation, 'conflict');
    assert.equal(outcome.enforced, true);
  });
});
