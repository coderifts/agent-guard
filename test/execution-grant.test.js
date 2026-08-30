'use strict';

/**
 * Native execution grant (9.6.0): per-call include_execution_grant + nonce + factory context.
 * Default OFF is byte-identical to 9.5.0. No process-global last grant.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  guardToolCall,
  withCodeRifts,
  computeCanonicalBundleFingerprint,
  computeBodyHash,
  writeFileIfUnchanged,
  createFsVersionToken,
} = require('../dist/cjs/index.js');

const ARTIFACTS = [
  { id: 'public-api', type: 'openapi', before: 'openapi: 3.0.0\npaths: {}\n', after: 'openapi: 3.0.0\npaths: {/x: {get: {}}}\n' },
];
const FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'merge' });

function boundVerify(env) {
  return {
    valid: true,
    status: 'VERIFIED_CURRENT',
    payload: { fp: env.fingerprint, bh: computeBodyHash(env) },
  };
}

function envelope(opts = {}) {
  return {
    spec_version: 'decision-result.v1.1',
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    decision_id: 'dec_grant_1',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900000).toISOString(),
    fingerprint: FP,
    input_fingerprint: FP,
    safe_for_agent: true,
    analysis_complete: true,
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
    ...opts,
  };
}

function allowBody(extra = {}) {
  const env = envelope();
  return {
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    decision_result: env,
    ...extra,
  };
}

function mockClient(preflight) {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) {
      return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
    },
    async preflightChangeSet(req) {
      const resp = await preflight(req);
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

const CALL = {
  toolName: 'Edit',
  arguments: { path: 'openapi.yaml' },
  artifacts: ARTIFACTS,
};

describe('executionGrant default OFF — byte-identical to 9.5.0', () => {
  it('absent config does not request a grant and omits execution_grant on the outcome', async () => {
    const seen = [];
    const client = mockClient((req) => {
      seen.push(req);
      return allowBody();
    });
    let factoryGrant;
    const outcome = await guardToolCall(
      CALL,
      async (_e, _r, exec) => {
        factoryGrant = exec;
        return { ok: true };
      },
      { client, operation: 'merge' },
    );
    assert.equal(outcome.executed, true);
    assert.equal(seen[0].include_execution_grant, undefined);
    assert.equal(seen[0].state_nonce, undefined);
    assert.equal(outcome.execution_grant, undefined);
    assert.equal(factoryGrant, undefined);
  });

  it('enabled:false-shaped absence vs omitted: same outcome keys (no execution_grant field)', async () => {
    const clientA = mockClient(() => allowBody());
    const clientB = mockClient(() => allowBody());
    const a = await guardToolCall(CALL, async () => ({ ok: true }), { client: clientA, operation: 'merge' });
    const b = await guardToolCall(CALL, async () => ({ ok: true }), { client: clientB, operation: 'merge' });
    assert.deepEqual(Object.keys(a).sort(), Object.keys(b).sort());
    assert.ok(!Object.prototype.hasOwnProperty.call(a, 'execution_grant'));
    assert.ok(!Object.prototype.hasOwnProperty.call(b, 'execution_grant'));
  });
});

describe('executionGrant enabled', () => {
  it('without resolver → grant requested, no nonce, factory receives THIS grant', async () => {
    const seen = [];
    const client = mockClient((req) => {
      seen.push(req);
      return allowBody({ execution_grant: 'grant-bearer-1' });
    });
    let got;
    const outcome = await guardToolCall(
      CALL,
      async (_e, _r, exec) => {
        got = exec && exec.execution_grant;
        return { ok: true };
      },
      { client, operation: 'merge', executionGrant: { enabled: true } },
    );
    assert.equal(seen[0].include_execution_grant, true);
    assert.equal(seen[0].state_nonce, undefined);
    assert.equal(got, 'grant-bearer-1');
    assert.deepEqual(outcome.execution_grant, { requested: true, arrived: true });
  });

  it('with resolver → nonce threaded for THAT call', async () => {
    const seen = [];
    const client = mockClient((req) => {
      seen.push(req);
      return allowBody({ execution_grant: `grant-${req.state_nonce}` });
    });
    const outcome = await guardToolCall(
      CALL,
      async (_e, _r, exec) => exec.execution_grant,
      {
        client,
        operation: 'merge',
        executionGrant: {
          enabled: true,
          resolveStateNonce: async ({ artifactId, toolName }) => {
            assert.equal(artifactId, 'public-api');
            assert.equal(toolName, 'Edit');
            return 'nonce-xyz';
          },
        },
      },
    );
    assert.equal(seen[0].state_nonce, 'nonce-xyz');
    assert.equal(outcome.result, 'grant-nonce-xyz');
    assert.equal(outcome.execution_grant.arrived, true);
  });

  it('resolver throw → fail closed EXECUTION_GRANT_NONCE_UNRESOLVABLE, factory never runs', async () => {
    let ran = false;
    const client = mockClient(() => allowBody({ execution_grant: 'should-not-issue' }));
    const outcome = await guardToolCall(
      CALL,
      async () => {
        ran = true;
        return { ok: true };
      },
      {
        client,
        operation: 'merge',
        executionGrant: {
          enabled: true,
          resolveStateNonce: async () => {
            throw new Error('challenge failed');
          },
        },
      },
    );
    assert.equal(ran, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.cause, 'EXECUTION_GRANT_NONCE_UNRESOLVABLE');
    assert.deepEqual(outcome.execution_grant, { requested: true, arrived: false });
  });

  it('signer-off SIGNER_UNAVAILABLE → fail closed with that cause, never grant-less proceed', async () => {
    let ran = false;
    const client = {
      async authorizeChangeSet() {
        const err = new Error('authorize allow-class with include_execution_grant requires a signed execution grant');
        err.code = 'SIGNER_UNAVAILABLE';
        err.status = 503;
        throw err;
      },
      async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
    };
    const outcome = await guardToolCall(
      CALL,
      async () => {
        ran = true;
        return { ok: true };
      },
      { client, operation: 'merge', executionGrant: { enabled: true } },
    );
    assert.equal(ran, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'SIGNER_UNAVAILABLE');
    assert.deepEqual(outcome.execution_grant, { requested: true, arrived: false });
  });

  it('allow-class 200 without execution_grant → EXECUTION_GRANT_MISSING, factory never runs', async () => {
    let ran = false;
    const client = mockClient(() => allowBody());
    const outcome = await guardToolCall(
      CALL,
      async () => {
        ran = true;
        return { ok: true };
      },
      { client, operation: 'merge', executionGrant: { enabled: true } },
    );
    assert.equal(ran, false);
    assert.equal(outcome.verdict.cause, 'EXECUTION_GRANT_MISSING');
    assert.deepEqual(outcome.execution_grant, { requested: true, arrived: false });
  });

  it('failPolicy open + NETWORK while grant requested → fail closed, never grant-less OPEN_PASSTHROUGH', async () => {
    let ran = false;
    const client = {
      async authorizeChangeSet() {
        throw Object.assign(new Error('fetch failed'), { name: 'TypeError' });
      },
      async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
    };
    const outcome = await guardToolCall(
      CALL,
      async () => {
        ran = true;
        return { ok: true };
      },
      { client, operation: 'merge', failPolicy: 'open', retries: 0, executionGrant: { enabled: true } },
    );
    assert.equal(ran, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.resolution, 'CLOSED');
    assert.equal(outcome.verdict.cause, 'NETWORK');
    assert.deepEqual(outcome.execution_grant, { requested: true, arrived: false });
  });

  it('failPolicy open + naked HTTP 503 while grant requested → SIGNER_UNAVAILABLE, factory never runs', async () => {
    let ran = false;
    const client = {
      async authorizeChangeSet() {
        throw Object.assign(new Error('service unavailable'), { status: 503, name: 'ApiError' });
      },
      async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
    };
    const outcome = await guardToolCall(
      CALL,
      async () => {
        ran = true;
        return { ok: true };
      },
      { client, operation: 'merge', failPolicy: 'open', retries: 0, executionGrant: { enabled: true } },
    );
    assert.equal(ran, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'SIGNER_UNAVAILABLE');
    assert.equal(outcome.verdict.resolution, 'CLOSED');
    assert.deepEqual(outcome.execution_grant, { requested: true, arrived: false });
  });

  it('failPolicy open + NETWORK with grant OFF remains OPEN_PASSTHROUGH (9.5.0)', async () => {
    const client = {
      async authorizeChangeSet() {
        throw Object.assign(new Error('fetch failed'), { name: 'TypeError' });
      },
      async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
    };
    const outcome = await guardToolCall(
      CALL,
      async () => ({ ok: true }),
      { client, operation: 'merge', failPolicy: 'open', retries: 0 },
    );
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.verdict.resolution, 'OPEN_PASSTHROUGH');
    assert.equal(outcome.execution_grant, undefined);
  });

  it('failPolicy open + 503 message mentioning SIGNER_UNAVAILABLE with grant OFF remains OPEN_PASSTHROUGH', async () => {
    const client = {
      async authorizeChangeSet() {
        throw Object.assign(new Error('SIGNER_UNAVAILABLE: not requested'), { status: 503, name: 'ApiError' });
      },
      async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
    };
    const outcome = await guardToolCall(
      CALL,
      async () => ({ ok: true }),
      { client, operation: 'merge', failPolicy: 'open', retries: 0 },
    );
    assert.equal(outcome.executed, true);
    assert.equal(outcome.verdict.resolution, 'OPEN_PASSTHROUGH');
    assert.equal(outcome.verdict.cause, 'SERVER_ERROR');
    assert.equal(outcome.execution_grant, undefined);
  });
});

describe('executionGrant concurrency — N overlapping calls, each gets ITS OWN grant', () => {
  it('8 overlapping guardToolCall invocations with distinct nonces', async () => {
    const N = 8;
    const client = mockClient(async (req) => {
      const nonce = req.state_nonce;
      await new Promise((r) => setTimeout(r, 15 + (String(nonce).charCodeAt(String(nonce).length - 1) % 20)));
      return allowBody({ execution_grant: `grant-for-${nonce}` });
    });
    const received = [];
    const jobs = [];
    for (let i = 0; i < N; i++) {
      const nonce = `n-${i}`;
      jobs.push(
        guardToolCall(
          {
            toolName: 'Edit',
            arguments: { path: 'openapi.yaml', i },
            artifacts: ARTIFACTS,
          },
          async (_e, redacted, exec) => {
            received.push({ i: redacted.arguments.i, grant: exec && exec.execution_grant });
            return exec.execution_grant;
          },
          {
            client,
            operation: 'merge',
            executionGrant: {
              enabled: true,
              resolveStateNonce: async ({ args }) => `n-${args.i}`,
            },
          },
        ),
      );
    }
    const outcomes = await Promise.all(jobs);
    assert.equal(outcomes.length, N);
    for (let i = 0; i < N; i++) {
      const o = outcomes[i];
      assert.equal(o.executed, true, `call ${i} executed`);
      assert.equal(o.result, `grant-for-n-${i}`, `call ${i} result`);
      assert.equal(o.execution_grant.arrived, true);
    }
    const byI = new Map(received.map((r) => [r.i, r.grant]));
    for (let i = 0; i < N; i++) {
      assert.equal(byI.get(i), `grant-for-n-${i}`, `factory for i=${i} saw its own grant`);
    }
  });

  it('withCodeRifts overlapping tools each receive their own grant on execute 2nd arg', async () => {
    const seenNonces = [];
    const client = mockClient(async (req) => {
      seenNonces.push(req.state_nonce);
      await new Promise((r) => setTimeout(r, 10));
      return allowBody({ execution_grant: `g-${req.state_nonce}` });
    });
    const got = [];
    const { tools } = withCodeRifts({
      tools: [
        {
          name: 'edit_a',
          mutationClass: 'mutating',
          execute: async (args, execution) => {
            got.push({ name: 'edit_a', grant: execution && execution.execution_grant, i: args.i });
            return execution.execution_grant;
          },
        },
        {
          name: 'edit_b',
          mutationClass: 'mutating',
          execute: async (args, execution) => {
            got.push({ name: 'edit_b', grant: execution && execution.execution_grant, i: args.i });
            return execution.execution_grant;
          },
        },
      ],
      client,
      operation: 'merge',
      executionGrant: {
        enabled: true,
        resolveStateNonce: async ({ toolName, args }) => `${toolName}-${args.i}`,
      },
    });
    const ta = tools.find((t) => t.name === 'edit_a');
    const tb = tools.find((t) => t.name === 'edit_b');
    const [oa, ob] = await Promise.all([
      ta.execute({ ...CALL.arguments, i: 1, artifacts: ARTIFACTS }),
      tb.execute({ ...CALL.arguments, i: 2, artifacts: ARTIFACTS }),
    ]);
    assert.equal(oa.result, 'g-edit_a-1');
    assert.equal(ob.result, 'g-edit_b-2');
    const ga = got.find((x) => x.name === 'edit_a');
    const gb = got.find((x) => x.name === 'edit_b');
    assert.equal(ga.grant, 'g-edit_a-1');
    assert.equal(gb.grant, 'g-edit_b-2');
  });
});

describe('executionGrant is not a preimage field', () => {
  it('authorize artifacts/context are unchanged aside from grant flags (no grant token in request)', async () => {
    const seen = [];
    const client = mockClient((req) => {
      seen.push(req);
      return allowBody({ execution_grant: 'tok' });
    });
    await guardToolCall(
      CALL,
      async () => ({ ok: true }),
      { client, operation: 'merge', executionGrant: { enabled: true } },
    );
    assert.deepEqual(seen[0].artifacts, ARTIFACTS);
    assert.equal(seen[0].context.operation, 'merge');
    assert.equal(seen[0].execution_grant, undefined);
    assert.equal(typeof seen[0].include_execution_grant, 'boolean');
  });

  it('T3 commit-observation re-preflight does not request a grant', async () => {
    const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'coderifts-grant-t3-'));
    const filePath = path.join(tmp, 'spec.yaml');
    await fsp.writeFile(filePath, 'before', 'utf8');
    const artifacts = [
      { id: 'public-api', type: 'openapi', before: 'before', after: 'after-auth' },
    ];
    const fp = computeCanonicalBundleFingerprint(artifacts, { operation: 'merge' });
    const seen = [];
    const client = mockClient((req) => {
      seen.push({
        include_execution_grant: req.include_execution_grant,
        state_nonce: req.state_nonce,
      });
      const env = envelope({ fingerprint: fp, input_fingerprint: fp });
      return {
        decision: 'ALLOW',
        execution_action: 'CONTINUE',
        decision_result: env,
        execution_grant: 'grant-t3',
      };
    });
    try {
      await guardToolCall(
        {
          toolName: 'Edit',
          arguments: { path: filePath, contents: 'after-auth' },
          artifacts,
        },
        async () => {
          const tok = await createFsVersionToken(filePath);
          const out = await writeFileIfUnchanged({ path: filePath, expected_token: tok, content: 'after-auth' });
          await fsp.writeFile(filePath, 'racer', 'utf8');
          return out;
        },
        { client, operation: 'merge', executionGrant: { enabled: true } },
      );
      assert.ok(seen.length >= 2, `expected authorize + T3 re-preflight, got ${seen.length}`);
      assert.equal(seen[0].include_execution_grant, true);
      for (let i = 1; i < seen.length; i++) {
        assert.equal(seen[i].include_execution_grant, undefined, `T3 request ${i} must not ask for a grant`);
        assert.equal(seen[i].state_nonce, undefined);
      }
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

// ── 1198: THE RESOLVED IDENTITY IS ON THE REQUEST ────────────────────────────
/**
 * The V2 identity used to live in two places: the top level of the withCodeRifts
 * input (→ the ATOMIC construction check) and the nested executionGrant config
 * (→ this request). A value set only at the top level never reached the wire.
 *
 * These read the body that actually went out. MEASURED while writing them: a
 * unit test over `v2WireFields(input)` stays green even when the with-coderifts
 * handoff drops the resolved values, because it never touches the handoff — the
 * request body is the only place the whole path is observable.
 */
describe('1198 — the V2 identity reaches the authorize request', () => {
  const V2 = { enabled: true, grantVersion: 'v2', resolveStateNonce: async () => 'nonce-1' };

  it('a TOP-LEVEL identity is on the body', async () => {
    const seen = [];
    const client = mockClient((req) => { seen.push(req); return allowBody(); });
    await guardToolCall(CALL, async () => ({ ok: true }), {
      client,
      operation: 'merge',
      executorId: 'exec-7',
      adapterId: 'pg',
      targetUri: 'postgres://articles',
      executionGrant: V2,
    });
    assert.ok(seen.length > 0);
    assert.equal(seen[0].grant_version, 'v2');
    assert.equal(seen[0].executor_id, 'exec-7', 'the top-level executorId never reached the wire');
    assert.equal(seen[0].adapter_id, 'pg');
    assert.equal(seen[0].target_uri, 'postgres://articles');
  });

  it('the deprecated nested identity is still on the body', async () => {
    const seen = [];
    const client = mockClient((req) => { seen.push(req); return allowBody(); });
    await guardToolCall(CALL, async () => ({ ok: true }), {
      client,
      operation: 'merge',
      executionGrant: { ...V2, executorId: 'exec-nested' },
    });
    assert.equal(seen[0].executor_id, 'exec-nested');
  });

  it('a MISMATCH refuses rather than sending one of the two', async () => {
    const seen = [];
    const client = mockClient((req) => { seen.push(req); return allowBody(); });
    await assert.rejects(
      () => guardToolCall(CALL, async () => ({ ok: true }), {
        client,
        operation: 'merge',
        executorId: 'exec-top',
        executionGrant: { ...V2, executorId: 'exec-nested' },
      }),
      (e) => e.code === 'V2_FIELDS_CONFLICT',
    );
    assert.equal(seen.length, 0, 'a request went out despite a conflicting identity');
  });

  it('an unsupplied field is ABSENT from the body, never an empty placeholder', async () => {
    const seen = [];
    const client = mockClient((req) => { seen.push(req); return allowBody(); });
    await guardToolCall(CALL, async () => ({ ok: true }), {
      client, operation: 'merge', executorId: 'exec-7', executionGrant: V2,
    });
    for (const k of ['adapter_id', 'target_uri', 'tenant_id', 'policy_hash', 'audience_hash']) {
      assert.ok(!(k in seen[0]), `${k} was sent as a placeholder`);
    }
  });

  it('a v1 grant carries NO V2 fields even with the identity configured', async () => {
    const seen = [];
    const client = mockClient((req) => { seen.push(req); return allowBody(); });
    await guardToolCall(CALL, async () => ({ ok: true }), {
      client,
      operation: 'merge',
      executorId: 'exec-7',
      executionGrant: { enabled: true, grantVersion: 'v1', resolveStateNonce: async () => 'n' },
    });
    assert.equal(seen[0].grant_version, undefined);
    assert.equal(seen[0].executor_id, undefined);
  });
});
