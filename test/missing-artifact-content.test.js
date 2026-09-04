'use strict';

/**
 * MISSING_ARTIFACT_CONTENT — the developer-adoption fail-closed (audit #1).
 *
 * The detector correctly triggers on a mutating contract change signalled by filesTouched/diff, but if
 * the caller supplies NO analyzable artifact content (no artifacts, or artifacts without before/after),
 * the guard must fail closed LOCALLY with a clear cause instead of sending an empty list to the server
 * (which returned an opaque REQUEST_REJECTED). Fail-closed is preserved: the tool does NOT execute.
 *
 * Everything drives the REAL guardToolCall / guardToolRegistry path — no hand-stubbed guard.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { guardToolCall, guardToolRegistry, computeBodyHash, computeArtifactDigest, computeCanonicalBundleFingerprint } = require('../dist/cjs/index.js');

// ── content-bearing artifacts (the WORKING shape) + a valid happy-path envelope/client ──────────────
const ARTIFACTS = [{ id: 'public-api', type: 'openapi', before: 'openapi: 3.0.0', after: 'openapi: 3.0.1' }];
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);
const LOCAL_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });
const TRIGGER_WITH_CONTENT = { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS };

function envelope(o = {}) {
  const env = {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: LOCAL_FP, input_fingerprint: LOCAL_FP,
    analysis_complete: true, artifact_digest: LOCAL_DIGEST, operation: 'tool_call', ...o,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  env.receipt = { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  return env;
}
function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function client(env) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { return { decision: env.decision, execution_action: env.execution_action, decision_result: env }; },
    async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; },
  };
}
// a client that must NEVER be reached on the MISSING path (fail-closed happens before any network).
const UNREACHABLE_CLIENT = {
  async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { throw new Error('preflight must NOT be called when content is missing'); },
  async verifyReceipt() { throw new Error('verifyReceipt must NOT be called'); },
};

// ── (a) trigger:true + NO artifacts (the README's old broken shape) → MISSING_ARTIFACT_CONTENT ──────
describe('(a) contract change detected but no artifact content → fail closed locally', () => {
  it('filesTouched+diff, no artifacts[] → MISSING_ARTIFACT_CONTENT, tool NOT executed', async () => {
    let executed = false;
    const outcome = await guardToolCall(
      { toolName: 'Edit', arguments: { path: 'openapi.yaml' }, filesTouched: ['openapi.yaml'], diff: '- old\n+ new' },
      async () => { executed = true; return 'SIDE_EFFECT'; },
      { client: UNREACHABLE_CLIENT, operation: 'merge', environment: 'production' },
    );
    assert.equal(executed, false, 'fail-closed: factory never ran');
    assert.equal(outcome.executed, false);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.executionAttempted, false, 'blocked before the factory (safe-to-retry once content is supplied)');
    assert.equal(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT', 'clear, actionable cause');
    assert.equal(outcome.verdict.kind, 'UNAVAILABLE');
    assert.equal(outcome.verdict.action, 'STOP');
  });

  it('artifacts present but WITHOUT before/after content → still MISSING_ARTIFACT_CONTENT', async () => {
    let executed = false;
    const outcome = await guardToolCall(
      { toolName: 'apply_openapi', arguments: {}, artifacts: [{ id: 'x', type: 'openapi' }] },
      async () => { executed = true; return 'SIDE_EFFECT'; },
      { client: UNREACHABLE_CLIENT, operation: 'merge' },
    );
    assert.equal(executed, false);
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT');
  });

  it('an onEvent sink receives the actionable artifact_content_missing event', async () => {
    const events = [];
    await guardToolCall(
      { toolName: 'Edit', filesTouched: ['openapi.yaml'], diff: '- a\n+ b' },
      async () => 'x',
      { client: UNREACHABLE_CLIENT, operation: 'merge', onEvent: (e) => events.push(e) },
    );
    const ev = events.find((e) => e.type === 'artifact_content_missing');
    assert.ok(ev, 'emitted artifact_content_missing');
    assert.equal(ev.cause, 'MISSING_ARTIFACT_CONTENT');
  });
});

// ── (b) trigger:true + artifacts WITH content → normal preflight (no false MISSING) ─────────────────
describe('(b) contract change WITH artifact content → normal preflight path, no false positive', () => {
  it('the working shape (artifacts with before/after) executes; cause is never MISSING_ARTIFACT_CONTENT', async () => {
    let executed = false;
    const outcome = await guardToolCall(
      TRIGGER_WITH_CONTENT,
      async () => { executed = true; return 'SIDE_EFFECT'; },
      { client: client(envelope()) },
    );
    assert.equal(executed, true, 'a good, content-bearing call still runs (no over-block)');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(outcome.result, 'SIDE_EFFECT');
  });

  it('even a content-bearing call that the server BLOCKS is not mislabeled MISSING_ARTIFACT_CONTENT', async () => {
    const outcome = await guardToolCall(
      TRIGGER_WITH_CONTENT,
      async () => 'SIDE_EFFECT',
      { client: client(envelope({ decision: 'BLOCK', execution_action: 'STOP', safe_for_agent: false })) },
    );
    assert.equal(outcome.executed, false, 'server BLOCK still fails closed');
    assert.notEqual(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT', 'got PAST the content gate');
  });
});

// ── (c) non-triggering readonly/non-contract call → passes through, no error ────────────────────────
describe('(c) a non-contract / readonly call passes through untouched (no MISSING error)', () => {
  it('Read with no contract surface → SKIPPED, executes enforced:false, no cause', async () => {
    let executed = false;
    const outcome = await guardToolCall(
      { toolName: 'Read', arguments: { path: 'README.md' } },
      async () => { executed = true; return 'CONTENTS'; },
      { client: UNREACHABLE_CLIENT },
    );
    assert.equal(executed, true, 'non-contract readonly still runs');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, false, 'unenforced passthrough (no preflight)');
    assert.equal(outcome.verdict.kind, 'SKIPPED');
    assert.notEqual(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT');
  });
});

// ── (d) composes through guardToolRegistry's wrapWithGuard (still fail-closed, propagates) ──────────
describe('(d) MISSING_ARTIFACT_CONTENT propagates cleanly through guardToolRegistry', () => {
  const STUB_CLIENT = { async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { return {}; }, async verifyReceipt() { return {}; } };

  it('a registry-wrapped mutator invoked without artifact content fails closed with MISSING_ARTIFACT_CONTENT', async () => {
    let rawRan = false;
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => { rawRan = true; return 'RAW_SIDE_EFFECT'; } }],
      {
        guard: { client: STUB_CLIENT, operation: 'merge' },
        // binder reproduces the broken shape: a contract-touching call with NO artifacts[].
        binders: { Edit: (_tool, args) => ({ toolName: 'Edit', arguments: args, filesTouched: ['openapi.yaml'], diff: '- old\n+ new' }) },
      },
    );
    const outcome = await registry.tools[0].execute({ path: 'openapi.yaml' });
    assert.equal(rawRan, false, 'the raw mutator never ran (fail-closed preserved through the registry)');
    assert.equal(outcome.executed, false);
    assert.equal(outcome.enforced, false);
    assert.equal(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT', 'the local cause propagates through wrapWithGuard');
  });
});

// ── (e) audit L6: args.artifacts flows through the DEFAULT binder (no explicit binder needed) ────────
describe('(e) audit L6: default binder forwards args.artifacts', () => {
  const STUB_CLIENT = { async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() { return {}; }, async verifyReceipt() { return {}; } };

  it('a registry-wrapped tool called with { artifacts } in its ARGS reaches preflight, not MISSING_ARTIFACT_CONTENT', async () => {
    const registry = guardToolRegistry(
      [{ name: 'apply_openapi', mutationClass: 'mutating', execute: async () => 'APPLIED' }],
      { guard: { client: STUB_CLIENT, operation: 'merge' } },
    );
    // No explicit binder. The change is carried as `artifacts` in the tool-call ARGS.
    // The default binder must forward it so the guard analyzes content instead of failing
    // closed locally. Proof of L6: the local MISSING_ARTIFACT_CONTENT cause is NOT raised.
    const outcome = await registry.tools[0].execute({ artifacts: ARTIFACTS });
    const cause = outcome && outcome.verdict && outcome.verdict.cause;
    assert.notEqual(cause, 'MISSING_ARTIFACT_CONTENT',
      'default binder forwarded args.artifacts → guard saw content (did not fail closed locally)');
  });

  it('WITHOUT artifacts in args, the same tool still fails closed locally (fail-closed preserved)', async () => {
    const registry = guardToolRegistry(
      [{ name: 'apply_openapi', mutationClass: 'mutating', execute: async () => 'APPLIED' }],
      { guard: { client: STUB_CLIENT, operation: 'merge' } },
    );
    // args carry NO artifacts and NO before/after content → detector triggers, still fail-closed.
    const outcome = await registry.tools[0].execute({ path: 'openapi.yaml', filesTouched: ['openapi.yaml'], diff: '- a\n+ b' });
    assert.equal(outcome.executed, false, 'still fail-closed when no artifacts content is present');
  });
});

// ── (f) S3 layer 1: defaultBinder lifts explicit edit sides (rename only; no invention) ────────────
// Convention: binder tests live here with the L6 default-binder suite — same surface
// (guardToolRegistry + defaultBinder), same MISSING_ARTIFACT_CONTENT assertions.
describe('(f) S3 layer 1: defaultBinder lifts old_string/new_string and edits[]', () => {
  /** Client that records the preflight request artifacts then fails closed on transport (no full envelope needed). */
  function recordingClient() {
    const seen = { artifacts: null };
    return {
      seen,
      client: {
        async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet(req) {
          seen.artifacts = req && req.artifacts;
          // Throw network so we never need a schema-valid envelope; reaching preflight is the proof.
          throw Object.assign(new Error('fetch failed'), { name: 'TypeError' });
        },
        async verifyReceipt() { throw new Error('verify must not run if preflight throws'); },
      },
    };
  }

  it('a. old_string + new_string + contract path → artifacts lifted, preflight reached (not MISSING)', async () => {
    const { client, seen } = recordingClient();
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client, operation: 'merge' } },
    );
    const outcome = await registry.tools[0].execute({
      path: 'openapi.yaml',
      old_string: 'paths: {}',
      new_string: 'paths:\n  /x:\n    get: {}',
    });
    assert.notEqual(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT',
      'both sides present → lifted → analysable content');
    assert.ok(Array.isArray(seen.artifacts) && seen.artifacts.length === 1, 'preflight saw one lifted artifact');
    assert.equal(seen.artifacts[0].before, 'paths: {}');
    assert.equal(seen.artifacts[0].after, 'paths:\n  /x:\n    get: {}');
    assert.equal(seen.artifacts[0].type, 'openapi');
    assert.equal(seen.artifacts[0].id, 'openapi:openapi.yaml');
  });

  it('b. edits[] with two entries on a contract path → both lifted', async () => {
    const { client, seen } = recordingClient();
    const registry = guardToolRegistry(
      [{ name: 'MultiEdit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client, operation: 'merge' } },
    );
    const outcome = await registry.tools[0].execute({
      path: 'openapi.yaml',
      edits: [
        { old_string: 'a: 1', new_string: 'a: 2' },
        { old_string: 'b: 1', new_string: 'b: 2' },
      ],
    });
    assert.notEqual(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT');
    assert.ok(Array.isArray(seen.artifacts) && seen.artifacts.length === 2);
    assert.equal(seen.artifacts[0].id, 'openapi:openapi.yaml#0');
    assert.equal(seen.artifacts[1].id, 'openapi:openapi.yaml#1');
    assert.equal(seen.artifacts[0].before, 'a: 1');
    assert.equal(seen.artifacts[1].after, 'b: 2');
  });

  it('c. old_string present but empty → NOT lifted; MISSING_ARTIFACT_CONTENT (one-sided pair ban)', async () => {
    // hasAnalyzableContent is an OR: empty before + real after would pass locally and reach the
    // server as a one-sided pair (create/replace where the truth is an edit). That is a fabricated
    // before by omission. The binder must refuse to lift rather than cross that line.
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client: UNREACHABLE_CLIENT, operation: 'merge' } },
    );
    const outcome = await registry.tools[0].execute({
      path: 'openapi.yaml',
      old_string: '',
      new_string: 'openapi: 3.0.0\npaths: {}',
    });
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT');
  });

  it('d. new_string present, old_string absent → NOT lifted, MISSING_ARTIFACT_CONTENT', async () => {
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client: UNREACHABLE_CLIENT, operation: 'merge' } },
    );
    const outcome = await registry.tools[0].execute({
      path: 'openapi.yaml',
      new_string: 'openapi: 3.0.0\npaths: {}',
    });
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'MISSING_ARTIFACT_CONTENT');
  });

  it('e. args.artifacts AND old_string/new_string both present → artifacts win, no merge', async () => {
    const { client, seen } = recordingClient();
    const hostArts = [{ id: 'host-wins', type: 'openapi', before: 'HOST_BEFORE', after: 'HOST_AFTER' }];
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client, operation: 'merge' } },
    );
    await registry.tools[0].execute({
      path: 'openapi.yaml',
      old_string: 'EDIT_BEFORE',
      new_string: 'EDIT_AFTER',
      artifacts: hostArts,
    });
    assert.ok(Array.isArray(seen.artifacts) && seen.artifacts.length === 1);
    assert.equal(seen.artifacts[0].id, 'host-wins');
    assert.equal(seen.artifacts[0].before, 'HOST_BEFORE');
    assert.equal(seen.artifacts[0].after, 'HOST_AFTER');
    // Synthesised edit-side id must not appear.
    assert.notEqual(seen.artifacts[0].id, 'openapi:openapi.yaml');
  });

  it('f. non-contract path (README edit) → NOT lifted', async () => {
    const { client, seen } = recordingClient();
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client, operation: 'merge' } },
    );
    const outcome = await registry.tools[0].execute({
      path: 'README.md',
      old_string: 'old prose',
      new_string: 'new prose',
    });
    // classifyByName(README.md) is null → no lift. This assertion is the point of the test and
    // is unchanged: never fabricate a contract artifact to have something to preflight.
    assert.equal(seen.artifacts, null, 'preflight must not run with lifted README artifacts');

    // 1356 CHANGED WHAT HAPPENS NEXT, and the change is a strengthening. This edit carries
    // old_string/new_string, so it is a MUTATION the detector does not recognise. It used to take
    // the SKIPPED path and EXECUTE with nothing preflighted and nothing signed; by default it is
    // now refused. The test's original intent — no fabricated artifact, no unguarded execution —
    // is better served by the new outcome than by the old one.
    assert.equal(outcome.verdict.cause, 'UNGUARDED_MUTATION');
    assert.equal(outcome.executed, false, 'an unguarded mutation must not run by default');

    // And the opt-out restores the old behaviour — deliberately, by name, never silently.
    process.env.CODERIFTS_ADVISORY = '1';
    try {
      const { client: c2 } = recordingClient();
      const reg2 = guardToolRegistry(
        [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
        { guard: { client: c2, operation: 'merge' } },
      );
      const advisory = await reg2.tools[0].execute({
        path: 'README.md', old_string: 'old prose', new_string: 'new prose',
      });
      assert.equal(advisory.verdict.kind, 'SKIPPED');
      assert.equal(advisory.executed, true);
      assert.equal(advisory.preflighted, false);
    } finally {
      delete process.env.CODERIFTS_ADVISORY;
    }
  });

  it('g. no path → NOT lifted', async () => {
    const registry = guardToolRegistry(
      [{ name: 'Edit', mutationClass: 'mutating', execute: async () => 'X' }],
      { guard: { client: UNREACHABLE_CLIENT, operation: 'merge' } },
    );
    // Content markers may still trigger without a path; without path we never lift → MISSING or SKIPPED.
    const outcome = await registry.tools[0].execute({
      old_string: 'paths: {}',
      new_string: 'paths:\n  /x: {}',
    });
    assert.ok(
      outcome.verdict.cause === 'MISSING_ARTIFACT_CONTENT' || outcome.verdict.kind === 'SKIPPED',
      `expected MISSING or SKIPPED without path, got ${JSON.stringify(outcome.verdict)}`,
    );
  });

  it('h. existing artifacts-only behaviour unchanged (L6 regression guard)', async () => {
    const { client, seen } = recordingClient();
    const registry = guardToolRegistry(
      [{ name: 'apply_openapi', mutationClass: 'mutating', execute: async () => 'APPLIED' }],
      { guard: { client, operation: 'merge' } },
    );
    await registry.tools[0].execute({ artifacts: ARTIFACTS });
    assert.ok(Array.isArray(seen.artifacts) && seen.artifacts.length === 1);
    assert.deepEqual(seen.artifacts, ARTIFACTS);
  });
});
