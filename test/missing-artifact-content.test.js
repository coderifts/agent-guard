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
const { guardToolCall, guardToolRegistry, computeBodyHash, computeArtifactDigest } = require('../dist/cjs/index.js');

// ── content-bearing artifacts (the WORKING shape) + a valid happy-path envelope/client ──────────────
const ARTIFACTS = [{ id: 'public-api', type: 'openapi', before: 'openapi: 3.0.0', after: 'openapi: 3.0.1' }];
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);
const TRIGGER_WITH_CONTENT = { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS };

function envelope(o = {}) {
  const env = {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: 'sha256:' + 'a'.repeat(64), input_fingerprint: 'sha256:' + 'b'.repeat(64),
    analysis_complete: true, artifact_digest: LOCAL_DIGEST, operation: 'tool_call', ...o,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  env.receipt = { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  return env;
}
function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function client(env) {
  return {
    async preflightChangeSet() { return { decision: env.decision, execution_action: env.execution_action, decision_result: env }; },
    async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; },
  };
}
// a client that must NEVER be reached on the MISSING path (fail-closed happens before any network).
const UNREACHABLE_CLIENT = {
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
  const STUB_CLIENT = { async preflightChangeSet() { return {}; }, async verifyReceipt() { return {}; } };

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
