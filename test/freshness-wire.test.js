'use strict';

/**
 * Freshness wiring: opt-in resolver, three wiring states, per-call basis, requireFreshness.
 * Pure assessFreshness stays pure; runner collects values and passes them into guardToolCall.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  guardToolCall,
  withCodeRifts,
  collectFreshnessCallContext,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

const BEFORE = 'openapi: 3.0.0\npaths: {}\n';
const AFTER = 'openapi: 3.0.0\npaths:\n  /x:\n    get: {}\n';
const ARTIFACTS = [{ id: 'openapi:spec.yaml', type: 'openapi', before: BEFORE, after: AFTER }];
const ARTIFACTS_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });
const TRIGGER = { toolName: 'Edit', arguments: { path: 'spec.yaml', old_string: 'a', new_string: 'b' }, artifacts: ARTIFACTS };
const WRITE = {
  toolName: 'Write',
  arguments: { path: 'openapi.yaml', contents: AFTER },
  // no both-side artifacts — write-style
  filesTouched: ['openapi.yaml'],
};

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: 'dec_fw', correlation_id: 'c', evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint || ARTIFACTS_FP,
    input_fingerprint: opts.fingerprint || ARTIFACTS_FP,
    operation: 'tool_call',
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function response(execution_action, decision, opts) {
  return { decision, decision_result: envelope(execution_action, decision, opts) };
}
function mockClient() {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const resp = response('CONTINUE', 'ALLOW');
      lastEnv = resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

describe('freshness wire — NOT_CONFIGURED without resolver', () => {
  it('existing both-side call still works and reports NOT_CONFIGURED', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), { client: mockClient() });
    assert.equal(o.executed, true);
    assert.equal(o.enforced, true);
    assert.ok(o.freshness, 'freshness basis on outcome');
    assert.equal(o.freshness.wiring, 'NOT_CONFIGURED');
    assert.equal(o.freshness.assessment, undefined);
    assert.notEqual(o.freshness.wiring, 'DEGRADED');
  });

  it('composition reports freshness_resolver_wired false and residual, inescapable stays false', () => {
    const r = withCodeRifts({
      tools: [{ name: 'Read', description: 'r', inputSchema: {}, execute: async () => 1 }],
      client: mockClient(),
      operation: 'tool_call',
    });
    assert.equal(r.composition_assurance.freshness_resolver_wired, false);
    assert.ok(r.composition_assurance.residuals.includes('composition_freshness_not_configured'));
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
  });
});

describe('freshness wire — DEGRADED distinct from NOT_CONFIGURED', () => {
  it('resolver that throws → DEGRADED, not NOT_CONFIGURED', async () => {
    const fctx = await collectFreshnessCallContext({
      call: { toolName: 'Write', artifacts: ARTIFACTS, arguments: { path: 'spec.yaml' } },
      resolvePriorContent: async () => { throw new Error('disk gone'); },
    });
    assert.equal(fctx.wiring, 'DEGRADED');
    assert.equal(fctx.degrade.reason, 'resolver_threw');
    assert.match(fctx.degrade.detail || '', /disk gone/);

    const o = await guardToolCall(
      { ...WRITE, arguments: { path: 'openapi.yaml', contents: AFTER, artifact_id: 'openapi:spec.yaml' } },
      async () => ({ ok: true }),
      { client: mockClient(), requireFreshness: true },
      fctx,
    );
    assert.equal(o.executed, false);
    assert.equal(o.freshness.wiring, 'DEGRADED');
    assert.notEqual(o.freshness.wiring, 'NOT_CONFIGURED');
    assert.equal(o.verdict.kind, 'UNAVAILABLE');
    assert.equal(o.verdict.cause, 'FRESHNESS_REQUIRED');
  });

  it('resolver returns empty → DEGRADED', async () => {
    const fctx = await collectFreshnessCallContext({
      call: { toolName: 'Write', artifacts: ARTIFACTS, arguments: {} },
      resolvePriorContent: async () => null,
    });
    assert.equal(fctx.wiring, 'DEGRADED');
    assert.equal(fctx.degrade.reason, 'resolver_returned_empty');
  });
});

describe('freshness wire — requireFreshness fail-closed without resolver', () => {
  it('write-style under requireFreshness without resolver does not proceed', async () => {
    let ran = false;
    const o = await guardToolCall(
      {
        toolName: 'Write',
        arguments: { path: 'openapi.yaml', contents: AFTER },
        filesTouched: ['openapi.yaml'],
      },
      async () => { ran = true; return 1; },
      { client: mockClient(), requireFreshness: true },
      { wiring: 'NOT_CONFIGURED' },
    );
    assert.equal(ran, false);
    assert.equal(o.executed, false);
    assert.equal(o.executionAttempted, false);
    assert.equal(o.freshness.wiring, 'NOT_CONFIGURED');
    assert.equal(o.freshness.require_freshness, true);
    assert.equal(o.freshness.write_style, true);
    assert.equal(o.verdict.cause, 'FRESHNESS_REQUIRED');
  });

  it('without requireFreshness, write-style without resolver still proceeds (API opt-in)', async () => {
    // Write-style may hit MISSING_ARTIFACT_CONTENT if detector triggers without artifacts —
    // use non-contract path so SKIPPED executes, still with freshness basis.
    const o = await guardToolCall(
      { toolName: 'Write', arguments: { path: 'README.md', contents: 'x' }, filesTouched: ['README.md'] },
      async () => ({ ok: true }),
      { client: mockClient() },
      { wiring: 'NOT_CONFIGURED' },
    );
    assert.equal(o.freshness.wiring, 'NOT_CONFIGURED');
    // README is non-contract → SKIPPED executes
    if (o.verdict.kind === 'SKIPPED') {
      assert.equal(o.executed, true);
    }
  });
});

describe('freshness wire — ACTIVE measurement', () => {
  it('ACTIVE fresh before allows enforce; basis includes assessment', async () => {
    const fctx = await collectFreshnessCallContext({
      call: { toolName: 'Edit', artifacts: ARTIFACTS, arguments: { path: 'spec.yaml' } },
      resolvePriorContent: async ({ artifactId }) => {
        assert.equal(artifactId, 'openapi:spec.yaml');
        return BEFORE;
      },
    });
    assert.equal(fctx.wiring, 'ACTIVE');
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), { client: mockClient() }, fctx);
    assert.equal(o.executed, true);
    assert.equal(o.enforced, true);
    assert.equal(o.freshness.wiring, 'ACTIVE');
    assert.ok(o.freshness.assessment);
    assert.equal(o.freshness.assessment.outcome, 'FRESH');
  });

  it('ACTIVE mutated before blocks as FRESHNESS_FAILED / TARGET_MUTATED', async () => {
    const fctx = await collectFreshnessCallContext({
      call: { toolName: 'Edit', artifacts: ARTIFACTS, arguments: {} },
      resolvePriorContent: async () => BEFORE + '\n# moved\n',
    });
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), { client: mockClient() }, fctx);
    assert.equal(o.executed, false);
    assert.equal(o.freshness.wiring, 'ACTIVE');
    assert.equal(o.freshness.assessment.outcome, 'TARGET_MUTATED');
    assert.equal(o.verdict.cause, 'FRESHNESS_FAILED');
  });
});

describe('freshness wire — composition never flips closed flags', () => {
  it('with resolver wired, inescapable_runtime still false and call policy incomplete residual remains', () => {
    const r = withCodeRifts({
      tools: [{
        name: 'Write',
        description: 'w',
        inputSchema: {},
        execute: async () => 1,
      }],
      client: mockClient(),
      operation: 'tool_call',
      resolvePriorContent: async () => BEFORE,
      requireFreshness: true,
    });
    assert.equal(r.composition_assurance.freshness_resolver_wired, true);
    assert.ok(!r.composition_assurance.residuals.includes('composition_freshness_not_configured'));
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(r.composition_assurance.residuals.includes('composition_call_policy_incomplete'));
  });
});
