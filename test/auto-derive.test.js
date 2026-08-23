/**
 * S1 auto-derive — wrap-layer before/after from current-state readers.
 * Frozen guardToolCall is unchanged; default OFF.
 */
'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  withCodeRifts,
  computeCanonicalBundleFingerprint,
  AUTO_DERIVE_SOURCE,
} = require('../dist/cjs/index.js');

const OP = 'tool_call';
const OPENAPI_BEFORE = 'openapi: 3.0.0\ninfo: { title: t, version: "1" }\npaths: {}\n';
const OPENAPI_AFTER = 'openapi: 3.0.0\ninfo: { title: t, version: "1" }\npaths:\n  /x:\n    get:\n      responses:\n        "200": { description: ok }\n';

function computeBodyHash(env) {
  const { computeBodyHash: h } = require('../dist/cjs/index.js');
  return h(env);
}

function envelope(execution_action, decision, opts = {}) {
  const env = {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: opts.decision_id || 'dec_1',
    correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    fingerprint: opts.fingerprint,
    input_fingerprint: opts.fingerprint,
    safe_for_agent: decision === 'ALLOW' || decision === 'WARN',
    analysis_complete: true,
    operation: OP,
    receipt: { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' },
  };
  if (decision === 'BLOCK') {
    env.remediation_transaction = {
      required_changes: [{ code: 'add_response' }],
      resubmission: {
        reference_fingerprint: opts.fingerprint,
        fingerprint_profile: 'crbundle.v1',
        modified_is_not_permission: true,
      },
      next_preflight_required: true,
      recheck_scope: { targets: ['/x'], precise: true },
      escalation: { path: 'human_review', when: 'changes_infeasible_or_disputed' },
    };
  }
  return env;
}

function capturingClient(decisions) {
  let i = 0;
  let lastEnv = null;
  const captured = [];
  return {
    async authorizeChangeSet(r) {
      return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
    },
    async preflightChangeSet(r) {
      captured.push(r && r.artifacts ? r.artifacts : []);
      const arts = (r && r.artifacts) || [];
      const fp = arts.length
        ? computeCanonicalBundleFingerprint(arts, { operation: OP })
        : (`sha256:${'ab'.repeat(32)}`);
      const d = decisions[Math.min(i, decisions.length - 1)];
      i += 1;
      const env = envelope(d === 'BLOCK' ? 'STOP' : 'CONTINUE', d, {
        fingerprint: fp,
        decision_id: `dec_${i}`,
      });
      lastEnv = env;
      return { decision: d, execution_action: env.execution_action, decision_result: env };
    },
    async verifyReceipt() {
      return lastEnv
        ? { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: lastEnv.fingerprint, bh: computeBodyHash(lastEnv) } }
        : { valid: true, status: 'VERIFIED_CURRENT' };
    },
    get captured() { return captured; },
    get calls() { return i; },
  };
}

let tmpDir;
before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-autoderive-'));
});
after(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function specPath(name) {
  return path.join(tmpDir, name);
}

describe('S1 auto-derive', () => {
  it('host artifacts win — autoDerive does not replace them', async () => {
    const host = [{
      id: 'host',
      type: 'openapi',
      before: OPENAPI_BEFORE,
      after: OPENAPI_AFTER,
    }];
    const client = capturingClient(['ALLOW']);
    const file = specPath('host-win.openapi.yaml');
    fs.writeFileSync(file, 'should-not-be-read');
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: true,
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER, artifacts: host });
    assert.equal(outcome.derivation.mode, 'host_supplied');
    assert.equal(client.captured[0][0].id, 'host');
    assert.equal(client.captured[0][0].before, OPENAPI_BEFORE);
    assert.equal(client.captured[0][0].source, undefined);
  });

  it('autoDerive fills before+after for fs target (temp file)', async () => {
    const file = specPath('fill.openapi.yaml');
    fs.writeFileSync(file, OPENAPI_BEFORE);
    const client = capturingClient(['ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: true,
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.equal(outcome.derivation.mode, 'auto_derived');
    assert.equal(outcome.derivation.targets[0].kind, 'fs');
    assert.equal(outcome.derivation.targets[0].key, file);
    const art = client.captured[0][0];
    assert.equal(art.before, OPENAPI_BEFORE);
    assert.equal(art.after, OPENAPI_AFTER);
    assert.equal(art.source, AUTO_DERIVE_SOURCE);
    assert.equal(art.type, 'openapi');
    assert.equal(outcome.executed, true);
  });

  it('missing target → before:null + before_unavailable note', async () => {
    const file = specPath('missing.openapi.yaml');
    const client = capturingClient(['ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: true,
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.equal(outcome.derivation.mode, 'auto_derived');
    const art = client.captured[0][0];
    assert.equal(art.before, null);
    assert.equal(art.after, OPENAPI_AFTER);
    assert.ok(outcome.derivation.notes.some((n) => n.note === 'before_unavailable' && n.target === file));
  });

  it('empty file → before:"" (distinct from missing/null)', async () => {
    const file = specPath('empty.openapi.yaml');
    fs.writeFileSync(file, '');
    const client = capturingClient(['ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: true,
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.equal(outcome.derivation.mode, 'auto_derived');
    const art = client.captured[0][0];
    assert.equal(art.before, '');
    assert.notEqual(art.before, null);
    assert.equal(outcome.derivation.notes, undefined);
  });

  it('reader throw → fragment fallback + derive_failed event', async () => {
    const file = specPath('throw.openapi.yaml');
    fs.writeFileSync(file, OPENAPI_BEFORE);
    const events = [];
    const client = capturingClient(['ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: {
        readers: {
          fs: async () => { throw new Error('disk boom'); },
        },
      },
      onEvent: (e) => events.push(e),
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.equal(outcome.derivation.mode, 'fragment_only');
    assert.ok(events.some((e) => e.type === 'derive_failed' && e.cause === 'reader_threw'));
    assert.equal(client.captured.length, 0, 'no preflight pair after derivation failure (fragment fallback)');
  });

  it('default OFF: no derivation field, no extra preflight behaviour', async () => {
    const file = specPath('off.openapi.yaml');
    fs.writeFileSync(file, OPENAPI_BEFORE);
    const client = capturingClient(['ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.equal(outcome.derivation, undefined);
    assert.equal(client.captured.length, 0, 'default OFF does not preflight a write without artifacts');
  });

  it('derivation observation present and not in fingerprint preimage', async () => {
    const file = specPath('preimage.openapi.yaml');
    fs.writeFileSync(file, OPENAPI_BEFORE);
    const client = capturingClient(['ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: true,
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.ok(outcome.derivation);
    assert.equal(outcome.derivation.mode, 'auto_derived');
    const art = client.captured[0][0];
    const withSource = computeCanonicalBundleFingerprint([art], { operation: OP });
    const stripped = { id: art.id, type: art.type, before: art.before, after: art.after };
    const withoutSource = computeCanonicalBundleFingerprint([stripped], { operation: OP });
    assert.equal(withSource, withoutSource);
    assert.equal(outcome.verdict.envelope.fingerprint, withSource);
  });

  it('works WITH autoRecheck: re-preflight re-derives fresh', async () => {
    const file = specPath('recheck.openapi.yaml');
    fs.writeFileSync(file, OPENAPI_BEFORE);
    const client = capturingClient(['BLOCK', 'ALLOW']);
    const { tools } = withCodeRifts({
      tools: [{ name: 'Write', mutationClass: 'mutating', execute: async () => 'ok' }],
      client,
      operation: OP,
      autoDerive: true,
      autoRecheck: {
        maxAttempts: 1,
        applyFix: async () => {
          fs.writeFileSync(file, OPENAPI_AFTER);
          return true;
        },
      },
    });
    const outcome = await tools[0].execute({ path: file, contents: OPENAPI_AFTER });
    assert.equal(client.calls, 2);
    assert.equal(client.captured[0][0].before, OPENAPI_BEFORE);
    assert.equal(client.captured[1][0].before, OPENAPI_AFTER, 'second attempt re-reads current file');
    assert.equal(outcome.derivation.mode, 'auto_derived');
    assert.equal(outcome.verdict.kind, 'ALLOW');
  });
});
