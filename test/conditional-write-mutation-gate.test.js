'use strict';

/**
 * The conditional-write policy gates on MUTATION, not on write-style.
 *
 * Regression: an ordinary Edit carries artifacts[] with non-empty before AND after (the default
 * tool-registry binder lifts old_string/new_string into exactly that shape). isWriteStyleCall
 * therefore returned false, requireConditionalWrite:true never fired, and the call executed
 * enforced with conditional_write:'not_reported'. Passing both sides of a change is evidence about
 * CONTENT; it is not evidence that the commit was ATOMIC. Those are different facts and one used
 * to suppress the check for the other.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  isWriteStyleCall,
  isMutatingCall,
  buildConditionalWriteBasis,
  conditionalWriteResidual,
  assertEnforcedReceiptInvariant,
  guardToolCall,
  computeBodyHash,
  computeArtifactDigest,
  computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');

// The exact shape the default binder produces for a str_replace-style Edit.
const ARTIFACTS = [{
  id: 'openapi:openapi.yaml',
  type: 'openapi',
  before: 'required: [id]',
  after: 'required: [id, tenant]',
}];
const EDIT = {
  toolName: 'apply_openapi',
  arguments: {
    path: 'openapi.yaml',
    old_string: 'required: [id]',
    new_string: 'required: [id, tenant]',
  },
  filesTouched: ['openapi.yaml'],
  artifacts: ARTIFACTS,
};

describe('isMutatingCall — artifact-independent', () => {
  it('an Edit carrying both sides is NOT write-style but IS mutating', () => {
    assert.equal(isWriteStyleCall(EDIT), false, 'precondition: the old predicate says not-write-style');
    assert.equal(isMutatingCall(EDIT), true);
  });

  it('a non-empty artifact `after` alone is mutation evidence (no path, no content args)', () => {
    assert.equal(isMutatingCall({ toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS }), true);
  });

  it('edits[] is mutation evidence', () => {
    assert.equal(isMutatingCall({
      toolName: 'MultiEdit',
      arguments: { path: 'openapi.yaml', edits: [{ old_string: 'a', new_string: 'b' }] },
    }), true);
  });

  it('a path alone is NOT mutation evidence — a read names a path too', () => {
    assert.equal(isMutatingCall({ toolName: 'Read', arguments: { path: 'openapi.yaml' } }), false);
    assert.equal(isMutatingCall({ toolName: 'Read', arguments: {}, filesTouched: ['openapi.yaml'] }), false);
  });

  it('a write-style call remains mutating (the old surface is a subset, not a sibling)', () => {
    const WRITE = { toolName: 'Write', arguments: { path: 'openapi.yaml', contents: 'x: 1\n' } };
    assert.equal(isWriteStyleCall(WRITE), true);
    assert.equal(isMutatingCall(WRITE), true);
  });

  it('an artifact with an empty after is not, by itself, mutation evidence', () => {
    assert.equal(isMutatingCall({ arguments: {}, artifacts: [{ id: 'a', before: 'x', after: '' }] }), false);
  });
});

describe('buildConditionalWriteBasis — gates on mutating', () => {
  it('mutating + policy + not_reported → CONDITIONAL_WRITE_REQUIRED even though writeStyle is false', () => {
    const { basis, blockCause } = buildConditionalWriteBasis({
      writeStyle: false,
      mutating: true,
      requireConditionalWrite: true,
      ctx: {},
    });
    assert.equal(basis.write_style, false);
    assert.equal(basis.mutating, true);
    assert.equal(basis.conditional_write, 'not_reported');
    assert.equal(blockCause, 'CONDITIONAL_WRITE_REQUIRED');
  });

  it('mutating + policy + host reports true → no block, token carried', () => {
    const { basis, blockCause } = buildConditionalWriteBasis({
      writeStyle: false,
      mutating: true,
      requireConditionalWrite: true,
      ctx: { conditional_write: true, conditioned_on_token: 'blob:deadbeef' },
    });
    assert.equal(blockCause, undefined);
    assert.equal(basis.conditioned_on_token, 'blob:deadbeef');
  });

  it('non-mutating + policy → no demand (a read is not a commit)', () => {
    const { blockCause } = buildConditionalWriteBasis({
      writeStyle: false, mutating: false, requireConditionalWrite: true, ctx: {},
    });
    assert.equal(blockCause, undefined);
  });

  it('mutating omitted → falls back to writeStyle (direct callers of the pure export unchanged)', () => {
    const legacy = buildConditionalWriteBasis({ writeStyle: false, requireConditionalWrite: true, ctx: {} });
    assert.equal(legacy.blockCause, undefined);
    assert.equal(legacy.basis.mutating, false);
    const legacyWrite = buildConditionalWriteBasis({ writeStyle: true, requireConditionalWrite: true, ctx: {} });
    assert.equal(legacyWrite.blockCause, 'CONDITIONAL_WRITE_REQUIRED');
    assert.equal(legacyWrite.basis.mutating, true);
  });
});

describe('conditionalWriteResidual — follows the same fact', () => {
  it('names the residual for a mutating non-write-style call', () => {
    assert.equal(
      conditionalWriteResidual({
        requireConditionalWrite: true, writeStyle: false, mutating: true, conditionalWrite: 'not_reported',
      }),
      'composition_unconditional_write_under_policy',
    );
  });
  it('no residual when the host reported true', () => {
    assert.equal(
      conditionalWriteResidual({
        requireConditionalWrite: true, writeStyle: false, mutating: true, conditionalWrite: true,
      }),
      null,
    );
  });
});

describe('assertEnforcedReceiptInvariant — mutating closes the same hole', () => {
  it('throws on enforced:true for a mutating call without conditional_write:true', () => {
    assert.throws(
      () => assertEnforcedReceiptInvariant({
        enforced: true, preflighted: true, receiptVerified: true,
        requireConditionalWrite: true, writeStyle: false, mutating: true,
        conditionalWrite: 'not_reported',
      }),
      /conditional_write:true under requireConditionalWrite/,
    );
  });
  it('does not throw when the host reported true', () => {
    assert.doesNotThrow(() => assertEnforcedReceiptInvariant({
      enforced: true, preflighted: true, receiptVerified: true,
      requireConditionalWrite: true, writeStyle: false, mutating: true, conditionalWrite: true,
    }));
  });
});

// ── end-to-end through guardToolCall ──────────────────────────────────────────────────────────
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);
const LOCAL_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });
function envelope() {
  return {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'dec_1', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: LOCAL_FP, input_fingerprint: LOCAL_FP, analysis_complete: true,
    artifact_digest: LOCAL_DIGEST, operation: 'tool_call',
    receipt: { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' },
  };
}
function client(env) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet(r); },
    async preflightChangeSet() {
      return { decision: env.decision, execution_action: env.execution_action, decision_result: env };
    },
    async verifyReceipt() {
      return { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: env.fingerprint, bh: computeBodyHash(env) } };
    },
  };
}

describe('guardToolCall — an ordinary Edit is subject to requireConditionalWrite', () => {
  it('REGRESSION: Edit with both-side artifacts + policy on + host silent → blocked, not executed', async () => {
    let executed = false;
    const out = await guardToolCall(
      EDIT,
      async () => { executed = true; return 'MUTATION_APPLIED'; },
      { client: client(envelope()), requireConditionalWrite: true },
      {},
    );
    assert.equal(executed, false, 'the side effect must not run');
    assert.equal(out.executed, false);
    assert.equal(out.enforced, false);
    assert.equal(out.verdict.cause, 'CONDITIONAL_WRITE_REQUIRED');
    assert.equal(out.conditional_write.mutating, true);
    assert.equal(out.conditional_write.write_style, false);
  });

  it('same Edit + policy on + host reports conditional_write:true → executes enforced', async () => {
    let executed = false;
    const out = await guardToolCall(
      EDIT,
      async () => { executed = true; return 'MUTATION_APPLIED'; },
      { client: client(envelope()), requireConditionalWrite: true },
      { conditional_write: true, conditioned_on_token: 'blob:deadbeef' },
    );
    assert.equal(executed, true);
    assert.equal(out.executed, true);
    assert.equal(out.enforced, true);
    assert.equal(out.conditional_write.conditional_write, true);
    assert.equal(out.conditional_write.conditioned_on_token, 'blob:deadbeef');
  });

  it('CONTROL: policy OFF → the same Edit executes and the basis still reports mutating:true', async () => {
    let executed = false;
    const out = await guardToolCall(
      EDIT,
      async () => { executed = true; return 'MUTATION_APPLIED'; },
      { client: client(envelope()), requireConditionalWrite: false },
      {},
    );
    assert.equal(executed, true);
    assert.equal(out.executed, true);
    assert.equal(out.conditional_write.mutating, true);
    assert.equal(out.conditional_write.require_conditional_write, false);
  });
});
