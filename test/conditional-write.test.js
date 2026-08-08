'use strict';

/**
 * ID781 — conditional-write surface (reporting only).
 * token collect→basis; requireConditionalWrite policy; not_reported default; must-fail fixture.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  buildConditionalWriteBasis,
  tokensEqual,
  conditionalWriteResidual,
  RESIDUAL_UNCONDITIONAL_WRITE,
  assertEnforcedReceiptInvariant,
  guardToolCall,
} = require('../dist/cjs/index.js');

// Write-style: path + new content, no both-side artifacts (see isWriteStyleCall).
const WRITE_CALL = {
  toolName: 'Write',
  arguments: { path: 'openapi.yaml', contents: 'x: 1\n' },
  filesTouched: ['openapi.yaml'],
};

function mockClientAllow() {
  return {
    preflight: async () => ({
      decision: 'ALLOW',
      execution_action: 'CONTINUE',
      safe_for_agent: true,
      analysis_complete: true,
      decision_id: 'dec_cw_1',
      fingerprint: 'fp_cw_1',
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      evaluated_at: new Date().toISOString(),
      receipt: { token: 'tok_cw_test_aaaaaaaaaaaaaaaa' },
    }),
    verifyReceipt: async () => ({
      status: 'VERIFIED_CURRENT',
      currently_authorized: true,
    }),
  };
}

describe('tokensEqual (equality only)', () => {
  it('equal strings match; null/undefined never equal', () => {
    assert.equal(tokensEqual('abc', 'abc'), true);
    assert.equal(tokensEqual('abc', 'abd'), false);
    assert.equal(tokensEqual(null, 'abc'), false);
    assert.equal(tokensEqual(undefined, undefined), false);
  });
});

describe('buildConditionalWriteBasis', () => {
  it('defaults to not_reported when host silent', () => {
    const { basis, blockCause } = buildConditionalWriteBasis({
      writeStyle: true,
      requireConditionalWrite: false,
      ctx: {},
    });
    assert.equal(basis.conditional_write, 'not_reported');
    assert.equal(basis.require_conditional_write, false);
    assert.equal(blockCause, undefined);
  });

  it('carries conditioned_on_token from versioned_content when true', () => {
    const { basis } = buildConditionalWriteBasis({
      writeStyle: true,
      requireConditionalWrite: false,
      ctx: {
        conditional_write: true,
        versioned_content: { content: 'x', version_token: 'blob:deadbeef' },
      },
    });
    assert.equal(basis.conditional_write, true);
    assert.equal(basis.conditioned_on_token, 'blob:deadbeef');
  });

  it('policy on + not_reported → CONDITIONAL_WRITE_REQUIRED', () => {
    const { basis, blockCause } = buildConditionalWriteBasis({
      writeStyle: true,
      requireConditionalWrite: true,
      ctx: { conditional_write: 'not_reported' },
    });
    assert.equal(basis.conditional_write, 'not_reported');
    assert.equal(blockCause, 'CONDITIONAL_WRITE_REQUIRED');
  });

  it('policy on + false → CONDITIONAL_WRITE_REQUIRED', () => {
    const { blockCause } = buildConditionalWriteBasis({
      writeStyle: true,
      requireConditionalWrite: true,
      ctx: { conditional_write: false },
    });
    assert.equal(blockCause, 'CONDITIONAL_WRITE_REQUIRED');
  });

  it('policy on + true → eligible (no block)', () => {
    const { blockCause } = buildConditionalWriteBasis({
      writeStyle: true,
      requireConditionalWrite: true,
      ctx: { conditional_write: true, conditioned_on_token: 'etag:1' },
    });
    assert.equal(blockCause, undefined);
  });

  it('policy off + not_reported → no block (identical permission to today)', () => {
    const { blockCause } = buildConditionalWriteBasis({
      writeStyle: true,
      requireConditionalWrite: false,
      ctx: {},
    });
    assert.equal(blockCause, undefined);
  });
});

describe('assertEnforcedReceiptInvariant + conditional write', () => {
  it('enforced:true without conditional_write:true under policy throws', () => {
    assert.throws(
      () => assertEnforcedReceiptInvariant({
        enforced: true,
        preflighted: true,
        receiptVerified: true,
        requireConditionalWrite: true,
        writeStyle: true,
        conditionalWrite: 'not_reported',
      }),
      /conditional_write:true under requireConditionalWrite/,
    );
  });

  it('enforced:true with conditional_write:true under policy ok', () => {
    assert.doesNotThrow(() => assertEnforcedReceiptInvariant({
      enforced: true,
      preflighted: true,
      receiptVerified: true,
      requireConditionalWrite: true,
      writeStyle: true,
      conditionalWrite: true,
    }));
  });
});

describe('guardToolCall wire — conditional_write basis', () => {
  it('surface: token carried collect→basis; default not_reported', async () => {
    const client = mockClientAllow();
    // Non-contract skip path still attaches basis
    const o = await guardToolCall(
      { toolName: 'Read', arguments: { path: 'README.md' }, nonContract: true },
      async () => 'ok',
      { client, requireExplicitArtifacts: true },
    );
    assert.ok(o.conditional_write);
    assert.equal(o.conditional_write.conditional_write, 'not_reported');
    assert.equal(o.conditional_write.require_conditional_write, false);
  });

  it('token on context appears on basis when conditional_write true', async () => {
    const client = mockClientAllow();
    const o = await guardToolCall(
      { toolName: 'Read', arguments: { path: 'README.md' }, nonContract: true },
      async () => 'ok',
      { client, requireExplicitArtifacts: true },
      {
        wiring: 'NOT_CONFIGURED',
        conditional_write: true,
        conditioned_on_token: 'git:abc123',
      },
    );
    assert.equal(o.conditional_write.conditional_write, true);
    assert.equal(o.conditional_write.conditioned_on_token, 'git:abc123');
  });

  it('policy: write + requireConditionalWrite + not_reported → no enforced:true', async () => {
    const client = mockClientAllow();
    // Force skip detect? Use write-style with artifacts so preflight path runs.
    // Without server mock binding, use observeOnly false and failPolicy closed —
    // or simpler: unit basis already tested; wire via requireConditionalWrite early gate.
    const o = await guardToolCall(
      WRITE_CALL,
      async () => {
        throw new Error('factory must not run when policy blocks');
      },
      {
        client,
        requireConditionalWrite: true,
        // detector will trigger on openapi path; preflight may still run after policy gate
      },
      { wiring: 'NOT_CONFIGURED', conditional_write: 'not_reported' },
    );
    assert.equal(o.executed, false);
    assert.equal(o.enforced, false);
    assert.equal(o.conditional_write.conditional_write, 'not_reported');
    assert.equal(o.conditional_write.require_conditional_write, true);
    if (o.verdict.kind === 'UNAVAILABLE') {
      assert.equal(o.verdict.cause, 'CONDITIONAL_WRITE_REQUIRED');
    }
  });

  it('policy: conditional_write true → not blocked by CONDITIONAL_WRITE_REQUIRED', async () => {
    const client = mockClientAllow();
    // May still block on receipt/MISSING_ARTIFACT if content paths differ — assert cause is not CW_REQUIRED
    const o = await guardToolCall(
      WRITE_CALL,
      async () => 'wrote',
      { client, requireConditionalWrite: true, observeOnly: true },
      {
        wiring: 'NOT_CONFIGURED',
        conditional_write: true,
        conditioned_on_token: 'etag:v1',
      },
    );
    assert.equal(o.conditional_write.conditional_write, true);
    assert.notEqual(
      o.verdict.kind === 'UNAVAILABLE' ? o.verdict.cause : null,
      'CONDITIONAL_WRITE_REQUIRED',
    );
  });

  it('policy off → behavior identical permission-wise (not_reported does not block)', async () => {
    const client = mockClientAllow();
    const o = await guardToolCall(
      WRITE_CALL,
      async () => 'wrote',
      { client, requireConditionalWrite: false, observeOnly: true },
      { wiring: 'NOT_CONFIGURED' },
    );
    assert.equal(o.conditional_write.conditional_write, 'not_reported');
    assert.equal(o.conditional_write.require_conditional_write, false);
    // observeOnly executes without enforced — same as pre-change when policy off
    if (o.executionAttempted) {
      assert.equal(o.enforced, false);
    }
  });

  it('replay: conditional_write survives unchanged on outcome object', async () => {
    const client = mockClientAllow();
    const o = await guardToolCall(
      { toolName: 'Read', arguments: {}, nonContract: true },
      async () => 1,
      { client, requireExplicitArtifacts: true },
      {
        wiring: 'NOT_CONFIGURED',
        conditional_write: false,
      },
    );
    const snap = JSON.stringify(o.conditional_write);
    // "Replay" = re-read the same outcome (host stores and reloads)
    const reloaded = JSON.parse(snap);
    assert.deepEqual(reloaded, o.conditional_write);
    assert.equal(reloaded.conditional_write, false);
  });

  it('MUST-FAIL: enforced:true on unconditional write under policy is forbidden', () => {
    // Encodes pre-change bug: policy on, host not_reported, but enforced true.
    // Guard that cannot fail is broken.
    assert.throws(
      () => assertEnforcedReceiptInvariant({
        enforced: true,
        preflighted: true,
        receiptVerified: true,
        requireConditionalWrite: true,
        writeStyle: true,
        conditionalWrite: 'not_reported',
      }),
      /conditional_write:true under requireConditionalWrite/,
    );
  });
});

describe('conditionalWriteResidual', () => {
  it('names residual under policy without true report', () => {
    assert.equal(
      conditionalWriteResidual({
        requireConditionalWrite: true,
        writeStyle: true,
        conditionalWrite: 'not_reported',
      }),
      RESIDUAL_UNCONDITIONAL_WRITE,
    );
    assert.equal(
      conditionalWriteResidual({
        requireConditionalWrite: true,
        writeStyle: true,
        conditionalWrite: true,
      }),
      null,
    );
  });
});
