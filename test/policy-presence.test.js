'use strict';

/**
 * Layer 3: policy_presence on GuardOutcome.
 * Observation only — omitted when systemPrompt is not supplied (byte-identical).
 * Never a verdict input; never on the proof/preimage.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const {
  guardToolCall,
  CODERIFTS_POLICY,
  POLICY_ABSENT_WARN,
  resetPolicyWarnForTests,
} = require('../dist/cjs/index.js');

const SKIP = { toolName: 'Read', arguments: { path: 'README.md' } };
const okFactory = async () => ({ ok: true });
const client = {
  async authorizeChangeSet() { return { decision: 'ALLOW' }; },
  async preflightChangeSet() { return { decision: 'ALLOW' }; },
  async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
};

describe('policy_presence on GuardOutcome', () => {
  beforeEach(() => resetPolicyWarnForTests());

  it('absent-config is byte-identical: no policy_presence key, proof unchanged', async () => {
    const o = await guardToolCall(SKIP, okFactory, { client });
    assert.equal(o.verdict.kind, 'SKIPPED');
    assert.equal('policy_presence' in o, false);
    assert.equal(o.policy_presence, undefined);
    assert.equal('policy_presence' in o.proof, false);
    assert.equal(JSON.stringify(o).includes('policy_presence'), false);
  });

  it('supplied + marker → detected; silent; not on proof', async () => {
    const hits = [];
    const orig = console.warn;
    console.warn = (m) => { hits.push(String(m)); };
    try {
      const o = await guardToolCall(SKIP, okFactory, { client, systemPrompt: CODERIFTS_POLICY });
      assert.equal(o.policy_presence, 'detected');
      assert.equal('policy_presence' in o.proof, false);
    } finally {
      console.warn = orig;
    }
    assert.equal(hits.length, 0);
  });

  it('supplied + no marker → absent + once-per-process warn', async () => {
    const hits = [];
    const orig = console.warn;
    console.warn = (m) => { hits.push(String(m)); };
    try {
      const a = await guardToolCall(SKIP, okFactory, { client, systemPrompt: 'tools only' });
      const b = await guardToolCall(SKIP, okFactory, { client, systemPrompt: 'still tools only' });
      assert.equal(a.policy_presence, 'absent');
      assert.equal(b.policy_presence, 'absent');
      assert.equal('policy_presence' in a.proof, false);
    } finally {
      console.warn = orig;
    }
    assert.deepEqual(hits, [POLICY_ABSENT_WARN]);
  });
});
