'use strict';

/**
 * 1356 — the host is the first gate, and it must be closed by default.
 *
 * WHAT WAS ALREADY CLOSED, measured before the flip and pinned here so nobody re-credits it to
 * this change: a CONTRACT-triggering call with no receipt / an unknown key / a STOP decision was
 * already refused by default (guard.ts:981 `enforceable = receiptVerified && …`, :813, :854).
 *
 * WHAT WAS OPEN: all three need the DETECTOR to have triggered. A mutating call it does not
 * recognise took the SKIPPED path (guard.ts:600) and EXECUTED — measured:
 *   Write deploy.sh {content:'rm -rf /'} → SKIPPED, executed:true, preflighted:false.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  guardToolCall, computeBodyHash, computeCanonicalBundleFingerprint,
  decideUnguardedMutation, ADVISORY_ENV_VAR,
} = require('../dist/cjs/index.js');

const ARTS = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
const FP = computeCanonicalBundleFingerprint(ARTS, { operation: 'tool_call' });

function envelope() {
  return {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', execution_action: 'CONTINUE',
    decision_id: 'd', correlation_id: 'c', evaluated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900000).toISOString(),
    fingerprint: FP, input_fingerprint: FP,
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function mockClient() {
  let last = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet(r); },
    async preflightChangeSet() { last = envelope(); return { decision: 'ALLOW', decision_result: last }; },
    async verifyReceipt() {
      return { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: last.fingerprint, bh: computeBodyHash(last) } };
    },
  };
}

const MUTATING = { toolName: 'Write', arguments: { file_path: 'deploy.sh', content: 'rm -rf /' } };
const READ = { toolName: 'Read', arguments: { path: 'README.md' } };
const CONTRACT = { toolName: 'Edit', arguments: {}, artifacts: ARTS };
const ok = async () => ({ ok: true });

/** Captures console.warn so "loud" can be asserted rather than assumed. */
async function run(call, config = {}) {
  const warnings = [];
  const original = console.warn;
  console.warn = (m) => warnings.push(String(m));
  try {
    const outcome = await guardToolCall(call, ok, { client: mockClient(), ...config });
    return { outcome, warnings };
  } finally { console.warn = original; }
}

describe('1356 — the four bite-proofs', () => {
  it('default config + mutating tool + no receipt → BLOCKED', async () => {
    const { outcome } = await run(MUTATING);
    assert.equal(outcome.verdict.cause, 'UNGUARDED_MUTATION');
    assert.equal(outcome.executed, false);
    assert.equal(outcome.executionAttempted, false, 'the factory must never be reached');
  });

  it(`+ ${ADVISORY_ENV_VAR}=1 → proceeds WITH a logged warning, never silent`, async () => {
    process.env[ADVISORY_ENV_VAR] = '1';
    try {
      const { outcome, warnings } = await run(MUTATING);
      assert.equal(outcome.verdict.kind, 'SKIPPED');
      assert.equal(outcome.executed, true);
      assert.equal(warnings.length, 1, 'advisory execution with no warning is the failure mode');
      assert.match(warnings[0], /ADVISORY/);
      assert.match(warnings[0], new RegExp(ADVISORY_ENV_VAR), 'the warning must name what to unset');
    } finally { delete process.env[ADVISORY_ENV_VAR]; }
  });

  it('a valid keyed CONTINUE receipt → proceeds, enforced', async () => {
    const { outcome, warnings } = await run(CONTRACT);
    assert.equal(outcome.verdict.kind, 'ALLOW');
    assert.equal(outcome.executed, true);
    assert.equal(outcome.enforced, true);
    assert.equal(warnings.length, 0, 'the guarded path must not warn');
  });

  it('a read-only tool → unaffected', async () => {
    const { outcome, warnings } = await run(READ);
    assert.equal(outcome.verdict.kind, 'SKIPPED');
    assert.equal(outcome.executed, true);
    assert.equal(warnings.length, 0);
  });
});

describe('1356 — the opt-out is an option, not a bypass', () => {
  const ENV_ON = { [ADVISORY_ENV_VAR]: '1' };

  it('an EXPLICIT fail-closed is NOT overridable by the environment', () => {
    // Anyone who can set an env var would otherwise hold an escape hatch over a decision the
    // host wrote down. That is a bypass, not an opt-out.
    const d = decideUnguardedMutation(true, 'fail-closed', ENV_ON);
    assert.equal(d.stop, true);
  });

  it('config advisory warns too, and says the choice came from config', () => {
    const d = decideUnguardedMutation(true, 'advisory', {});
    assert.equal(d.stop, false);
    assert.equal(d.source, 'config');
    assert.match(d.warn, /ADVISORY/);
  });

  it('NON-VACUITY: the env var is matched exactly, not merely present', () => {
    // A classifier that answered "advisory" to any value would pass every test above.
    for (const v of ['0', 'false', 'no', 'off', '', 'maybe']) {
      assert.equal(decideUnguardedMutation(true, undefined, { [ADVISORY_ENV_VAR]: v }).stop, true,
        `${ADVISORY_ENV_VAR}=${JSON.stringify(v)} must not disable the guard`);
    }
    for (const v of ['1', 'true', 'YES', 'On']) {
      assert.equal(decideUnguardedMutation(true, undefined, { [ADVISORY_ENV_VAR]: v }).stop, false, v);
    }
  });

  it('NON-VACUITY: it is gated on MUTATION, not on "was it preflighted"', () => {
    // A predicate that always said stop would pass the first bite-proof and break every read.
    assert.equal(decideUnguardedMutation(false, undefined, ENV_ON).stop, false);
    assert.equal(decideUnguardedMutation(false, undefined, {}).stop, false);
    assert.equal(decideUnguardedMutation(false, undefined, {}).warn, undefined,
      'a read must not warn — a warning on every read gets the whole thing muted');
  });

  it('the refusal says what to do about it, both ways', () => {
    const d = decideUnguardedMutation(true, undefined, {});
    assert.match(d.detail, new RegExp(ADVISORY_ENV_VAR), 'name the opt-out');
    assert.match(d.detail, /preflight/, 'name the way to proceed WITH a receipt');
  });
});

describe('1356 — what this change does NOT close', () => {
  it('RESIDUAL NARROWED (1375): a bare descriptor with no declared class still slips', async () => {
    // This test asked to be updated when the residual closed, and half of it has. What closed is
    // the REGISTRY path (see registry-shell-boundary.test.js): guardToolRegistry resolves Bash to
    // mutating_shell and now stamps it on the descriptor, so every raw-shell call through the
    // supported wrapper is refused by default.
    //
    // WHAT REMAINS, and it is narrower than before: a caller who builds a ToolCallDescriptor BY
    // HAND and declares nothing. isMutatingCall still reads contents/content/new_string/old_string/
    // patch/edits, and `command` is deliberately NOT among them — widening it would silently move
    // the conditional-write gate that shares the predicate (guard.ts:495), and no string test can
    // survive `sh -c`, an alias or a wrapper script anyway. Such a caller declares the class
    // themselves (descriptor.mutationClass) — the assertion below is the un-declared case.
    const { outcome } = await run({ toolName: 'Bash', arguments: { command: 'kubectl apply -f prod.yaml' } });
    assert.equal(outcome.executed, true,
      'undeclared bare descriptor: the host said nothing about this capability');
  });

  it('...and declaring the class on that same bare descriptor closes it', async () => {
    // The escape from the residual is a declaration, not a cleverer parser.
    const { outcome } = await run({
      toolName: 'Bash',
      arguments: { command: 'kubectl apply -f prod.yaml' },
      mutationClass: 'mutating_shell',
    });
    assert.equal(outcome.executed, false);
    assert.equal(outcome.verdict.cause, 'UNGUARDED_MUTATION');
  });

  it('the three contract-path refusals were already the default, and still are', async () => {
    // Pinned so this change is never credited with closing them.
    const noReceiptClient = {
      async authorizeChangeSet(r) { return this.preflightChangeSet(r); },
      async preflightChangeSet() {
        const e = envelope(); delete e.receipt;
        return { decision: 'ALLOW', decision_result: e };
      },
      async verifyReceipt() { return { valid: true, status: 'VERIFIED_CURRENT' }; },
    };
    const o = await guardToolCall(CONTRACT, ok, { client: noReceiptClient });
    assert.equal(o.executed, false);
    assert.equal(o.verdict.cause, 'RECEIPT_MISSING', 'guard.ts:981/1067, not 1356');
  });
});
