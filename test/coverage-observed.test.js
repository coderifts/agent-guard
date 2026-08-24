'use strict';

/**
 * Coverage attestation (guard 9.5.0) — what the guard MEASURED about tool traffic,
 * not what it assumed at registration time.
 *
 * Half A: governed_calls / tools from execute() through the returned table.
 * Half B: host reportToolDispatch — total/ungoverned OMITTED when never supplied.
 * Classes: UNKNOWN_OUTSIDE_SCOPE | INCOMPLETE_OBSERVED | COMPLETE_OBSERVED.
 * Observation only; not a preimage field; direct guardToolCall stays 9.4.0-shaped.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  withCodeRifts,
  withCodeRiftsLangGraph,
  guardToolCall,
  createCoverageObserver,
  formatCoverageObservedLine,
  freezeCoverageObserved,
  renderFinalAnswerProof,
  buildExecutionProof,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: opts.decision_id || 'dec_cov_1',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint || CONTRACT_FP,
    input_fingerprint: opts.fingerprint || CONTRACT_FP,
    safe_for_agent: decision === 'ALLOW' || decision === 'WARN',
    analysis_complete: true,
    receipt: opts.noReceipt ? undefined : { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function response(execution_action, decision, opts) {
  return { decision, execution_action, decision_result: envelope(execution_action, decision, opts) };
}
function mockClient({ preflight } = {}) {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const resp = preflight ? preflight() : response('CONTINUE', 'ALLOW');
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

const CONTRACT_ARGS = {
  artifacts: [{
    id: 'a',
    type: 'openapi',
    before: 'openapi: 3.0.0\npaths: {}\n',
    after: 'openapi: 3.0.0\npaths: {/x: {get: {}}}\n',
  }],
};
const CONTRACT_FP = computeCanonicalBundleFingerprint(CONTRACT_ARGS.artifacts, { operation: 'merge' });

const STUB_CLIENT = { preflight: async () => ({}) };

function skippedProof(coverageObserved) {
  return buildExecutionProof({
    preflighted: false,
    executionAttempted: true,
    executed: true,
    enforced: false,
    verdict: { kind: 'SKIPPED' },
    result: 'ok',
    coverageObserved,
  });
}

function assertHalfBOmitted(snap) {
  assert.equal('total_calls' in snap, false, 'total_calls must be omitted when Half B is absent');
  assert.equal('ungoverned_calls' in snap, false, 'ungoverned_calls must be omitted when Half B is absent');
  assert.equal('ungoverned_tools' in snap, false, 'ungoverned_tools must be omitted when Half B is absent');
  assert.equal(snap.total_calls, undefined);
  assert.equal(snap.ungoverned_calls, undefined);
}

describe('coverage observer — unit (Half A / Half B / classes)', () => {
  it('governed-only counting: UNKNOWN_OUTSIDE_SCOPE; Half B fields omitted (not zero)', () => {
    const obs = createCoverageObserver();
    obs.setTableNames(['edit_file', 'read_file']);
    obs.recordGoverned('edit_file');
    obs.recordGoverned('edit_file');
    obs.recordGoverned('read_file');
    const snap = obs.snapshot();
    assert.equal(snap.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.equal(snap.governed_calls, 3);
    assert.deepEqual(snap.tools, ['edit_file', 'read_file']);
    assertHalfBOmitted(snap);
    assert.equal(
      formatCoverageObservedLine(snap),
      'governed 3 calls; traffic outside the guarded table not observable from here',
    );
  });

  it('host-reported totals produce INCOMPLETE_OBSERVED with names', () => {
    const obs = createCoverageObserver();
    obs.setTableNames(['edit_file']);
    obs.recordGoverned('edit_file');
    obs.handle.reportToolDispatch({ name: 'edit_file' });
    obs.handle.reportToolDispatch({ name: 'patch_file' });
    obs.handle.reportToolDispatch({ name: 'raw_write' });
    obs.handle.reportToolDispatch({ name: 'shell' });
    const snap = obs.snapshot();
    assert.equal(snap.class, 'INCOMPLETE_OBSERVED');
    assert.equal(snap.governed_calls, 1);
    assert.equal(snap.total_calls, 4);
    assert.equal(snap.ungoverned_calls, 3);
    assert.deepEqual(snap.ungoverned_tools, ['patch_file', 'raw_write', 'shell']);
    assert.equal(
      formatCoverageObservedLine(snap),
      'governed 1/4 dispatched calls; 3 outside the guarded table: patch_file, raw_write, shell',
    );
  });

  it('host-reported empty batch is supplied zero, not omitted; COMPLETE_OBSERVED', () => {
    const obs = createCoverageObserver();
    obs.setTableNames(['edit_file']);
    obs.handle.reportToolDispatchBatch([]);
    const snap = obs.snapshot();
    assert.equal(snap.class, 'COMPLETE_OBSERVED');
    assert.equal(snap.total_calls, 0);
    assert.equal(snap.ungoverned_calls, 0);
    assert.deepEqual(snap.ungoverned_tools, []);
    assert.equal('total_calls' in snap, true);
    assert.equal(
      formatCoverageObservedLine(snap),
      'governed 0/0 dispatched calls; 0 outside the guarded table',
    );
  });

  it('host-reported table-only names → COMPLETE_OBSERVED (names in the table are not ungoverned)', () => {
    const obs = createCoverageObserver();
    obs.setTableNames(['edit_file', 'read_file']);
    obs.recordGoverned('edit_file');
    obs.handle.reportToolDispatchBatch([
      { name: 'edit_file' },
      { name: 'read_file' },
    ]);
    const snap = obs.snapshot();
    assert.equal(snap.class, 'COMPLETE_OBSERVED');
    assert.equal(snap.ungoverned_calls, 0);
    assert.deepEqual(snap.ungoverned_tools, []);
    assert.equal(
      formatCoverageObservedLine(snap),
      'governed 1/2 dispatched calls; 0 outside the guarded table',
    );
  });

  it('singular wording: governed 1 call; traffic outside … not observable', () => {
    const obs = createCoverageObserver();
    obs.recordGoverned('edit_file');
    assert.equal(
      formatCoverageObservedLine(obs.snapshot()),
      'governed 1 call; traffic outside the guarded table not observable from here',
    );
  });

  it('freezeCoverageObserved omits Half B keys when absent; freezes arrays', () => {
    const obs = createCoverageObserver();
    obs.recordGoverned('edit_file');
    const frozen = freezeCoverageObserved(obs.snapshot());
    assert.ok(Object.isFrozen(frozen));
    assert.ok(Object.isFrozen(frozen.tools));
    assertHalfBOmitted(frozen);
    obs.handle.reportToolDispatch({ name: 'patch_file' });
    const frozenB = freezeCoverageObserved(obs.snapshot());
    assert.ok(Object.isFrozen(frozenB.ungoverned_tools));
    assert.equal(frozenB.class, 'INCOMPLETE_OBSERVED');
  });

  it('snapshot() is frozen (run attestation is not caller-writable)', () => {
    const obs = createCoverageObserver();
    obs.recordGoverned('edit_file');
    const snap = obs.snapshot();
    assert.ok(Object.isFrozen(snap));
    assert.throws(() => { snap.governed_calls = 99; });
    assert.equal(obs.snapshot().governed_calls, 1);
  });

  it('invalid reportToolDispatch does NOT mark Half B supplied (not COMPLETE_OBSERVED)', () => {
    const obs = createCoverageObserver();
    obs.setTableNames(['edit_file']);
    obs.recordGoverned('edit_file');
    obs.handle.reportToolDispatch('edit_file');
    obs.handle.reportToolDispatch(null);
    obs.handle.reportToolDispatch({ name: '' });
    obs.handle.reportToolDispatch({ name: '   ' });
    obs.handle.reportToolDispatchBatch(undefined);
    const snap = obs.snapshot();
    assert.equal(snap.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assertHalfBOmitted(snap);
  });
});

describe('coverage observer — proof / T3 lines (all three classes)', () => {
  it('UNKNOWN_OUTSIDE_SCOPE proof line', () => {
    const snap = {
      class: 'UNKNOWN_OUTSIDE_SCOPE',
      governed_calls: 9,
      tools: ['edit_file'],
    };
    const text = renderFinalAnswerProof(skippedProof(snap));
    assert.match(text, /Coverage \(observed\)/);
    assert.match(text, /governed 9 calls; traffic outside the guarded table not observable from here/);
    assert.match(text, /class: UNKNOWN_OUTSIDE_SCOPE/);
    assert.doesNotMatch(text, /COMPLETE_OBSERVED/);
    assert.doesNotMatch(text, /total_calls/);
  });

  it('INCOMPLETE_OBSERVED proof line with names', () => {
    const snap = {
      class: 'INCOMPLETE_OBSERVED',
      governed_calls: 9,
      tools: ['edit_file'],
      total_calls: 12,
      ungoverned_calls: 3,
      ungoverned_tools: ['patch_file', 'raw_write', 'shell'],
    };
    const text = renderFinalAnswerProof(skippedProof(snap));
    assert.match(text, /governed 9\/12 dispatched calls; 3 outside the guarded table: patch_file, raw_write, shell/);
    assert.match(text, /class: INCOMPLETE_OBSERVED/);
  });

  it('COMPLETE_OBSERVED proof line', () => {
    const snap = {
      class: 'COMPLETE_OBSERVED',
      governed_calls: 9,
      tools: ['edit_file'],
      total_calls: 9,
      ungoverned_calls: 0,
      ungoverned_tools: [],
    };
    const text = renderFinalAnswerProof(skippedProof(snap));
    assert.match(text, /governed 9\/9 dispatched calls; 0 outside the guarded table/);
    assert.match(text, /class: COMPLETE_OBSERVED/);
  });

  it('absent coverage_observed: no Coverage section (byte-identical to 9.4.0 render)', () => {
    const text = renderFinalAnswerProof(skippedProof(undefined));
    assert.doesNotMatch(text, /Coverage \(observed\)/);
    assert.doesNotMatch(text, /UNKNOWN_OUTSIDE_SCOPE/);
    assert.match(text, /outside the guarded path are invisible/);
  });
});

describe('withCodeRifts — Half A governed counting', () => {
  it('execute through the table increments governed_calls; class stays UNKNOWN without Half B', async () => {
    const r = withCodeRifts({
      tools: [
        { name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' },
        { name: 'read_file', mutationClass: 'readonly', execute: async () => 'read' },
      ],
      client: mockClient(),
      operation: 'merge',
    });
    assert.equal(typeof r.coverage_observed.snapshot, 'function');
    assert.equal(r.composition_assurance.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.ok(Object.isFrozen(r.composition_assurance));
    const desc = Object.getOwnPropertyDescriptor(r.composition_assurance, 'observed_class');
    assert.equal(typeof desc.get, 'function');

    const before = r.coverage_observed.snapshot();
    assert.equal(before.governed_calls, 0);
    assertHalfBOmitted(before);

    const outcome = await r.tools.find((t) => t.name === 'edit_file').execute(CONTRACT_ARGS);
    await r.tools.find((t) => t.name === 'read_file').execute({ path: 'x' });

    const snap = r.coverage_observed.snapshot();
    assert.equal(snap.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.equal(snap.governed_calls, 2);
    assert.deepEqual(snap.tools, ['edit_file', 'read_file']);
    assertHalfBOmitted(snap);
    assert.equal(r.composition_assurance.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');

    assert.equal(outcome.coverage_observed.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.equal(outcome.proof.coverage_observed.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assertHalfBOmitted(outcome.coverage_observed);
    const text = renderFinalAnswerProof(outcome.proof);
    assert.match(text, /governed 1 call; traffic outside the guarded table not observable from here/);
  });

  it('BLOCK still counts as a governed dispatch', async () => {
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'SHOULD_NOT_RUN' }],
      client: mockClient({ preflight: () => response('STOP', 'BLOCK') }),
      operation: 'merge',
    });
    const outcome = await r.tools[0].execute(CONTRACT_ARGS);
    assert.equal(outcome.executed, false);
    assert.equal(r.coverage_observed.snapshot().governed_calls, 1);
    assert.equal(outcome.coverage_observed.governed_calls, 1);
  });
});

describe('withCodeRifts — Half B host report + claim narrowing', () => {
  it('absent host data is UNKNOWN_OUTSIDE_SCOPE and NOT zero/COMPLETE', async () => {
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
    });
    await r.tools[0].execute(CONTRACT_ARGS);
    const snap = r.coverage_observed.snapshot();
    assert.equal(snap.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.notEqual(snap.class, 'COMPLETE');
    assert.notEqual(snap.class, 'COMPLETE_OBSERVED');
    assertHalfBOmitted(snap);
    assert.equal(r.registry_report.coverage, 'COMPLETE', 'registry COMPLETE is table-truth, not agent-truth');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');
  });

  it('host-reported ungoverned names → INCOMPLETE_OBSERVED; registry stays COMPLETE', async () => {
    const r = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
    });
    r.coverage_observed.reportToolDispatch({ name: 'edit_file' });
    r.coverage_observed.reportToolDispatch({ name: 'patch_file' });
    const outcome = await r.tools[0].execute(CONTRACT_ARGS);
    const snap = r.coverage_observed.snapshot();
    assert.equal(snap.class, 'INCOMPLETE_OBSERVED');
    assert.equal(snap.ungoverned_calls, 1);
    assert.deepEqual(snap.ungoverned_tools, ['patch_file']);
    assert.equal(r.composition_assurance.observed_class, 'INCOMPLETE_OBSERVED');
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(outcome.proof.coverage_observed.class, 'INCOMPLETE_OBSERVED');
    const text = renderFinalAnswerProof(outcome.proof);
    assert.match(text, /governed 1\/2 dispatched calls; 1 outside the guarded table: patch_file/);
  });
});

describe('direct guardToolCall — no observer is 9.4.0-shaped', () => {
  it('omits coverage_observed on outcome and proof', async () => {
    const SKIP = { toolName: 'Read', arguments: { path: 'README.md' } };
    const o = await guardToolCall(SKIP, async () => ({ ok: true }), { client: mockClient() });
    assert.equal('coverage_observed' in o, false);
    assert.equal('coverage_observed' in o.proof, false);
    const text = renderFinalAnswerProof(o.proof);
    assert.doesNotMatch(text, /Coverage \(observed\)/);
  });
});

describe('coverage is not a preimage field', () => {
  it('Half B report does not change change_fp / input_fingerprint', async () => {
    const r1 = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
    });
    const o1 = await r1.tools[0].execute(CONTRACT_ARGS);

    const r2 = withCodeRifts({
      tools: [{ name: 'edit_file', mutationClass: 'mutating', execute: async () => 'edited' }],
      client: mockClient(),
      operation: 'merge',
    });
    r2.coverage_observed.reportToolDispatch({ name: 'patch_file' });
    const o2 = await r2.tools[0].execute(CONTRACT_ARGS);

    assert.equal(o1.proof.binds_to.change_fp, CONTRACT_FP);
    assert.equal(o2.proof.binds_to.change_fp, CONTRACT_FP);
    assert.equal(o1.proof.binds_to.change_fp, o2.proof.binds_to.change_fp);
    assert.equal(o1.coverage_observed.class, 'UNKNOWN_OUTSIDE_SCOPE');
    assert.equal(o2.coverage_observed.class, 'INCOMPLETE_OBSERVED');
  });
});

describe('LangGraph bypass (N-6) — 1 ungoverned call, not COMPLETE', () => {
  it('raw patch_file outside the table is INCOMPLETE_OBSERVED with 1 ungoverned', async () => {
    const r = withCodeRiftsLangGraph({
      tools: [
        {
          name: 'edit_file',
          description: 'Edit a file',
          mutationClass: 'mutating',
          inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          execute: async () => 'edited',
        },
      ],
      client: mockClient(),
      operation: 'merge',
    });

    // 9.4.0-shaped table-truth — this is the honest problem the panel named.
    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.registry_report.claim.inescapable_runtime, true);
    assert.equal(typeof r.coverage_observed.reportToolDispatch, 'function');

    // Host AgentHooks saw the governed table call AND a raw patch_file (the bypass).
    r.coverage_observed.reportToolDispatch({ name: 'edit_file' });
    r.coverage_observed.reportToolDispatch({ name: 'patch_file' });
    const outcome = await r.protected_tools[0].execute(CONTRACT_ARGS);

    const snap = r.coverage_observed.snapshot();
    assert.equal(snap.class, 'INCOMPLETE_OBSERVED');
    assert.equal(snap.governed_calls, 1);
    assert.equal(snap.total_calls, 2);
    assert.equal(snap.ungoverned_calls, 1);
    assert.deepEqual(snap.ungoverned_tools, ['patch_file']);
    assert.equal(r.composition_assurance.observed_class, 'INCOMPLETE_OBSERVED');
    assert.notEqual(r.composition_assurance.observed_class, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');

    const line = formatCoverageObservedLine(snap);
    assert.equal(line, 'governed 1/2 dispatched calls; 1 outside the guarded table: patch_file');

    const text = renderFinalAnswerProof(outcome.proof);
    assert.match(text, /governed 1\/2 dispatched calls; 1 outside the guarded table: patch_file/);
    assert.match(text, /class: INCOMPLETE_OBSERVED/);
    assert.doesNotMatch(text, /class: COMPLETE_OBSERVED/);
  });
});
