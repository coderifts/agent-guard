'use strict';

/**
 * I-1288f — the DECISION's own next step, rendered from the SIGNED envelope.
 *
 * The field moved inside `decision_result`, so `decision_body_hash` covers it and the
 * receipt signs it. That is what lets deployGate and guardToolCall render it from the
 * envelope they already hold — no second call to the issuer.
 *
 * The two assertions that carry the weight:
 *   1. THE VERDICT NEVER MOVES. Every branchable field is deep-equal to the same run
 *      with no step in the envelope; the step is the only difference.
 *   2. AN UNSIGNED STEP IS NEVER SHOWN. verified_view and unverified receipts are host
 *      CLAIMS about someone else's check; a tampered token authenticates nothing. In
 *      every one of those cases a well-formed step in the input renders nothing.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  deployGate,
  asVerifiedDeployReceiptView,
  guardToolCall,
  readNextAgentStep,
  NEXT_AGENT_ACTIONS,
  NEXT_STEP_NOTE,
} = require('../dist/cjs/index.js');
const { computeBodyHash } = require('../dist/cjs/receipt-binding.js');

const ART = `sha256:${'a'.repeat(64)}`;
const FP = `sha256:${'b'.repeat(64)}`;
const FUTURE = '2099-01-01T00:00:00.000Z';

/**
 * A next_agent_step exactly as the issuer signs it — shape and closed action set from
 * coderifts-app schemas/decision-result.v1.producer.json properties.next_agent_step
 * (required action / reason / resume_condition / then_call; additionalProperties false).
 */
const NEXT_STEP = Object.freeze({
  action: 'revert',
  reason: 'remediate_or_revert',
  resume_condition: 'the removed field is restored or the consumers are migrated',
  then_call: 'preflight_change_set',
});

const enforcing = () => ({ enforcement: 'ENFORCING', bypass_possible: false });
const target = () => ({ environment: 'staging', artifact_id: ART });

function pair(kid = 'nas-k1') {
  const p = crypto.generateKeyPairSync('ed25519');
  return { kid, privateKey: p.privateKey, publicPem: p.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const registry = (s) => ({
  keys: [{ kid: s.kid, public_key_pem: s.publicPem, status: 'active', valid_from: null, retired_at: null }],
});

function envelope(over = {}) {
  const env = {
    spec_version: 'decision-result.v1.1',
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    decision_id: 'dec_nas',
    fingerprint: FP,
    operation: 'deploy',
    target_id: ART,
    environment: 'staging',
    expires_at: FUTURE,
    ...over,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  return env;
}

/** A non-allow decision that still VERIFIES — the reachable case for a deploy gate. */
const blockEnv = (over = {}) => envelope({ decision: 'BLOCK', execution_action: 'STOP', ...over });

function issueV4(signer, env) {
  const bh = computeBodyHash(env);
  const ts = new Date().toISOString();
  const body = {
    v: 4, kid: signer.kid, fp: env.fingerprint, prev: 'null', caller: 'next-step-test',
    ts, reg: '', ir: '', expires_at: env.expires_at, bh,
  };
  const input = `crchain.v1|${body.kid}|${body.fp}|${body.prev}|${body.caller}|${body.ts}|${body.reg}|${body.ir}|${body.expires_at}|${body.bh}`;
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), signer.privateKey);
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
}

const gateWithToken = (signer, env) => deployGate({
  deployTarget: target(),
  token: { token: issueV4(signer, env), decision_result: env, registry: registry(signer) },
  requiredContext: { operation: 'deploy', enforcement: enforcing() },
});

// ── reader ───────────────────────────────────────────────────────────────────
describe('readNextAgentStep — the shape rule', () => {
  it('reads a well-formed step off an envelope', () => {
    assert.deepEqual(readNextAgentStep({ next_agent_step: NEXT_STEP }), NEXT_STEP);
  });

  it('a step without an action is not a step', () => {
    for (const bad of [
      { next_agent_step: { reason: 'x', then_call: 'y' } },
      { next_agent_step: { action: '' } },
      { next_agent_step: 'revert' },
      { next_agent_step: ['revert'] },
      { next_agent_step: null },
      {}, null, undefined, 'not-an-object',
    ]) {
      assert.equal(readNextAgentStep(bad), null, JSON.stringify(bad));
    }
  });

  it('the closed action set and the fixed sentence match the published contract', () => {
    assert.deepEqual([...NEXT_AGENT_ACTIONS],
      ['re_preflight', 'revert', 'migrate', 'escalate', 'await_approval']);
    assert.equal(NEXT_STEP_NOTE,
      "This is the decision's remediation suggestion, not permission; branch on execution_action.");
  });
});

// ── deployGate ───────────────────────────────────────────────────────────────
describe('deployGate — next_step from a TOKEN the guard verified', () => {
  it('a non-allow decision DOES reach this surface: the token verifies, the deploy is refused', () => {
    const s = pair();
    const g = gateWithToken(s, blockEnv({ next_agent_step: NEXT_STEP }));
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.reason, 'decision_not_allow');
    assert.equal(g.verification.mode, 'token');
    assert.equal(g.verification.verify_status, 'VERIFIED_CURRENT');
  });

  it('the step is exposed top-level, verbatim', () => {
    const s = pair();
    const g = gateWithToken(s, blockEnv({ next_agent_step: NEXT_STEP }));
    assert.deepEqual(g.next_step, NEXT_STEP);
    assert.equal(JSON.stringify(g.next_step), JSON.stringify(NEXT_STEP));
  });

  it('THE VERDICT NEVER MOVES: deep-equal to the no-step run but for next_step', () => {
    const s = pair();
    const withStep = gateWithToken(s, blockEnv({ next_agent_step: NEXT_STEP }));
    const without = gateWithToken(s, blockEnv());
    for (const k of ['deploy_allowed', 'state', 'reason', 'enforcement_state', 'inescapable_deploy']) {
      assert.deepEqual(withStep[k], without[k], `${k} moved`);
    }
    assert.deepEqual(withStep.detail, without.detail);
    assert.deepEqual(withStep.residuals, without.residuals);
    const strip = (o) => { const c = { ...o }; delete c.next_step; return c; };
    assert.deepEqual(strip(withStep), strip(without));
  });

  it('an allow-class deploy renders nothing (the issuer sends null)', () => {
    const s = pair();
    const g = gateWithToken(s, envelope({ next_agent_step: null }));
    assert.equal(g.deploy_allowed, true);
    assert.ok(!('next_step' in g));
  });

  it('an absent step is not invented', () => {
    const s = pair();
    const g = gateWithToken(s, blockEnv());
    assert.equal(g.reason, 'decision_not_allow');
    assert.ok(!('next_step' in g));
  });
});

describe('deployGate — an unsigned step is never shown as guidance', () => {
  it('VERIFIED-VIEW mode renders nothing: a host claim is not a signature this guard checked', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: asVerifiedDeployReceiptView({
        currently_authorized: true,
        decision: 'BLOCK',
        execution_action: 'STOP',
        operation: 'deploy',
        bound_environment: 'staging',
        bound_artifact_id: ART,
        // A host that puts a step on a view it computed itself. Nothing here bound it.
        next_agent_step: NEXT_STEP,
      }),
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.verification.mode, 'verified_view');
    assert.ok(!('next_step' in g), 'a host-attributed view must not yield guidance');
  });

  it('UNVERIFIED mode renders nothing', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: {
        currently_authorized: true,
        decision: 'BLOCK',
        execution_action: 'STOP',
        next_agent_step: NEXT_STEP,
      },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.reason, 'unverified_receipt_view');
    assert.ok(!('next_step' in g));
  });

  it('a TAMPERED token renders nothing, though the envelope carries a step', () => {
    const s = pair();
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const good = issueV4(s, env);
    const [b64, sig] = good.split('.');
    const body = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    body.fp = `sha256:${'c'.repeat(64)}`;
    const bad = `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig}`;
    const g = deployGate({
      deployTarget: target(),
      token: { token: bad, decision_result: env, registry: registry(s) },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.ok(!('next_step' in g), 'an unauthenticated token must never yield a step');
  });

  it('an envelope SWAPPED after signing renders nothing (body hash no longer binds)', () => {
    const s = pair();
    const honest = blockEnv();
    const token = issueV4(s, honest);
    const forged = blockEnv({ next_agent_step: { ...NEXT_STEP, action: 're_preflight' } });
    const g = deployGate({
      deployTarget: target(),
      token: { token, decision_result: forged, registry: registry(s) },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.ok(!('next_step' in g));
  });

  it('no receipt and no token: nothing to read from', () => {
    const g = deployGate({
      deployTarget: target(),
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.reason, 'no_receipt');
    assert.ok(!('next_step' in g));
  });
});

// ── guardToolCall ────────────────────────────────────────────────────────────
/**
 * MEASURED: the tool_call envelope CAN carry the field. The app authors
 * next_agent_step on the additive (v4 envelope-bearing) path for EVERY operation,
 * tool_call included — it is gated on envelopeFields, not on operation. So the same
 * rendering applies here, with `verdict.receiptVerified` as the gate: the response
 * arrives over the network, and without a verified receipt nothing in this process
 * checked a signature over the step.
 *
 * Harness mirrors test/client-enforcement.test.js (same mock client, same fixtures).
 */
const { computeArtifactDigest, computeBundleFingerprint } = require('../dist/cjs/index.js');

const ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'openapi: 3.0.0', after: 'openapi: 3.0.1' }];
const TRIGGER = { toolName: 'apply_openapi', arguments: {}, artifacts: ARTIFACTS };
const LOCAL_DIGEST = computeArtifactDigest(ARTIFACTS);
const LOCAL_FP = computeBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });

function toolEnvelope(o = {}) {
  const { __noReceipt, ...rest } = o;
  const env = {
    spec_version: 'decision-result.v1.1',
    decision: 'BLOCK',
    safe_for_agent: false,
    execution_action: 'STOP',
    decision_id: 'dec_ns',
    correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    fingerprint: LOCAL_FP,
    input_fingerprint: LOCAL_FP,
    analysis_complete: true,
    artifact_digest: LOCAL_DIGEST,
    operation: 'tool_call',
    ...rest,
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  if (!__noReceipt) env.receipt = { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' };
  return env;
}

const signedFor = (env) => ({ fp: env.fingerprint, bh: computeBodyHash(env) });

/** verifyOk:false → the guard could not verify the receipt (the gate under test). */
function toolClient(env, { verifyOk = true } = {}) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      return { decision: env.decision, execution_action: env.execution_action, decision_result: env };
    },
    async verifyReceipt() {
      return verifyOk
        ? { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }
        : { valid: false, status: 'INVALID_SIGNATURE' };
    },
  };
}

const runTool = (env, opts = {}) => guardToolCall(
  TRIGGER,
  async () => 'SIDE_EFFECT',
  { client: toolClient(env, opts) },
);

describe('guardToolCall — next_step from a VERIFIED tool_call envelope', () => {
  it('a BLOCK on a verified receipt exposes the step top-level, verbatim', async () => {
    const out = await runTool(toolEnvelope({ next_agent_step: NEXT_STEP }));
    assert.equal(out.executed, false);
    assert.equal(out.verdict.kind, 'BLOCK');
    assert.equal(out.verdict.receiptVerified, true);
    assert.deepEqual(out.next_step, NEXT_STEP);
  });

  it('THE VERDICT NEVER MOVES: deep-equal to the no-step run but for next_step', async () => {
    const withStep = await runTool(toolEnvelope({ next_agent_step: NEXT_STEP }));
    const without = await runTool(toolEnvelope());
    assert.equal(withStep.executed, without.executed);
    assert.equal(withStep.enforced, without.enforced);
    assert.equal(withStep.executionAttempted, without.executionAttempted);
    assert.equal(withStep.verdict.kind, without.verdict.kind);
    assert.equal(withStep.verdict.action, without.verdict.action);
    assert.ok(!('next_step' in without), 'an absent step is not invented');
  });

  it('a receipt that FAILS to verify escalates to UNAVAILABLE — no envelope, no step', async () => {
    const out = await runTool(toolEnvelope({ next_agent_step: NEXT_STEP }), { verifyOk: false });
    assert.equal(out.executed, false, 'still refused');
    assert.equal(out.verdict.kind, 'UNAVAILABLE');
    assert.equal(out.verdict.cause, 'RECEIPT_UNVERIFIED');
    assert.ok(!('envelope' in out.verdict), 'an unverified verdict carries no envelope');
    assert.ok(!('next_step' in out));
  });

  it('THE GATE THAT MATTERS: verifyReceipts:false keeps the BLOCK but renders NO step', async () => {
    // The verdict here IS a BLOCK carrying the envelope — the guard simply never
    // checked a signature over it. This is the one configuration where a step could
    // leak from unauthenticated bytes, and receiptVerified is what stops it.
    const out = await guardToolCall(
      TRIGGER,
      async () => 'SIDE_EFFECT',
      { client: toolClient(toolEnvelope({ next_agent_step: NEXT_STEP })), verifyReceipts: false },
    );
    assert.equal(out.executed, false, 'still refused');
    assert.equal(out.verdict.kind, 'BLOCK');
    assert.ok('envelope' in out.verdict, 'the envelope IS on the verdict');
    assert.deepEqual(out.verdict.envelope.next_agent_step, NEXT_STEP, 'and it DOES carry a step');
    assert.equal(out.verdict.receiptVerified, false);
    assert.ok(!('next_step' in out), 'unverified guidance is not guidance');
  });

  it('an executed ALLOW carries no step (nothing to remediate)', async () => {
    const out = await runTool(toolEnvelope({
      decision: 'ALLOW', safe_for_agent: true, execution_action: 'CONTINUE', next_agent_step: null,
    }));
    assert.equal(out.executed, true);
    assert.ok(!('next_step' in out));
  });

  it('a REQUEST_APPROVAL refusal renders its step too', async () => {
    const step = { ...NEXT_STEP, action: 'await_approval', then_call: null };
    const out = await runTool(toolEnvelope({
      decision: 'REQUIRE_APPROVAL', execution_action: 'REQUEST_APPROVAL', next_agent_step: step,
    }));
    assert.equal(out.executed, false);
    assert.equal(out.verdict.kind, 'APPROVAL');
    assert.deepEqual(out.next_step, step);
  });
});
