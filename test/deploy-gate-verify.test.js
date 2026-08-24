'use strict';

/**
 * deployGate 9.0.0 — TOKEN + VERIFIED-VIEW. Bare currently_authorized is not proof
 * (P0 / external audit 2026-08-24, the other half of CLI 4.4.0).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  deployGate,
  asVerifiedDeployReceiptView,
  DEPLOY_RECEIPT_VIEW_SPEC,
} = require('../dist/cjs/index.js');
const { computeBodyHash } = require('../dist/cjs/receipt-binding.js');

const ART = `sha256:${'a'.repeat(64)}`;
const FP = `sha256:${'b'.repeat(64)}`;
const FUTURE = '2099-01-01T00:00:00.000Z';
const PAST = '2020-01-01T00:00:00.000Z';

function enforcing() {
  return { enforcement: 'ENFORCING', bypass_possible: false };
}

function target() {
  return { environment: 'staging', artifact_id: ART };
}

function pair(kid = 'test-k1') {
  const p = crypto.generateKeyPairSync('ed25519');
  return {
    kid,
    privateKey: p.privateKey,
    publicPem: p.publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function registry(signer, extra = []) {
  return {
    keys: [
      {
        kid: signer.kid,
        public_key_pem: signer.publicPem,
        status: 'active',
        valid_from: null,
        retired_at: null,
      },
      ...extra,
    ],
  };
}

function envelope(over = {}) {
  const env = {
    spec_version: 'decision-result.v1.1',
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    decision_id: 'dec_dg',
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

function issueV4(signer, env) {
  const bh = computeBodyHash(env);
  const ts = new Date().toISOString();
  const body = {
    v: 4,
    kid: signer.kid,
    fp: env.fingerprint,
    prev: 'null',
    caller: 'deploy-gate-test',
    ts,
    reg: '',
    ir: '',
    expires_at: env.expires_at,
    bh,
  };
  const input = `crchain.v1|${body.kid}|${body.fp}|${body.prev}|${body.caller}|${body.ts}|${body.reg}|${body.ir}|${body.expires_at}|${body.bh}`;
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), signer.privateKey);
  const token = `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
  return { token, bh, body };
}

function tamper(token) {
  const [b64, sig] = token.split('.');
  const body = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  body.fp = `sha256:${'c'.repeat(64)}`;
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig}`;
}

function viewFields(over = {}) {
  return asVerifiedDeployReceiptView({
    currently_authorized: true,
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    operation: 'deploy',
    bound_environment: 'staging',
    bound_artifact_id: ART,
    ...over,
  });
}

describe('deployGate — unverified_receipt_view (forged bare boolean)', () => {
  it('AUDITOR VECTOR: currently_authorized:true + no provenance + no token → unverified_receipt_view', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: {
        currently_authorized: true,
        decision: 'ALLOW',
        execution_action: 'CONTINUE',
        operation: 'deploy',
        bound_environment: 'staging',
        bound_artifact_id: ART,
      },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.reason, 'unverified_receipt_view');
    assert.notEqual(g.reason, 'receipt_not_authorized');
    assert.equal(g.verification.mode, 'unverified');
    assert.equal(g.inescapable_deploy, false);
  });

  it('currently_authorized:false without provenance is still unverified_receipt_view (not receipt_not_authorized)', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: { currently_authorized: false, decision: 'ALLOW', operation: 'deploy' },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.reason, 'unverified_receipt_view');
  });
});

describe('deployGate — VERIFIED-VIEW mode', () => {
  it('view_spec + verified:true + matching bounds → allow', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: viewFields(),
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, true);
    assert.equal(g.reason, 'allow_current_deploy');
    assert.equal(g.verification.mode, 'verified_view');
    assert.equal(g.verification.verify_status, 'VERIFIED_CURRENT');
  });

  it('verified:true without view_spec → unverified_receipt_view', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: {
        currently_authorized: true,
        verified: true,
        verify_status: 'VERIFIED_CURRENT',
        decision: 'ALLOW',
        execution_action: 'CONTINUE',
        operation: 'deploy',
        bound_environment: 'staging',
        bound_artifact_id: ART,
      },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.reason, 'unverified_receipt_view');
  });

  it('wrong view_spec string → unverified_receipt_view', () => {
    const g = deployGate({
      deployTarget: target(),
      receipt: {
        ...viewFields(),
        view_spec: 'not-the-guard-marker',
      },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.reason, 'unverified_receipt_view');
  });

  it('asVerifiedDeployReceiptView stamps the guard marker', () => {
    const v = asVerifiedDeployReceiptView({
      currently_authorized: true, decision: 'ALLOW', operation: 'deploy',
    });
    assert.equal(v.view_spec, DEPLOY_RECEIPT_VIEW_SPEC);
    assert.equal(v.verified, true);
  });
});

describe('deployGate — TOKEN mode', () => {
  const signer = pair('tok-k1');
  const keys = registry(signer);

  it('valid token + envelope + matching context → allow', () => {
    const env = envelope();
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      token: { token, decision_result: env, registry: keys },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, true, g.reason);
    assert.equal(g.reason, 'allow_current_deploy');
    assert.equal(g.verification.mode, 'token');
    assert.equal(g.verification.verify_status, 'VERIFIED_CURRENT');
  });

  it('pinnedKeyPem air-gap → allow', () => {
    const env = envelope();
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      token: { token, decision_result: env, pinnedKeyPem: signer.publicPem },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, true);
    assert.equal(g.verification.mode, 'token');
  });

  it('TB-04: merge receipt token on deploy → operation_mismatch', () => {
    const env = envelope({ operation: 'merge' });
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      token: { token, decision_result: env, registry: keys },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.reason, 'operation_mismatch');
    assert.equal(g.verification.mode, 'token');
    assert.equal(g.verification.verify_status, 'VERIFIED_CURRENT');
  });

  it('tampered payload → invalid_signature', () => {
    const env = envelope();
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      token: { token: tamper(token), decision_result: env, registry: keys },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.reason, 'invalid_signature');
    assert.equal(g.verification.verify_status, 'INVALID_SIGNATURE');
  });

  it('expired v4 → expired / VERIFIED_EXPIRED', () => {
    const env = envelope({ expires_at: PAST });
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      token: { token, decision_result: env, registry: keys },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.reason, 'expired');
    assert.equal(g.verification.verify_status, 'VERIFIED_EXPIRED');
  });

  it('retired-kid-in-window → retired_key, currently_authorized false (live rule)', () => {
    const retired = pair('retired-k1');
    const env = envelope();
    const { token } = issueV4(retired, env);
    const g = deployGate({
      deployTarget: target(),
      token: {
        token,
        decision_result: env,
        registry: {
          keys: [{
            kid: retired.kid,
            public_key_pem: retired.publicPem,
            status: 'retired',
            valid_from: '2020-01-01T00:00:00.000Z',
            retired_at: '2099-01-01T00:00:00.000Z',
          }],
        },
      },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.reason, 'retired_key');
    assert.equal(g.verification.verify_status, 'RETIRED_KEY_VALID_AT_ISSUE');
  });

  it('TOKEN without registry or pinnedKeyPem → inputs_incomplete', () => {
    const env = envelope();
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      token: { token, decision_result: env },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.reason, 'inputs_incomplete');
  });

  it('TOKEN wins over a forged sibling receipt view', () => {
    const env = envelope();
    const { token } = issueV4(signer, env);
    const g = deployGate({
      deployTarget: target(),
      receipt: {
        currently_authorized: true,
        decision: 'ALLOW',
        operation: 'deploy',
        bound_environment: 'staging',
        bound_artifact_id: ART,
      },
      token: { token, decision_result: env, registry: keys },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    assert.equal(g.deploy_allowed, true);
    assert.equal(g.verification.mode, 'token');
  });
});

describe('deployGate — verification observation is deterministic (not a preimage field)', () => {
  it('same TOKEN input → identical verification observation', () => {
    const signer = pair('det-k1');
    const env = envelope();
    const { token } = issueV4(signer, env);
    const input = {
      deployTarget: target(),
      token: { token, decision_result: env, registry: registry(signer) },
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    };
    const a = deployGate(input);
    const b = deployGate(input);
    assert.deepEqual(a, b);
    assert.equal(a.verification.mode, 'token');
  });
});
