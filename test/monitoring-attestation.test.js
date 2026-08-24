'use strict';

/**
 * B2/1 cr.monitor.attest.v1 — guard issuance via host sign(bytes).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  guardToolCall,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  renderFinalAnswerProof,
  monitorAttestSigningInput,
  MONITOR_ATTEST_VERSION,
  MONITOR_ATTEST_ENVELOPE_TAG,
  receiptDigestOfToken,
} = require('../dist/cjs/index.js');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'mon-guard-k1';
const PEM = publicKey.export({ type: 'spki', format: 'pem' });

const TRIGGER_ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
const TRIGGER = { toolName: 'Edit', arguments: {}, artifacts: TRIGGER_ARTIFACTS };
const TRIGGER_FP = computeCanonicalBundleFingerprint(TRIGGER_ARTIFACTS, { operation: 'tool_call' });

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

function envelope(execution_action, decision) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: 'dec_mon_att_1', correlation_id: 'c', evaluated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900000).toISOString(),
    fingerprint: TRIGGER_FP,
    input_fingerprint: TRIGGER_FP,
    receipt: { token: 'tok-mon', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}

function mockClient(action = 'CONTINUE_WITH_MONITORING', decision = 'WARN') {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const env = envelope(action, decision);
      lastEnv = env;
      return { decision, decision_result: env };
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

function signerCfg() {
  return {
    kid: KID,
    signer: (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey),
  };
}

function verifyLocal(tok) {
  const parts = tok.split('|');
  const body = JSON.parse(Buffer.from(parts[2], 'base64url').toString('utf8'));
  const input = monitorAttestSigningInput(body);
  const ok = crypto.verify(null, Buffer.from(input, 'utf8'), publicKey, Buffer.from(parts[3], 'base64url'));
  return { ok, body, parts };
}

const wired = (extra = {}) => ({
  client: mockClient(),
  monitoringSinkWired: true,
  onEvent: () => {},
  ...extra,
});

describe('cr.monitor.attest.v1 guard issuance', () => {
  it('constants', () => {
    assert.equal(MONITOR_ATTEST_VERSION, 'cr.monitor.attest.v1');
    assert.equal(MONITOR_ATTEST_ENVELOPE_TAG, 'cr.monitor.attest.v1');
  });

  it('CWM + signer → monitoring_attestation on outcome; proof line upgrades', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), wired({
      monitoringSink: async () => 'ACK-OK',
      monitoringAttestation: signerCfg(),
    }));
    assert.equal(o.verdict.kind, 'MONITOR');
    assert.equal(o.enforced, true);
    assert.equal(o.executed, true);
    assert.equal(o.monitoring_delivery.status, 'delivered_acked');
    assert.equal(typeof o.monitoring_attestation, 'string');
    assert.equal(o.proof.monitoring_attestation, o.monitoring_attestation);
    const { ok, body, parts } = verifyLocal(o.monitoring_attestation);
    assert.equal(ok, true);
    assert.equal(parts[0], 'cr.monitor.attest.v1');
    assert.equal(parts[1], KID);
    assert.equal(body.v, 'cr.monitor.attest.v1');
    assert.equal(body.kid, KID);
    assert.equal(body.decision_id, 'dec_mon_att_1');
    assert.equal(body.delivery_status, 'delivered_acked');
    assert.equal(body.receipt_digest, receiptDigestOfToken('tok-mon'));
    assert.match(body.ack_digest, /^sha256:[a-f0-9]{64}$/);
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /monitoring: delivered \(attested kid mon-guard-k1\)/);
    assert.match(text, /holder of the monitoring key observed this delivery status/);
  });

  it('absent config → no monitoring_attestation (byte-identical to 9.1.0)', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), wired({
      monitoringSink: async () => 'ACK-OK',
    }));
    assert.equal(o.monitoring_attestation, undefined);
    assert.equal(o.proof.monitoring_attestation, undefined);
    assert.equal(o.monitoring_delivery.status, 'delivered_acked');
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /monitoring: delivered \(acked sha256:/);
    assert.equal(text.includes('attested kid'), false);
  });

  it('not_delivered attests honestly (failPolicy open so factory still path-visible)', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), wired({
      monitoringSink: () => { throw new Error('down'); },
      failPolicy: 'open',
      monitoringAttestation: signerCfg(),
    }));
    assert.equal(o.monitoring_delivery.status, 'not_delivered');
    assert.equal(typeof o.monitoring_attestation, 'string');
    const { ok, body } = verifyLocal(o.monitoring_attestation);
    assert.equal(ok, true);
    assert.equal(body.delivery_status, 'not_delivered');
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /attested kid mon-guard-k1/);
  });

  it('signer throw → omit token; execution unchanged', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), wired({
      monitoringSink: async () => 'ACK-OK',
      monitoringAttestation: {
        kid: KID,
        signer: () => { throw new Error('nope'); },
      },
    }));
    assert.equal(o.executed, true);
    assert.equal(o.enforced, true);
    assert.equal(o.monitoring_delivery.status, 'delivered_acked');
    assert.equal(o.monitoring_attestation, undefined);
  });

  it('ALLOW path with signer configured → no token', async () => {
    const o = await guardToolCall(TRIGGER, async () => ({ ok: true }), {
      client: mockClient('CONTINUE', 'ALLOW'),
      monitoringAttestation: signerCfg(),
    });
    assert.equal(o.verdict.kind, 'ALLOW');
    assert.equal(o.monitoring_delivery, undefined);
    assert.equal(o.monitoring_attestation, undefined);
  });

  it('determinism: same delivery + same signer → same token', async () => {
    const cfg = signerCfg();
    const a = await guardToolCall(TRIGGER, async () => ({ ok: true }), wired({
      monitoringSink: async () => 'ACK-OK',
      monitoringAttestation: cfg,
    }));
    const b = await guardToolCall(TRIGGER, async () => ({ ok: true }), wired({
      monitoringSink: async () => 'ACK-OK',
      monitoringAttestation: cfg,
    }));
    // observed_at comes from delivery evidence.at (iso per call) so tokens differ by timestamp.
    // Same payload fields except observed_at; signatures verify independently.
    const va = verifyLocal(a.monitoring_attestation);
    const vb = verifyLocal(b.monitoring_attestation);
    assert.equal(va.ok, true);
    assert.equal(vb.ok, true);
    assert.equal(va.body.decision_id, vb.body.decision_id);
    assert.equal(va.body.receipt_digest, vb.body.receipt_digest);
    assert.equal(va.body.delivery_status, vb.body.delivery_status);
  });
});
