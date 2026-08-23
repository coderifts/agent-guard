'use strict';

/**
 * N-4 monitoring delivery attestation.
 * Observation-side tri-state; ENFORCING teeth on not_delivered; HMAC optional.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');
const {
  guardToolCall,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  deliverMonitoring,
  formatMonitoringDeliveryLine,
  verifyAckHmac,
  ackBytes,
  renderFinalAnswerProof,
  DEFAULT_MONITORING_SINK_TIMEOUT_MS,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

const TRIGGER_ARTIFACTS = [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }];
const TRIGGER = { toolName: 'Edit', arguments: {}, artifacts: TRIGGER_ARTIFACTS };
const TRIGGER_FP = computeCanonicalBundleFingerprint(TRIGGER_ARTIFACTS, { operation: 'tool_call' });
const RESULT = { ok: true };
const okFactory = async () => RESULT;

function envelope(execution_action, decision, opts = {}) {
  return {
    spec_version: 'decision-result.v1.1', decision, execution_action,
    decision_id: 'dec_mon_1', correlation_id: 'c', evaluated_at: new Date().toISOString(),
    expires_at: opts.expires_at || new Date(Date.now() + 900000).toISOString(),
    fingerprint: opts.fingerprint || TRIGGER_FP,
    input_fingerprint: opts.input_fingerprint || opts.fingerprint || TRIGGER_FP,
    receipt: opts.noReceipt ? undefined : { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function response(execution_action, decision, opts) {
  return { decision, decision_result: envelope(execution_action, decision, opts) };
}
function mockClient({ preflight, verify } = {}) {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const resp = preflight ? preflight() : response('CONTINUE_WITH_MONITORING', 'WARN');
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      if (verify) return verify();
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

const wired = (extra = {}) => ({
  client: mockClient(),
  monitoringSinkWired: true,
  onEvent: () => {},
  ...extra,
});

describe('deliverMonitoring — unit (no guardToolCall)', () => {
  it('no sink → sent_unacked', async () => {
    const d = await deliverMonitoring({
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(d.status, 'sent_unacked');
    assert.equal(d.evidence.sink_kind, 'callback');
  });

  it('callback returning a value → delivered_acked + sha256 hash', async () => {
    const d = await deliverMonitoring({
      sink: async () => 'ACK-OK',
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(d.status, 'delivered_acked');
    assert.match(d.evidence.ack_hash, /^sha256:[0-9a-f]{64}$/);
    const expect = 'sha256:' + require('node:crypto').createHash('sha256').update('ACK-OK', 'utf8').digest('hex');
    assert.equal(d.evidence.ack_hash, expect);
  });

  it('undefined-returning callback → sent_unacked', async () => {
    const d = await deliverMonitoring({
      sink: () => undefined,
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(d.status, 'sent_unacked');
    assert.equal(d.evidence.ack_hash, undefined);
  });

  it('throwing sink → not_delivered reason threw', async () => {
    const d = await deliverMonitoring({
      sink: () => { throw new Error('boom'); },
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(d.status, 'not_delivered');
    assert.equal(d.reason, 'threw');
  });

  it('timeout sink → not_delivered reason timeout', async () => {
    const d = await deliverMonitoring({
      sink: () => new Promise(() => {}),
      timeoutMs: 30,
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(d.status, 'not_delivered');
    assert.equal(d.reason, 'timeout');
  });

  it('HTTP 200 → delivered_acked; HTTP 500 → not_delivered', async () => {
    const ok = await deliverMonitoring({
      sink: {
        url: 'https://sink.example/mon',
        fetchImpl: async () => ({ ok: true, status: 200, headers: {}, text: async () => 'ok' }),
      },
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(ok.status, 'delivered_acked');
    assert.equal(ok.evidence.status_code, 200);

    const bad = await deliverMonitoring({
      sink: {
        url: 'https://sink.example/mon',
        fetchImpl: async () => ({ ok: false, status: 500, headers: {}, text: async () => 'nope' }),
      },
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(bad.status, 'not_delivered');
    assert.equal(bad.reason, 'http_500');
  });

  it('HMAC valid / invalid / absent', async () => {
    const key = 'super-secret';
    const body = 'ACK';
    const hex = createHmac('sha256', key).update(body, 'utf8').digest('hex');

    const valid = await deliverMonitoring({
      sink: async () => ({ ack: body, signature: `sha256=${hex}` }),
      ackHmacKey: key,
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(valid.status, 'delivered_acked');
    assert.equal(valid.evidence.ack_verified, true);

    const invalid = await deliverMonitoring({
      sink: async () => ({ ack: body, signature: 'sha256:' + '0'.repeat(64) }),
      ackHmacKey: key,
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(invalid.status, 'not_delivered');
    assert.equal(invalid.reason, 'ack_hmac_invalid');

    const absent = await deliverMonitoring({
      sink: async () => ({ ack: body, signature: `sha256=${hex}` }),
      // no ackHmacKey
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(absent.status, 'delivered_acked');
    assert.equal(absent.evidence.ack_verified, undefined);

    const httpValid = await deliverMonitoring({
      sink: {
        url: 'https://sink.example/mon',
        ackHmacKey: key,
        fetchImpl: async () => ({
          ok: true,
          status: 200,
          headers: { 'x-coderifts-ack-signature': `sha256=${hex}` },
          text: async () => body,
        }),
      },
      payload: { at: 't', action: 'CONTINUE_WITH_MONITORING', kind: 'MONITOR' },
      now: 't',
    });
    assert.equal(httpValid.status, 'delivered_acked');
    assert.equal(httpValid.evidence.ack_verified, true);
  });

  it('DEFAULT timeout is 5000ms', () => {
    assert.equal(DEFAULT_MONITORING_SINK_TIMEOUT_MS, 5000);
  });

  it('verifyAckHmac rejects truncated signatures', () => {
    const key = 'k';
    const bytes = ackBytes('x');
    assert.equal(verifyAckHmac(bytes, 'ab', key), false);
  });
});

describe('guardToolCall CWM arm — delivery teeth', () => {
  it('acked callback → delivered_acked + hash; factory runs enforced', async () => {
    const o = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSink: async () => 'ACK-OK',
    }));
    assert.equal(o.verdict.kind, 'MONITOR');
    assert.equal(o.enforced, true);
    assert.equal(o.executed, true);
    assert.equal(o.monitoring_delivery.status, 'delivered_acked');
    assert.match(o.monitoring_delivery.evidence.ack_hash, /^sha256:[0-9a-f]{64}$/);
    assert.equal(o.proof.monitoring_delivery.status, 'delivered_acked');
  });

  it('undefined-returning callback → sent_unacked; still enforced', async () => {
    const o = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSink: () => undefined,
    }));
    assert.equal(o.verdict.kind, 'MONITOR');
    assert.equal(o.enforced, true);
    assert.equal(o.executed, true);
    assert.equal(o.monitoring_delivery.status, 'sent_unacked');
  });

  it('no dedicated sink (onEvent only) → sent_unacked (honest claim, no ack)', async () => {
    const o = await guardToolCall(TRIGGER, okFactory, wired());
    assert.equal(o.verdict.kind, 'MONITOR');
    assert.equal(o.enforced, true);
    assert.equal(o.monitoring_delivery.status, 'sent_unacked');
  });

  it('throwing sink under default (ENFORCING/closed) → not_delivered + MONITORING_UNWIRED blocks CWM', async () => {
    let ran = false;
    const o = await guardToolCall(TRIGGER, async () => { ran = true; return RESULT; }, wired({
      monitoringSink: () => { throw new Error('sink down'); },
    }));
    assert.equal(ran, false);
    assert.equal(o.executed, false);
    assert.equal(o.enforced, false);
    assert.equal(o.verdict.kind, 'UNAVAILABLE');
    assert.equal(o.verdict.cause, 'MONITORING_UNWIRED');
    assert.equal(o.monitoring_delivery.status, 'not_delivered');
    assert.equal(o.monitoring_delivery.reason, 'threw');
  });

  it('timeout sink under ENFORCING → not_delivered + blocks', async () => {
    const o = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSinkTimeoutMs: 25,
      monitoringSink: () => new Promise(() => {}),
    }));
    assert.equal(o.executed, false);
    assert.equal(o.verdict.cause, 'MONITORING_UNWIRED');
    assert.equal(o.monitoring_delivery.status, 'not_delivered');
    assert.equal(o.monitoring_delivery.reason, 'timeout');
  });

  it('advisory (failPolicy open): throwing sink degrades, does not block, reason visible', async () => {
    const o = await guardToolCall(TRIGGER, okFactory, wired({
      failPolicy: 'open',
      monitoringSink: () => { throw new Error('sink down'); },
    }));
    assert.equal(o.executed, true);
    assert.equal(o.enforced, false);
    assert.equal(o.verdict.kind, 'MONITOR');
    assert.equal(o.monitoring_delivery.status, 'not_delivered');
  });

  it('HTTP 200 proceeds; HTTP 500 blocks under default closed', async () => {
    const ok = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSink: {
        url: 'https://sink.example/mon',
        fetchImpl: async () => ({ ok: true, status: 200, headers: {}, text: async () => '' }),
      },
    }));
    assert.equal(ok.executed, true);
    assert.equal(ok.monitoring_delivery.status, 'delivered_acked');
    assert.equal(ok.monitoring_delivery.evidence.status_code, 200);

    const bad = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSink: {
        url: 'https://sink.example/mon',
        fetchImpl: async () => ({ ok: false, status: 500, headers: {}, text: async () => 'err' }),
      },
    }));
    assert.equal(bad.executed, false);
    assert.equal(bad.verdict.cause, 'MONITORING_UNWIRED');
    assert.equal(bad.monitoring_delivery.status, 'not_delivered');
    assert.equal(bad.monitoring_delivery.reason, 'http_500');
  });

  it('determinism: ALLOW path has no monitoring_delivery; CWM does not mutate verdict/preimage', async () => {
    const allowClient = mockClient({ preflight: () => response('CONTINUE', 'ALLOW') });
    const allow = await guardToolCall(TRIGGER, okFactory, { client: allowClient });
    assert.equal(allow.verdict.kind, 'ALLOW');
    assert.equal(allow.monitoring_delivery, undefined);
    assert.equal(allow.proof.monitoring_delivery, undefined);

    const cwm = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSink: async () => 'ACK',
    }));
    assert.equal(cwm.verdict.kind, 'MONITOR');
    assert.equal(cwm.verdict.action, 'CONTINUE_WITH_MONITORING');
    assert.equal(cwm.verdict.envelope.decision_id, 'dec_mon_1');
    assert.equal(cwm.verdict.envelope.fingerprint, TRIGGER_FP);
    assert.ok(cwm.monitoring_delivery);
    // observation field is additive — verdict kind/action/fp untouched
    assert.notEqual(cwm.monitoring_delivery.status, undefined);
  });
});

describe('proof renderer — monitoring line', () => {
  it('delivered_acked / sent_unacked / NOT delivered wording', () => {
    assert.equal(
      formatMonitoringDeliveryLine({ status: 'sent_unacked', evidence: { at: 't', sink_kind: 'callback' } }),
      'monitoring: sent, not acked',
    );
    assert.equal(
      formatMonitoringDeliveryLine({ status: 'not_delivered', reason: 'threw' }),
      'monitoring: NOT delivered (threw)',
    );
    const line = formatMonitoringDeliveryLine({
      status: 'delivered_acked',
      evidence: { at: 't', sink_kind: 'callback', ack_hash: 'sha256:' + 'ab'.repeat(32) },
    });
    assert.match(line, /^monitoring: delivered \(acked sha256:abababababab/);
  });

  it('renderFinalAnswerProof surfaces the tri-state + honesty sentence when present', async () => {
    const o = await guardToolCall(TRIGGER, okFactory, wired({
      monitoringSink: async () => 'ACK-OK',
    }));
    const text = renderFinalAnswerProof(o.proof);
    assert.match(text, /Monitoring delivery/);
    assert.match(text, /monitoring: delivered \(acked sha256:/);
    assert.match(text, /does NOT mean a human saw the event/);
  });

  it('ALLOW proof wording is unchanged (no monitoring section)', async () => {
    const allowClient = mockClient({ preflight: () => response('CONTINUE', 'ALLOW') });
    const o = await guardToolCall(TRIGGER, okFactory, { client: allowClient });
    const text = renderFinalAnswerProof(o.proof);
    assert.doesNotMatch(text, /Monitoring delivery/);
    assert.doesNotMatch(text, /monitoring:/);
  });
});
