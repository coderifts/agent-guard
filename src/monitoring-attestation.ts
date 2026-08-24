/**
 * cr.monitor.attest.v1 issuance (guard side).
 *
 * Wire/signing input MIRRORS app src/verdict-core/monitoring-attestation.js /
 * docs/cr-monitor-attest-v1.md. The guard SIGNS via a host-provided
 * sign(bytes) callback — never a raw key in config. CodeRifts never holds
 * the monitoring private key.
 *
 * Observation-side only. Signer throw/empty → omit the token; never unsigned.
 */
'use strict';

import { createHash } from 'node:crypto';
import type { DecisionResultEnvelope } from './types.js';
import type { MonitoringDelivery } from './monitoring-delivery.js';

export const MONITOR_ATTEST_VERSION = 'cr.monitor.attest.v1';
export const MONITOR_ATTEST_SIGNING_PREFIX = 'crmonattest.v1';
export const MONITOR_ATTEST_ENVELOPE_TAG = 'cr.monitor.attest.v1';

const DELIVERY_STATUSES = ['delivered_acked', 'sent_unacked', 'not_delivered'] as const;
const SINK_KINDS = ['callback', 'http'] as const;

export type MonitoringAttestationSigner = (
  bytes: Uint8Array,
) => Uint8Array | Promise<Uint8Array>;

export type MonitoringAttestationConfig = {
  /** Customer-held monitoring key id. Named on the token; resolved later against a registry. */
  kid: string;
  /** Host signs the UTF-8 signing-input bytes. Returns raw Ed25519 signature. Never a raw key. */
  signer: MonitoringAttestationSigner;
};

function scalar(v: unknown): string {
  return v == null ? '' : String(v);
}

export function monitorAttestSigningInput(body: Record<string, unknown>): string {
  const parts = [
    MONITOR_ATTEST_SIGNING_PREFIX,
    scalar(body.kid),
    scalar(body.decision_id),
    scalar(body.receipt_digest),
    scalar(body.delivery_status),
    body.ack_digest != null && String(body.ack_digest).length > 0 ? String(body.ack_digest) : '',
    scalar(body.sink_kind),
    scalar(body.observed_at),
    body.attempt_count != null ? String(body.attempt_count) : '',
  ];
  return parts.join('|');
}

export function receiptDigestOfToken(token: string): string {
  return 'sha256:' + createHash('sha256').update(String(token), 'utf8').digest('hex');
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function envelopeReceiptToken(envelope: DecisionResultEnvelope | null | undefined): string | null {
  if (!envelope || typeof envelope !== 'object') return null;
  const rec = (envelope as { receipt?: { token?: unknown } }).receipt;
  if (rec && typeof rec.token === 'string' && rec.token.length > 0) return rec.token;
  return null;
}

/**
 * Issue a cr.monitor.attest.v1 token after a CWM arm. Returns undefined when
 * config is absent, required bindings are missing, or the host signer throws.
 */
export async function tryIssueMonitoringAttestation(args: {
  config?: MonitoringAttestationConfig | null;
  delivery: MonitoringDelivery;
  envelope: DecisionResultEnvelope | null | undefined;
  now?: string;
}): Promise<string | undefined> {
  const cfg = args.config;
  if (!cfg || typeof cfg.kid !== 'string' || !cfg.kid || typeof cfg.signer !== 'function') {
    return undefined;
  }
  const delivery = args.delivery;
  if (!delivery || typeof delivery.status !== 'string') return undefined;
  if (!(DELIVERY_STATUSES as readonly string[]).includes(delivery.status)) return undefined;

  const decision_id = args.envelope && typeof args.envelope.decision_id === 'string'
    ? args.envelope.decision_id
    : '';
  const token = envelopeReceiptToken(args.envelope);
  if (!decision_id || !token) return undefined;

  const rawKind = delivery.evidence && delivery.evidence.sink_kind;
  const sink_kind = (SINK_KINDS as readonly string[]).includes(String(rawKind))
    ? rawKind
    : 'callback';
  const observed_at = (delivery.evidence && delivery.evidence.at)
    || args.now
    || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const ack_digest = delivery.status === 'delivered_acked'
    && delivery.evidence
    && typeof delivery.evidence.ack_hash === 'string'
    && delivery.evidence.ack_hash.startsWith('sha256:')
    ? delivery.evidence.ack_hash
    : undefined;

  const body: Record<string, unknown> = {
    v: MONITOR_ATTEST_VERSION,
    kid: cfg.kid,
    decision_id,
    receipt_digest: receiptDigestOfToken(token),
    delivery_status: delivery.status,
    sink_kind,
    observed_at,
  };
  if (ack_digest) body.ack_digest = ack_digest;

  const input = Buffer.from(monitorAttestSigningInput(body), 'utf8');
  let sig: Uint8Array;
  try {
    sig = await cfg.signer(input);
  } catch {
    return undefined;
  }
  if (sig == null) return undefined;
  const sigBuf = Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  if (sigBuf.length === 0) return undefined;
  return [
    MONITOR_ATTEST_ENVELOPE_TAG,
    cfg.kid,
    b64url(Buffer.from(JSON.stringify(body), 'utf8')),
    b64url(sigBuf),
  ].join('|');
}

export function kidFromMonitoringAttestation(token: string | undefined | null): string | null {
  if (typeof token !== 'string' || token.length === 0) return null;
  const parts = token.split('|');
  if (parts.length !== 4 || parts[0] !== MONITOR_ATTEST_ENVELOPE_TAG) return null;
  return parts[1] || null;
}
