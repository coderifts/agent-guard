/**
 * N-4 monitoring delivery attestation.
 *
 * The MONITOR gate still requires the host claim (`monitoringSinkWired` + `onEvent`).
 * This module records MEASURED delivery evidence when a dedicated `monitoringSink` is
 * invoked: callback ack, HTTP 2xx, or HMAC-verified ack. Observation-side only —
 * never the verdict/preimage.
 *
 * Tri-state (no fourth value):
 *   delivered_acked | sent_unacked | not_delivered
 *
 * Honesty: delivered_acked means the sink returned an ack. It does NOT mean a human saw it.
 */
'use strict';

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const DEFAULT_MONITORING_SINK_TIMEOUT_MS = 5000;

export type MonitoringDeliveryStatus = 'delivered_acked' | 'sent_unacked' | 'not_delivered';
export type MonitoringSinkKind = 'callback' | 'http';

export type MonitoringDeliveryEvidence = {
  at: string;
  ack_hash?: string;
  status_code?: number;
  sink_kind: MonitoringSinkKind;
  ack_verified?: boolean;
};

export type MonitoringDelivery = {
  status: MonitoringDeliveryStatus;
  evidence?: MonitoringDeliveryEvidence;
  reason?: string;
};

export type MonitoringSinkPayload = {
  at: string;
  decision_id?: string;
  action: 'CONTINUE_WITH_MONITORING';
  kind: 'MONITOR';
};

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{
  ok: boolean;
  status: number;
  headers?: { get?(name: string): string | null } | Record<string, string>;
  text(): Promise<string>;
}>;

export type MonitoringSinkHttp = {
  url: string;
  headers?: Record<string, string>;
  ackHmacKey?: string | Buffer;
  fetchImpl?: FetchLike;
};

export type MonitoringSinkCallback = (
  payload: MonitoringSinkPayload,
) => unknown | Promise<unknown>;

export type MonitoringSink = MonitoringSinkCallback | MonitoringSinkHttp;

const HMAC_HEADER_NAMES = [
  'x-coderifts-ack-signature',
  'x-hub-signature-256',
  'x-signature',
];

function sha256Prefixed(bytes: Buffer): string {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex');
}

export function ackBytes(ack: unknown): Buffer {
  if (ack == null) return Buffer.alloc(0);
  if (typeof ack === 'string') return Buffer.from(ack, 'utf8');
  if (Buffer.isBuffer(ack)) return ack;
  if (typeof ack === 'number' || typeof ack === 'boolean') return Buffer.from(String(ack), 'utf8');
  try {
    return Buffer.from(JSON.stringify(ack), 'utf8');
  } catch {
    return Buffer.from(String(ack), 'utf8');
  }
}

function normalizeSig(raw: string): string {
  return raw.trim().toLowerCase().replace(/^sha256=/, '');
}

export function verifyAckHmac(ack: Buffer, signature: string, key: string | Buffer): boolean {
  const expectedHex = createHmac('sha256', key).update(ack).digest('hex');
  const gotHex = normalizeSig(signature);
  if (!/^[0-9a-f]+$/.test(gotHex) || gotHex.length !== expectedHex.length) return false;
  try {
    return timingSafeEqual(Buffer.from(gotHex, 'hex'), Buffer.from(expectedHex, 'hex'));
  } catch {
    return false;
  }
}

function headerGet(
  headers: { get?(name: string): string | null } | Record<string, string> | undefined,
  name: string,
): string | null {
  if (!headers) return null;
  if (typeof (headers as { get?: unknown }).get === 'function') {
    const v = (headers as { get(n: string): string | null }).get(name);
    return v == null ? null : String(v);
  }
  const rec = headers as Record<string, string>;
  const key = Object.keys(rec).find((k) => k.toLowerCase() === name.toLowerCase());
  return key != null ? String(rec[key]) : null;
}

function pickSignature(
  hdrs?: { get?(n: string): string | null } | Record<string, string>,
): string | null {
  if (!hdrs) return null;
  for (const n of HMAC_HEADER_NAMES) {
    const v = headerGet(hdrs, n);
    if (v) return v;
  }
  return null;
}

function signatureFromAckValue(ack: unknown): string | null {
  if (!ack || typeof ack !== 'object' || Array.isArray(ack)) return null;
  const o = ack as Record<string, unknown>;
  for (const k of ['signature', 'ack_signature', 'hmac']) {
    if (typeof o[k] === 'string' && o[k]) return o[k] as string;
  }
  return null;
}

/** Bytes HMAC'd / hashed: prefer `ack`/`body` so a signature field is not included in its own preimage. */
function ackMaterial(raw: unknown): { bytes: Buffer; signature: string | null } {
  const signature = signatureFromAckValue(raw);
  if (raw && typeof raw === 'object' && !Array.isArray(raw) && !Buffer.isBuffer(raw)) {
    const o = raw as Record<string, unknown>;
    if ('ack' in o) return { bytes: ackBytes(o.ack), signature };
    if ('body' in o) return { bytes: ackBytes(o.body), signature };
    const copy = { ...o };
    delete copy.signature;
    delete copy.ack_signature;
    delete copy.hmac;
    return { bytes: ackBytes(copy), signature };
  }
  return { bytes: ackBytes(raw), signature };
}

function withTimeout<R>(p: Promise<R>, ms: number): Promise<R> {
  return new Promise<R>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(Object.assign(new Error(`monitoring sink timed out after ${ms}ms`), { name: 'TimeoutError' }));
    }, Math.max(1, ms));
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

function hmacResult(
  ack: Buffer,
  signature: string | null,
  key: string | Buffer | undefined,
): { ok: true; verified?: boolean } | { ok: false; reason: string } {
  if (key == null || String(key).length === 0) return { ok: true }; // no key → no verification, no penalty
  if (!signature) return { ok: false, reason: 'ack_hmac_missing' };
  if (!verifyAckHmac(ack, signature, key)) return { ok: false, reason: 'ack_hmac_invalid' };
  return { ok: true, verified: true };
}

async function deliverCallback(
  sink: MonitoringSinkCallback,
  payload: MonitoringSinkPayload,
  timeoutMs: number,
  ackHmacKey: string | Buffer | undefined,
  at: string,
): Promise<MonitoringDelivery> {
  try {
    const raw = await withTimeout(Promise.resolve(sink(payload)), timeoutMs);
    if (raw === undefined || raw === null) {
      return {
        status: 'sent_unacked',
        evidence: { at, sink_kind: 'callback' },
      };
    }
    const { bytes, signature } = ackMaterial(raw);
    const hmac = hmacResult(bytes, signature, ackHmacKey);
    if (!hmac.ok) {
      return {
        status: 'not_delivered',
        evidence: { at, sink_kind: 'callback', ack_hash: sha256Prefixed(bytes) },
        reason: hmac.reason,
      };
    }
    const evidence: MonitoringDeliveryEvidence = {
      at,
      sink_kind: 'callback',
      ack_hash: sha256Prefixed(bytes),
    };
    if (hmac.verified === true) evidence.ack_verified = true;
    return { status: 'delivered_acked', evidence };
  } catch (err) {
    const name = err && typeof err === 'object' ? (err as { name?: string }).name : '';
    const reason = name === 'TimeoutError' ? 'timeout' : 'threw';
    return {
      status: 'not_delivered',
      evidence: { at, sink_kind: 'callback' },
      reason,
    };
  }
}

async function deliverHttp(
  sink: MonitoringSinkHttp,
  payload: MonitoringSinkPayload,
  timeoutMs: number,
  ackHmacKey: string | Buffer | undefined,
  at: string,
): Promise<MonitoringDelivery> {
  const fetchImpl: FetchLike = sink.fetchImpl || (globalThis.fetch as unknown as FetchLike);
  if (typeof fetchImpl !== 'function') {
    return {
      status: 'not_delivered',
      evidence: { at, sink_kind: 'http' },
      reason: 'fetch_unavailable',
    };
  }
  try {
    const resp = await withTimeout(
      fetchImpl(sink.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(sink.headers || {}) },
        body: JSON.stringify(payload),
      }),
      timeoutMs,
    );
    const status_code = resp.status;
    if (!resp.ok || status_code < 200 || status_code >= 300) {
      return {
        status: 'not_delivered',
        evidence: { at, sink_kind: 'http', status_code },
        reason: `http_${status_code}`,
      };
    }
    let body = '';
    try { body = await resp.text(); } catch { body = ''; }
    const bytes = Buffer.from(body, 'utf8');
    const key = sink.ackHmacKey != null ? sink.ackHmacKey : ackHmacKey;
    const sig = pickSignature(resp.headers);
    const hmac = hmacResult(bytes, sig, key);
    if (!hmac.ok) {
      return {
        status: 'not_delivered',
        evidence: { at, sink_kind: 'http', status_code, ack_hash: sha256Prefixed(bytes) },
        reason: hmac.reason,
      };
    }
    const evidence: MonitoringDeliveryEvidence = {
      at,
      sink_kind: 'http',
      status_code,
    };
    if (bytes.length > 0) evidence.ack_hash = sha256Prefixed(bytes);
    if (hmac.verified === true) evidence.ack_verified = true;
    return { status: 'delivered_acked', evidence };
  } catch (err) {
    const name = err && typeof err === 'object' ? (err as { name?: string }).name : '';
    const reason = name === 'TimeoutError' ? 'timeout' : 'threw';
    return {
      status: 'not_delivered',
      evidence: { at, sink_kind: 'http' },
      reason,
    };
  }
}

function isHttpSink(sink: MonitoringSink): sink is MonitoringSinkHttp {
  return typeof sink === 'object' && sink != null && typeof (sink as MonitoringSinkHttp).url === 'string';
}

/**
 * Invoke the dedicated monitoring sink (if any) and classify delivery.
 * No sink configured → sent_unacked (claim + onEvent only; no ack semantics).
 */
export async function deliverMonitoring(args: {
  sink?: MonitoringSink;
  timeoutMs?: number;
  ackHmacKey?: string | Buffer;
  payload: MonitoringSinkPayload;
  now: string;
}): Promise<MonitoringDelivery> {
  const at = args.now;
  const timeoutMs = args.timeoutMs ?? DEFAULT_MONITORING_SINK_TIMEOUT_MS;
  if (args.sink == null) {
    return { status: 'sent_unacked', evidence: { at, sink_kind: 'callback' } };
  }
  if (typeof args.sink === 'function') {
    return deliverCallback(args.sink, args.payload, timeoutMs, args.ackHmacKey, at);
  }
  if (isHttpSink(args.sink)) {
    return deliverHttp(args.sink, args.payload, timeoutMs, args.ackHmacKey, at);
  }
  return {
    status: 'not_delivered',
    evidence: { at, sink_kind: 'callback' },
    reason: 'sink_unrecognised',
  };
}

/** Proof/renderer one-liner. Honesty sentence is appended by the renderer, not here. */
export function formatMonitoringDeliveryLine(d: MonitoringDelivery, attestedKid?: string | null): string {
  if (attestedKid) {
    if (d.status === 'sent_unacked') return `monitoring: sent, not acked (attested kid ${attestedKid})`;
    if (d.status === 'not_delivered') {
      return d.reason
        ? `monitoring: NOT delivered (${d.reason}; attested kid ${attestedKid})`
        : `monitoring: NOT delivered (attested kid ${attestedKid})`;
    }
    return `monitoring: delivered (attested kid ${attestedKid})`;
  }
  if (d.status === 'sent_unacked') return 'monitoring: sent, not acked';
  if (d.status === 'not_delivered') {
    return d.reason ? `monitoring: NOT delivered (${d.reason})` : 'monitoring: NOT delivered';
  }
  const ev = d.evidence;
  if (ev && ev.ack_hash) {
    const short = ev.ack_hash.replace(/^sha256:/, '').slice(0, 12);
    return `monitoring: delivered (acked sha256:${short}…)`;
  }
  if (ev && typeof ev.status_code === 'number') {
    return `monitoring: delivered (acked HTTP ${ev.status_code})`;
  }
  return 'monitoring: delivered (acked)';
}

/** ENFORCING teeth: not_delivered blocks CWM except observeOnly / failPolicy open. */
export function monitoringDeliveryFailClosed(config: {
  observeOnly?: boolean;
  failPolicy?: 'closed' | 'open' | 'lkg';
  profile?: 'ENFORCING_STRICT' | 'ENFORCING_ATOMIC';
}): boolean {
  if (config.observeOnly === true) return false;
  if (config.failPolicy === 'open') return false;
  return true;
}
