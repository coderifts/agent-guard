/**
 * T3 post-commit observation (ID781). Re-read after the host write; compare to
 * authorized `after` (content) or intended post token (token-only adapters).
 * OBSERVED — never verified/atomic. Does not change `enforced`. Host attestation
 * is a label on the measurement, never a substitute.
 */
'use strict';

import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { createFsVersionToken, FS_ABSENT_TOKEN, fsTokenContentHash } from './cas-adapters/fs.js';
import { createApiVersionToken } from './cas-adapters/api.js';
import { createDbVersionToken } from './cas-adapters/db.js';
import { createRegistryVersionToken } from './cas-adapters/registry.js';
import { tokensEqual, type VersionToken } from './conditional-write.js';

/** Same specStr as execution-time-fingerprint.ts:25 (crbundle.v1 after-slot). */
function specStr(v: unknown): string {
  if (v == null) return '';
  return typeof v === 'string' ? v : JSON.stringify(v);
}
export function hashObservedContent(v: unknown): string {
  return 'sha256:' + createHash('sha256').update(specStr(v), 'utf8').digest('hex');
}

export type CommitObservationStatus =
  | 'not_observed' | 'observed_match' | 'observed_drift' | 'observed_token_match';
export type CommitHostAttestation =
  | 'absent' | 'host_attested_committed' | 'host_attested_refused' | 'conflict';
export type CommitObservationBlast = {
  compared: 'content' | 'token';
  decision?: string; execution_action?: string; decision_id?: string | null;
  unavailable?: boolean; cause?: string;
};
export type CommitObservation = {
  status: CommitObservationStatus;
  observed_fp?: string; expected_fp?: string; token?: string;
  observed_at: string;
  host_attestation?: CommitHostAttestation;
  blast?: CommitObservationBlast;
};
export type ObserveCommitCall = {
  arguments?: unknown;
  artifacts?: ReadonlyArray<{ id?: string; after?: unknown }>;
  filesTouched?: string[];
};
export type ObserveCommitPreflight = (
  artifacts: Array<{ id?: string; type?: string; before?: unknown; after?: unknown }>,
) => Promise<{ ok: true; response: unknown } | { ok: false; cause: string }>;
export type ObserveCommitInput = {
  enabled: boolean; call: ObserveCommitCall; result?: unknown; now: string;
  preflightOnObserved?: ObserveCommitPreflight;
};

type Cas = 'committed' | 'refused' | 'committed_stale_detected';

function unobserved(now: string, host: CommitHostAttestation = 'absent'): CommitObservation {
  return { status: 'not_observed', observed_at: now, host_attestation: host };
}
function casStatus(result: unknown): Cas | null {
  const s = result && typeof result === 'object' ? (result as { status?: unknown }).status : null;
  return s === 'committed' || s === 'refused' || s === 'committed_stale_detected' ? s : null;
}
function hostLabel(cas: Cas | null, drifted: boolean): CommitHostAttestation {
  if (cas == null) return 'absent';
  if (cas === 'refused') return 'host_attested_refused';
  if (cas === 'committed' && drifted) return 'conflict';
  if (cas === 'committed_stale_detected') return drifted ? 'conflict' : 'host_attested_committed';
  return 'host_attested_committed';
}
function casInner(result: unknown): Record<string, unknown> | null {
  if (!result || typeof result !== 'object') return null;
  const o = result as Record<string, unknown>;
  if (o.status === 'committed' || o.status === 'committed_stale_detected') {
    return o.result && typeof o.result === 'object' ? o.result as Record<string, unknown> : null;
  }
  return o;
}
function inferPath(call: ObserveCommitCall, result: unknown): string | null {
  const args = call.arguments && typeof call.arguments === 'object'
    ? call.arguments as Record<string, unknown> : {};
  if (typeof args.path === 'string' && args.path) return args.path;
  if (Array.isArray(call.filesTouched) && typeof call.filesTouched[0] === 'string' && call.filesTouched[0]) {
    return call.filesTouched[0];
  }
  const inner = casInner(result);
  return inner && typeof inner.path === 'string' && inner.path ? inner.path : null;
}
function casObservedToken(result: unknown): VersionToken | null {
  if (!result || typeof result !== 'object') return null;
  const o = result as { observed_token?: unknown; post_commit_token?: unknown };
  if (typeof o.observed_token === 'string' && o.observed_token) return o.observed_token;
  if (typeof o.post_commit_token === 'string' && o.post_commit_token) return o.post_commit_token;
  return null;
}
function intendedPostToken(result: unknown): VersionToken | null {
  const inner = casInner(result);
  if (!inner) return null;
  if (typeof inner.new_etag === 'string' && inner.new_etag.trim()) return createApiVersionToken(inner.new_etag);
  if (inner.new_version != null && String(inner.new_version).trim()) {
    return createDbVersionToken(inner.new_version as string | number | bigint);
  }
  if (inner.new_token != null && String(inner.new_token).trim()) {
    return createRegistryVersionToken(inner.new_token as string | number | bigint);
  }
  if (typeof inner.written_content_hash === 'string' && /^[a-f0-9]{64}$/.test(inner.written_content_hash)) {
    return inner.written_content_hash;
  }
  return null;
}
function authorizedAfter(artifacts: ObserveCommitCall['artifacts']): unknown {
  if (!Array.isArray(artifacts)) return undefined;
  for (const a of artifacts) {
    if (a && a.after !== undefined && a.after !== null) return a.after;
  }
  return undefined;
}

/** T3 measurement. Never throws. Does not write. Does not flip enforced. */
export async function observeCommit(input: ObserveCommitInput): Promise<CommitObservation> {
  const cas = casStatus(input.result);
  const host0 = hostLabel(cas, false);
  if (input.enabled !== true) return unobserved(input.now, 'absent');
  try {
    return await observeInner(input, cas, host0);
  } catch {
    return unobserved(input.now, host0);
  }
}

async function observeInner(
  input: ObserveCommitInput, cas: Cas | null, host0: CommitHostAttestation,
): Promise<CommitObservation> {
  const now = input.now;
  const expectedAfter = authorizedAfter(input.call.artifacts);
  const filePath = inferPath(input.call, input.result);
  let observedContent: string | null = null;
  let token: string | undefined;
  if (filePath && expectedAfter !== undefined) {
    const fsTok = await createFsVersionToken(filePath);
    token = fsTok;
    observedContent = fsTok === FS_ABSENT_TOKEN ? '' : await fsp.readFile(filePath, 'utf8');
  }
  if (observedContent !== null && expectedAfter !== undefined) {
    const observed_fp = hashObservedContent(observedContent);
    const expected_fp = hashObservedContent(expectedAfter);
    const match = observed_fp === expected_fp;
    const obs: CommitObservation = {
      status: match ? 'observed_match' : 'observed_drift',
      observed_fp, expected_fp, token, observed_at: now,
      host_attestation: hostLabel(cas, !match),
    };
    if (!match) obs.blast = await contentBlast(input, observedContent);
    return obs;
  }
  const observedTok = casObservedToken(input.result);
  const intended = intendedPostToken(input.result);
  if (observedTok && intended) {
    const tokenMatch = intended.length === 64 && !intended.includes(':')
      ? fsTokenContentHash(observedTok) === intended
      : tokensEqual(observedTok, intended);
    const obs: CommitObservation = {
      status: tokenMatch ? 'observed_token_match' : 'observed_drift',
      token: observedTok, observed_at: now, host_attestation: hostLabel(cas, !tokenMatch),
    };
    if (!tokenMatch) {
      obs.observed_fp = observedTok; obs.expected_fp = intended; obs.blast = { compared: 'token' };
    }
    return obs;
  }
  if (observedTok) return { status: 'not_observed', token: observedTok, observed_at: now, host_attestation: host0 };
  return unobserved(now, host0);
}

async function contentBlast(input: ObserveCommitInput, observedContent: string): Promise<CommitObservationBlast> {
  const pf = input.preflightOnObserved;
  if (typeof pf !== 'function') return { compared: 'content' };
  const arts = Array.isArray(input.call.artifacts)
    ? input.call.artifacts.map((a) => ({ ...a, after: observedContent }))
    : [{ after: observedContent }];
  try {
    const r = await pf(arts);
    if (!r.ok) return { compared: 'content', unavailable: true, cause: r.cause };
    const raw = r.response;
    const env = raw && typeof raw === 'object' && (raw as { decision_result?: unknown }).decision_result
      && typeof (raw as { decision_result: unknown }).decision_result === 'object'
      ? (raw as { decision_result: Record<string, unknown> }).decision_result
      : (raw && typeof raw === 'object' ? raw as Record<string, unknown> : null);
    if (!env) return { compared: 'content', unavailable: true };
    return {
      compared: 'content',
      decision: typeof env.decision === 'string' ? env.decision : undefined,
      execution_action: typeof env.execution_action === 'string' ? env.execution_action : undefined,
      decision_id: typeof env.decision_id === 'string' ? env.decision_id : null,
    };
  } catch (err) {
    return { compared: 'content', unavailable: true, cause: err instanceof Error ? err.message : 'preflight_threw' };
  }
}
