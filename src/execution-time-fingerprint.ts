/**
 * ID842 step 1 — host-independent execution-time fingerprint recheck (pure).
 *
 * Recomputes the CURRENT artifacts' bundle fingerprint with the CANONICAL algorithm
 * (server change-set.computeBundleFingerprint / crbundle.v1) and compares it to the
 * fingerprint authorized on the receipt/envelope. No network, no host callback —
 * measures only the artifacts it is given.
 *
 * Gated at the guard wire by GuardConfig.requireExecutionStateMatch
 * (guard@8 default true — fail-closed; false / 'warn' are explicit opt-down).
 */

import { createHash } from 'node:crypto';
import type { Artifact } from './types.js';

/** Matches server change-set.js NUL separator. */
const NUL = '\x1f';
/** Matches server change-set.js BUNDLE_FP_DOMAIN. */
const BUNDLE_FP_DOMAIN = 'crbundle.v1';

function sha256hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function specStr(v: unknown): string {
  if (v == null) return '';
  return typeof v === 'string' ? v : JSON.stringify(v);
}

function scalar(v: unknown): string {
  return v == null ? '' : String(v);
}

/** Context slots the server folds into crbundle.v1 (change-set.js:477–480). */
export type BundleFingerprintContext = {
  operation?: unknown;
  environment?: unknown;
  repository?: unknown;
  branch?: unknown;
  pull_request?: unknown;
  policy_profile?: unknown;
};

/**
 * Canonical crbundle.v1 bundle fingerprint — byte-identical to
 * coderifts-app change-set.computeBundleFingerprint(artifacts, context) at change-set.js:466.
 * Do NOT invent a second preimage.
 */
export function computeCanonicalBundleFingerprint(
  artifacts: Artifact[],
  context?: BundleFingerprintContext | null,
): string {
  const sorted = artifacts.slice().sort((x, y) => {
    const kx = `${x.type}${NUL}${x.id}`;
    const ky = `${y.type}${NUL}${y.id}`;
    return kx < ky ? -1 : (kx > ky ? 1 : 0);
  });
  const parts: string[] = [BUNDLE_FP_DOMAIN, String(artifacts.length)];
  for (const a of sorted) {
    parts.push(
      [a.type, a.id, sha256hex(specStr(a.before)), sha256hex(specStr(a.after))].join(NUL),
    );
  }
  const ctx = context || {};
  parts.push(
    [
      scalar(ctx.operation),
      scalar(ctx.environment),
      scalar(ctx.repository),
      scalar(ctx.branch),
      scalar(ctx.pull_request),
      scalar(ctx.policy_profile),
    ].join(NUL),
  );
  return `sha256:${sha256hex(parts.join(NUL))}`;
}

/** Stable reason codes (greppable; align with app verdict-core/execution-time-fingerprint). */
export const EXECUTION_TIME_FP_REASONS = Object.freeze({
  MATCH: 'match',
  /** Current artifacts hash ≠ authorized fingerprint (T1→T2 content drift). */
  FINGERPRINT_STALE_AT_EXECUTE: 'fingerprint_stale_at_execute',
  /** Integrity-style alias used on the guard blocked path (IntegrityCause). */
  EXECUTION_STATE_DRIFT: 'EXECUTION_STATE_DRIFT',
  MISSING_AUTHORIZED_FINGERPRINT: 'missing_authorized_fingerprint',
  MISSING_ARTIFACTS: 'missing_artifacts',
} as const);

export type ExecutionTimeFpReason =
  (typeof EXECUTION_TIME_FP_REASONS)[keyof typeof EXECUTION_TIME_FP_REASONS];

/**
 * Warn-mode classification: unmeasurable ≠ drift.
 * - fingerprint_stale_at_execute → real drift (loud: execution_state_drift_observed)
 * - missing_artifacts / missing_authorized_fingerprint → nothing to measure (quiet: execution_state_unmeasurable)
 */
export function isUnmeasurableExecutionStateReason(reason: string): boolean {
  return (
    reason === EXECUTION_TIME_FP_REASONS.MISSING_ARTIFACTS
    || reason === EXECUTION_TIME_FP_REASONS.MISSING_AUTHORIZED_FINGERPRINT
  );
}

/** Fixed note on the quiet warn event — not evidence of drift, not evidence of safety. */
export const EXECUTION_STATE_UNMEASURABLE_NOTE =
  'nothing to measure — not evidence of drift, not evidence of safety';

export type ExecutionTimeFingerprintVerdict = {
  match: boolean;
  reason: ExecutionTimeFpReason;
  current_fingerprint: string | null;
  authorized_fingerprint: string | null;
};

/**
 * Extract the authorized fingerprint from a decision envelope / receipt view.
 * Authorize path: fingerprint === input_fingerprint === crbundle.v1 hash.
 */
export function authorizedFingerprintFromEnvelope(
  envelope: Record<string, unknown> | null | undefined,
): string | null {
  if (!envelope || typeof envelope !== 'object') return null;
  if (typeof envelope.fingerprint === 'string' && envelope.fingerprint) {
    return envelope.fingerprint;
  }
  if (typeof envelope.input_fingerprint === 'string' && envelope.input_fingerprint) {
    return envelope.input_fingerprint;
  }
  if (typeof envelope.verdict_fingerprint === 'string' && envelope.verdict_fingerprint) {
    return envelope.verdict_fingerprint;
  }
  return null;
}

export type CheckExecutionTimeFingerprintArgs = {
  /** CURRENT artifacts about to execute (host-independent: measured as given). */
  artifacts: Artifact[] | undefined | null;
  /** Same context slots the server folded into crbundle.v1 at authorize. */
  context?: BundleFingerprintContext | null;
  /** Explicit authorized fp (wins over envelope extraction). */
  authorizedFingerprint?: string | null;
  /** Decision envelope / receipt projection carrying the authorized fp. */
  envelope?: Record<string, unknown> | null;
};

/**
 * Pure execution-time check: recompute current artifacts fp and compare to authorized.
 * No network, no host-supplied expected_fingerprint trusted for the CURRENT measurement.
 */
export function checkExecutionTimeFingerprint(
  args: CheckExecutionTimeFingerprintArgs = { artifacts: undefined },
): ExecutionTimeFingerprintVerdict {
  const { artifacts, context, authorizedFingerprint, envelope } = args;
  const authorized =
    typeof authorizedFingerprint === 'string' && authorizedFingerprint
      ? authorizedFingerprint
      : authorizedFingerprintFromEnvelope(envelope);

  if (!Array.isArray(artifacts) || artifacts.length === 0) {
    return {
      match: false,
      reason: EXECUTION_TIME_FP_REASONS.MISSING_ARTIFACTS,
      current_fingerprint: null,
      authorized_fingerprint: authorized,
    };
  }

  if (typeof authorized !== 'string' || !authorized) {
    return {
      match: false,
      reason: EXECUTION_TIME_FP_REASONS.MISSING_AUTHORIZED_FINGERPRINT,
      current_fingerprint: null,
      authorized_fingerprint: null,
    };
  }

  const current = computeCanonicalBundleFingerprint(artifacts, context || {});
  if (current !== authorized) {
    return {
      match: false,
      reason: EXECUTION_TIME_FP_REASONS.FINGERPRINT_STALE_AT_EXECUTE,
      current_fingerprint: current,
      authorized_fingerprint: authorized,
    };
  }

  return {
    match: true,
    reason: EXECUTION_TIME_FP_REASONS.MATCH,
    current_fingerprint: current,
    authorized_fingerprint: authorized,
  };
}
