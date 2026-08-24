/**
 * Binder-visible gate-refusal copy. Shared by the four host binders so a blocked
 * call teaches the same sentence the construction path already uses.
 *
 * Does not change verdict.cause / preimage. Additive string on the tool-result
 * body the host (and model) actually see.
 */
'use strict';

import type { GuardOutcome, GuardVerdict } from './types.js';
import type { FreshnessBasis } from './freshness.js';

/** One-line fix — same vocabulary as withCodeRifts / README / createFsPriorContentResolver. */
export const FRESHNESS_RESOLVER_FIX =
  'pass resolvePriorContent (e.g. createFsPriorContentResolver()) to withCodeRifts / GuardConfig';

export function verdictKind(outcome: GuardOutcome<unknown>): string {
  const v = outcome.verdict;
  return v && typeof v === 'object' && 'kind' in v ? String((v as { kind: string }).kind) : 'UNKNOWN';
}

export function verdictCause(outcome: GuardOutcome<unknown>): string | undefined {
  const v = outcome.verdict as GuardVerdict | undefined;
  if (v && typeof v === 'object' && 'cause' in v && typeof (v as { cause?: unknown }).cause === 'string') {
    return (v as { cause: string }).cause;
  }
  return undefined;
}

/**
 * Teaching suffix for freshness fail-closed. Names the cause and the fix.
 * Null when the refusal is not a freshness gate (BLOCK / APPROVAL stay byte-identical).
 */
export function freshnessRefusalTeaching(outcome: GuardOutcome<unknown>): string | null {
  const cause = verdictCause(outcome);
  const basis = outcome.freshness as FreshnessBasis | undefined;
  const wiring = basis && typeof basis === 'object' ? basis.wiring : undefined;
  const degradeReason = basis && basis.wiring === 'DEGRADED' && basis.degrade
    ? basis.degrade.reason
    : undefined;
  const assessment = basis && basis.wiring === 'ACTIVE' && basis.assessment
    ? basis.assessment.outcome
    : undefined;

  if (cause === 'FRESHNESS_REQUIRED') {
    if (wiring === 'NOT_CONFIGURED') {
      return (
        'cause: FRESHNESS_REQUIRED — resolvePriorContent / prior-content resolver not configured. '
        + `One-line fix: ${FRESHNESS_RESOLVER_FIX}.`
      );
    }
    if (wiring === 'DEGRADED') {
      const why = degradeReason || 'resolver_returned_empty';
      return (
        `cause: FRESHNESS_REQUIRED — prior-content resolver is configured but DEGRADED (${why}). `
        + 'Fix the resolver so it returns current file bytes.'
      );
    }
    return (
      'cause: FRESHNESS_REQUIRED — freshness measurement was required and was not ACTIVE. '
      + `One-line fix: ${FRESHNESS_RESOLVER_FIX}.`
    );
  }
  if (cause === 'FRESHNESS_FAILED') {
    const o = assessment || 'UNKNOWN';
    return (
      `cause: FRESHNESS_FAILED — prior-content measurement ran and fail-closed (${o}). `
      + 'Re-preflight with current bytes; do not retry the stale change-set.'
    );
  }
  return null;
}

/** Blocked-before-factory body. BLOCK/APPROVAL prefix is unchanged; freshness appends teaching. */
export function formatGateRefusalBody(outcome: GuardOutcome<unknown>): string {
  const kind = verdictKind(outcome);
  let body =
    `CodeRifts gate did not permit execution (verdict: ${kind}). `
    + 'No tool result was produced.';
  const teach = freshnessRefusalTeaching(outcome);
  if (teach) body += ` ${teach}`;
  return body;
}

export function formatGuardError(err: unknown): string {
  if (err instanceof Error) return err.message || err.name || 'Error';
  if (typeof err === 'string') return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
