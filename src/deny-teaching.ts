/**
 * deny-teaching.v1 — the machine block that makes a refusal actionable.
 *
 * ── WHY THIS IS NOT deny-remedy.v1 ──────────────────────────────────────────────────────────
 *
 * `deny-remedy.ts` beside this file is pinned to a published schema
 * (capability-demo/docs/deny-remedy.v1.json, sha256 3f51c5af…) and covers exactly THREE grant
 * classes, refusing on purpose to invent a fourth. Widening it would break every copy of that
 * schema in the ecosystem and silently change what a pinned document means.
 *
 * MEASURED: the guard's own refusal vocabulary is much larger than three — 4 AvailabilityCause and
 * 15 IntegrityCause values (src/types.ts) — and NONE of them produced a next step. A caller that
 * got `EXECUTION_ACTION_UNRECOGNISED` was told what was wrong and not what to do next.
 *
 * A deny with no next_action is a dead gate: the bot stops, a human is summoned, and the loop that
 * was supposed to be a protocol becomes a support ticket. This block sits BESIDE the remedy, never
 * replacing it, and answers the one question the cause alone cannot: what is the next call.
 *
 * ── WHAT IT DOES NOT DO ─────────────────────────────────────────────────────────────────────
 *
 * It is emitted AFTER a verdict, reads no key, verifies nothing, and cannot turn a deny into an
 * allow. `retryable` says whether the SAME call could ever succeed unchanged — it is not a promise
 * that it will, and `RETRY_SAME` on an availability cause still runs into the breaker.
 *
 * An unmapped cause gets `next_action: 'ESCALATE_HUMAN'` rather than a guess. That is the honest
 * default for this file: sending a bot to a call that does not address why it was refused is worse
 * than telling it a human is needed.
 */

/** What the caller should do next. Closed set — a surface must not invent a sixth. */
export const NEXT_ACTION = Object.freeze({
  /** Call preflight again with a grant requested. The change set is fine; authorization is missing. */
  REQUEST_GRANT: 'REQUEST_GRANT',
  /** Re-run preflight for the CURRENT change set — the previous decision no longer describes it. */
  REPREFLIGHT: 'REPREFLIGHT',
  /** The same call may succeed later, unchanged (transient). */
  RETRY_SAME: 'RETRY_SAME',
  /** The request itself must change before any retry can help. */
  FIX_REQUEST: 'FIX_REQUEST',
  /** No mechanical next step exists. A person decides. */
  ESCALATE_HUMAN: 'ESCALATE_HUMAN',
});

export type NextAction = (typeof NEXT_ACTION)[keyof typeof NEXT_ACTION];

/** The payload shape a next call needs, per action. Field names, not values. */
const PAYLOAD_SHAPE: Record<string, Record<string, string>> = Object.freeze({
  [NEXT_ACTION.REQUEST_GRANT]: {
    tool: 'preflight_change_set',
    preflight_mode: 'authorize',
    artifacts: 'Array<{ id, type, before, after }> — the COMPLETE base→head change set',
    context: '{ operation (required), repository?, branch?, pull_request?, environment? }',
    include_execution_grant: 'true — this refusal was about a missing grant',
  },
  [NEXT_ACTION.REPREFLIGHT]: {
    tool: 'preflight_change_set',
    preflight_mode: 'authorize',
    artifacts: 'Array<{ id, type, before, after }> — re-read from the CURRENT head, not the cached set',
    context: '{ operation (required), repository?, branch?, pull_request? }',
  },
  [NEXT_ACTION.RETRY_SAME]: {
    tool: 'preflight_change_set',
    note: 'the identical request; nothing in it needs to change',
  },
  [NEXT_ACTION.FIX_REQUEST]: {
    tool: 'preflight_change_set',
    note: 'the request was rejected on its own terms — see `reason` before resending',
  },
  [NEXT_ACTION.ESCALATE_HUMAN]: {},
});

/**
 * cause -> next step. Explicit and closed; an unlisted cause escalates rather than guessing.
 *
 * The mapping is by what the caller can DO, not by how bad the cause is. `RECEIPT_MISSING` and
 * `RECEIPT_ENVELOPE_MISMATCH` are different failures with the same next call, and a bot needs the
 * call, not the taxonomy.
 */
const BY_CAUSE: Record<string, NextAction> = Object.freeze({
  // Availability — the server, not the request.
  TIMEOUT: NEXT_ACTION.RETRY_SAME,
  NETWORK: NEXT_ACTION.RETRY_SAME,
  SERVER_ERROR: NEXT_ACTION.RETRY_SAME,
  RATE_LIMITED: NEXT_ACTION.RETRY_SAME,

  // No verifiable authorization for this change set.
  RECEIPT_MISSING: NEXT_ACTION.REQUEST_GRANT,
  RECEIPT_UNVERIFIED: NEXT_ACTION.REQUEST_GRANT,

  // A decision exists and does not describe THIS change set / envelope.
  RECEIPT_ENVELOPE_MISMATCH: NEXT_ACTION.REPREFLIGHT,
  ARTIFACT_MISMATCH: NEXT_ACTION.REPREFLIGHT,
  ANALYSIS_DEGRADED: NEXT_ACTION.REPREFLIGHT,

  // The response could not be read as a decision. Re-asking is the only mechanical move; the
  // guard has already refused to execute, so a re-preflight cannot weaken anything.
  UNREADABLE_DECISION: NEXT_ACTION.REPREFLIGHT,
  EXECUTION_ACTION_UNRECOGNISED: NEXT_ACTION.REPREFLIGHT,
  DECISION_INCONSISTENT: NEXT_ACTION.REPREFLIGHT,
  INVALID_RESPONSE: NEXT_ACTION.REPREFLIGHT,
  SCHEMA_INVALID: NEXT_ACTION.REPREFLIGHT,

  // The request was rejected on its own terms — resending it unchanged repeats the refusal.
  REQUEST_REJECTED: NEXT_ACTION.FIX_REQUEST,
  PAYLOAD_TOO_LARGE: NEXT_ACTION.FIX_REQUEST,

  // Local misconfiguration and version skew: no call the bot can make fixes these.
  CONFIG_ERROR: NEXT_ACTION.ESCALATE_HUMAN,
  DETECTOR_ERROR: NEXT_ACTION.ESCALATE_HUMAN,
  UNSUPPORTED_VERSION: NEXT_ACTION.ESCALATE_HUMAN,
});

export interface DenyTeaching {
  v: 'coderifts.deny.v1';
  reason: string;
  next_action: NextAction;
  payload_shape: Record<string, string>;
  retryable: boolean;
  /** Present only when the refusal names a target the caller addressed. */
  target?: string | null;
  /** The human sentence, kept — the block is the contract, the sentence is the courtesy. */
  human: string;
}

/**
 * @param reason the guard's own cause / refusal code
 * @param human  the sentence a person reads; kept alongside, never replaced
 */
export function buildDenyTeaching(
  reason: string,
  human: string,
  target: string | null = null,
): DenyTeaching {
  const key = String(reason || '').toUpperCase();
  const next = BY_CAUSE[key] || NEXT_ACTION.ESCALATE_HUMAN;
  return {
    v: 'coderifts.deny.v1',
    reason: key || 'UNKNOWN',
    next_action: next,
    payload_shape: { ...PAYLOAD_SHAPE[next] },
    // Only the transient class. A REPREFLIGHT is a DIFFERENT call, not a retry of this one, and
    // labelling it retryable would invite a bot to resend the request that was just refused.
    retryable: next === NEXT_ACTION.RETRY_SAME,
    ...(target ? { target } : {}),
    human: String(human || ''),
  };
}

/** Every cause this file maps — so a test can assert the guard's vocabulary is covered. */
export function mappedCauses(): string[] {
  return Object.keys(BY_CAUSE).sort();
}
