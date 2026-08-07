/**
 * Decision reading for the guard — envelope-first, fail-closed.
 *
 * Differs from the SDK ladder in one critical respect: a PRESENT execution_action outside the
 * closed set is NOT treated as missing. The SDK falls through to decision→action mapping, which
 * reinvents permission from the decision and makes reconciliation impossible (there is nothing
 * known to reconcile against). Future restrictive actions (e.g. QUARANTINE) would be silently
 * ignored the same way.
 *
 *   - PRESENT + closed set  → use that action
 *   - PRESENT + not closed  → halt reason EXECUTION_ACTION_UNRECOGNISED (do not map from decision)
 *   - MISSING               → legacy decision→action map (unchanged)
 *   - nothing readable      → STOP + UNREADABLE_DECISION
 */

import type { DecisionResultEnvelope, DecisionReceipt, ExecutionAction } from '@coderifts/sdk';

/** Closed control set — must match well-known recommended_usage.execution_action. */
const CLOSED_ACTIONS = new Set<string>([
  'CONTINUE',
  'CONTINUE_WITH_MONITORING',
  'REQUEST_APPROVAL',
  'STOP',
]);

/** Pure decision → execution-action map (mirrors the server's deriveExecutionAction). Missing-action only. */
const DECISION_TO_ACTION: Record<string, ExecutionAction> = {
  ALLOW: 'CONTINUE',
  WARN: 'CONTINUE_WITH_MONITORING',
  REQUIRE_APPROVAL: 'REQUEST_APPROVAL',
  BLOCK: 'STOP',
};

export type ReadDecisionReason =
  | 'UNREADABLE_DECISION'
  | 'EXECUTION_ACTION_UNRECOGNISED';

export interface ReadDecisionResult {
  /**
   * Action to honour when known. On EXECUTION_ACTION_UNRECOGNISED this is the raw present string
   * (when string-typed) so callers can distinguish it from a mapped STOP — never invent CONTINUE.
   * On UNREADABLE_DECISION this is STOP.
   */
  executionAction: ExecutionAction | string;
  decision: string | null;
  envelope?: DecisionResultEnvelope;
  receipt?: DecisionReceipt;
  reason?: ReadDecisionReason;
}

function isClosedAction(v: unknown): v is ExecutionAction {
  return typeof v === 'string' && CLOSED_ACTIONS.has(v);
}

/** Absent / empty — nothing to read (legacy map may apply). null/undefined/'' only. */
function isMissingAction(v: unknown): boolean {
  return v === undefined || v === null || v === '';
}

/**
 * Classify a field value. A non-empty value outside the closed set is PRESENT unknown —
 * including wrong types (number/object). That is not the same fact as missing.
 */
function classifyAction(v: unknown): 'missing' | 'known' | 'unknown' {
  if (isMissingAction(v)) return 'missing';
  if (isClosedAction(v)) return 'known';
  return 'unknown';
}

function asEnvelope(env: object): DecisionResultEnvelope {
  return env as DecisionResultEnvelope;
}

function receiptOf(env: Record<string, unknown>): DecisionReceipt | undefined {
  const receipt = env.receipt;
  return receipt && typeof receipt === 'object' ? (receipt as DecisionReceipt) : undefined;
}

function decisionOf(...candidates: unknown[]): string | null {
  for (const c of candidates) {
    if (typeof c === 'string' && c.length > 0) return c;
  }
  return null;
}

/**
 * Read a governance decision from ANY CodeRifts response, fail-closed.
 * Never throws.
 */
export function readDecision(response: unknown): ReadDecisionResult {
  if (!response || typeof response !== 'object') {
    return { executionAction: 'STOP', decision: null, reason: 'UNREADABLE_DECISION' };
  }
  const r = response as Record<string, unknown>;
  const envRaw = r.decision_result;
  const envObj = envRaw && typeof envRaw === 'object' ? (envRaw as Record<string, unknown>) : null;

  // 1. Envelope-first — when decision_result is an object, classify ITS execution_action.
  if (envObj) {
    const envCls = classifyAction(envObj.execution_action);
    if (envCls === 'known') {
      return {
        executionAction: envObj.execution_action as ExecutionAction,
        decision: decisionOf(envObj.decision, r.decision),
        envelope: asEnvelope(envObj),
        receipt: receiptOf(envObj),
      };
    }
    if (envCls === 'unknown') {
      // PRESENT but not in the closed set — do NOT fall through to the decision map.
      const raw = envObj.execution_action;
      return {
        executionAction: typeof raw === 'string' ? raw : 'STOP',
        decision: decisionOf(envObj.decision, r.decision),
        envelope: asEnvelope(envObj),
        receipt: receiptOf(envObj),
        reason: 'EXECUTION_ACTION_UNRECOGNISED',
      };
    }
    // env action MISSING — try top-level, then decision map (may still attach this envelope below).
  }

  // 2. Top-level execution_action.
  const topCls = classifyAction(r.execution_action);
  if (topCls === 'known') {
    const out: ReadDecisionResult = {
      executionAction: r.execution_action as ExecutionAction,
      decision: decisionOf(r.decision, envObj?.decision),
    };
    // If envelope existed with a missing action, still surface it when present.
    if (envObj) {
      out.envelope = asEnvelope(envObj);
      out.receipt = receiptOf(envObj);
    }
    return out;
  }
  if (topCls === 'unknown') {
    const raw = r.execution_action;
    const out: ReadDecisionResult = {
      executionAction: typeof raw === 'string' ? raw : 'STOP',
      decision: decisionOf(r.decision, envObj?.decision),
      reason: 'EXECUTION_ACTION_UNRECOGNISED',
    };
    if (envObj) {
      out.envelope = asEnvelope(envObj);
      out.receipt = receiptOf(envObj);
    }
    return out;
  }

  // 3. Action MISSING everywhere — legacy decision→action map only (do not invent on unknown).
  const topDecision = decisionOf(r.decision);
  if (topDecision && Object.prototype.hasOwnProperty.call(DECISION_TO_ACTION, topDecision)) {
    const out: ReadDecisionResult = {
      executionAction: DECISION_TO_ACTION[topDecision]!,
      decision: topDecision,
    };
    if (envObj) {
      out.envelope = asEnvelope(envObj);
      out.receipt = receiptOf(envObj);
    }
    return out;
  }
  const envDecision = envObj ? decisionOf(envObj.decision) : null;
  if (envDecision && Object.prototype.hasOwnProperty.call(DECISION_TO_ACTION, envDecision)) {
    return {
      executionAction: DECISION_TO_ACTION[envDecision]!,
      decision: envDecision,
      envelope: envObj ? asEnvelope(envObj) : undefined,
      receipt: envObj ? receiptOf(envObj) : undefined,
    };
  }

  // 4. Fail closed.
  return {
    executionAction: 'STOP',
    decision: decisionOf(r.decision, envObj?.decision),
    reason: 'UNREADABLE_DECISION',
  };
}

export { CLOSED_ACTIONS, DECISION_TO_ACTION, isClosedAction, isMissingAction, classifyAction };
