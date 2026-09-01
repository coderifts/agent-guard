/**
 * next_agent_step — the DECISION's own remediation SUGGESTION, read from a SIGNED envelope.
 *
 * WHY THIS FILE EXISTS (I-1288f). The app moved the field inside `decision_result`, where
 * `decision_body_hash` covers it and the receipt signs it. That is what makes it safe for a
 * consumer holding only the envelope — deployGate, and the two verifier services — to render
 * it without a second call to the issuer.
 *
 * The corollary is the rule every caller here obeys: read it ONLY off an envelope whose
 * signature this process already checked. `receiptVerified` on a GuardVerdict and
 * `verification.mode === 'token'` on a deploy outcome are the two places that is true. An
 * unsigned step is an attacker-supplied instruction wearing the issuer's voice.
 *
 * Shape and closed action set: coderifts-app schemas/decision-result.v1.producer.json,
 * properties.next_agent_step (required action / reason / resume_condition / then_call;
 * additionalProperties false). Mirrors contract-gate 0.8.0 `readNextAgentStep`.
 *
 * NOT PERMISSION: this is the decision's remediation suggestion, not permission; branch on
 * execution_action.
 */

/** The closed action set the issuer projects (producer schema enum). */
export const NEXT_AGENT_ACTIONS = [
  're_preflight', 'revert', 'migrate', 'escalate', 'await_approval',
] as const;

export type NextAgentAction = typeof NEXT_AGENT_ACTIONS[number];

/**
 * The step as the issuer signs it. `action` is typed as the closed set plus `string`
 * so an action added by a newer issuer is carried through rather than dropped — the
 * same fail-open-for-DATA / fail-closed-for-CONTROL split the guard uses elsewhere.
 * Nothing here is a control input.
 */
export type NextAgentStep = {
  action: NextAgentAction | string;
  reason?: string;
  resume_condition?: string;
  then_call?: string | null;
};

/**
 * Read the step from a decision envelope. A step without a non-empty `action` is not a
 * step (same rule as contract-gate): the action is the only field a reader can act on,
 * so a step missing it would render as guidance that says nothing.
 *
 * Pure. Never throws. Returns null for anything that is not an object with an action.
 */
export function readNextAgentStep(envelope: unknown): NextAgentStep | null {
  if (!envelope || typeof envelope !== 'object') return null;
  const raw = (envelope as { next_agent_step?: unknown }).next_agent_step;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const step = raw as Record<string, unknown>;
  if (typeof step.action !== 'string' || step.action.length === 0) return null;
  return step as NextAgentStep;
}

/**
 * The one fixed sentence every CodeRifts surface prints beside a rendered step.
 * Byte-identical to contract-gate 0.8.0 `nextStepBlock`. It is not from the server:
 * the step is a suggestion, and execution_action remains the thing to branch on.
 */
export const NEXT_STEP_NOTE =
  "This is the decision's remediation suggestion, not permission; branch on execution_action.";
