/**
 * @coderifts/agent-guard — fail-closed guard for AI agent tool calls.
 *
 * Preflight contract changes before they execute. Security core FROZEN (agent-guard-api v1.0).
 *
 * @example
 * ```ts
 * import { guardToolCall } from '@coderifts/agent-guard';
 * import { CodeRifts } from '@coderifts/sdk';
 *
 * const client = new CodeRifts({ apiKey: 'cr_live_...' });
 * const outcome = await guardToolCall(
 *   { toolName: 'Edit', arguments: { path: 'openapi.yaml', ... }, filesTouched: ['openapi.yaml'] },
 *   async (envelope, redactedCall) => applyTheEdit(redactedCall),
 *   { client },
 * );
 * if (!outcome.executed) console.error('blocked:', outcome.verdict);
 * ```
 */

export { guardToolCall } from './guard.js';
export { builtinDetector, DETECTOR_VERSION } from './detector.js';
// P0 receipt-substitution fix: client-side receipt→envelope binding (mirrors server §106).
export { bindReceiptToEnvelope, computeBodyHash, canonicalJson } from './receipt-binding.js';
export type { BindResult, BindCause, BindContext, VerifyReceiptResultLike } from './receipt-binding.js';
export { readDecision } from '@coderifts/sdk';
// Additive session-taint surface (SEPARATE from the frozen single-call detector; own version).
export {
  SessionTaintTracker, SESSION_TAINT_VERSION, updateSession, evaluate, computeTainted,
  emptySessionState, projectState, classifyCommand, pathClass, deriveKeySignal,
} from './session-taint.js';
export type {
  SessionState, SessionTaintConfig, SessionTaintObservation, SessionEval, PendingRename, PathClass, CmdClass,
} from './session-taint.js';

export type {
  ReceiptVerifiedEnvelope,
  GuardConfig,
  ToolCallDescriptor,
  ExecuteFactory,
  ApprovedVerdict,
  GuardOutcome,
  GuardVerdict,
  UnavailableVerdict,
  AvailabilityCause,
  IntegrityCause,
  UnavailableCause,
  TriggerDetector,
  LkgStore,
  GuardEvent,
  CodeRifts,
  DecisionResultEnvelope,
  ExecutionAction,
  Artifact,
} from './types.js';
