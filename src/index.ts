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
// P0-b/c client-enforcement gate: decision↔action reconciliation, §111 degraded, §115 safe_for_agent,
// and local artifact_digest / input_fingerprint recomputation.
export { evaluateEnvelope, computeArtifactDigest, computeBundleFingerprint } from './enforcement-gate.js';
export type { GateResult } from './enforcement-gate.js';
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

// artifactResolver — automatic base/head contract artifacts from a pure git snapshot (upstream of
// preflight; produces artifacts, never decides). Companion to MISSING_ARTIFACT_CONTENT.
export { resolve as resolveArtifacts } from './artifact-resolver.js';
export type {
  ResolveInput, ResolveConfig, ResolveResult, ResolvedArtifact, ResolveCoverage,
  UnresolvedEntry, UnresolvedReason, BlobValue, SsotSelection, ArtifactType as ResolverArtifactType,
} from './artifact-resolver.js';
export { matchGlob, globToRegExp } from './resolver-glob.js';

// guardToolRegistry — the agent-runtime inescapability layer ABOVE guardToolCall (Placement A only).
export { guardToolRegistry, RegistryConstructionError } from './tool-registry.js';
export type {
  RawTool,
  ProtectedTool,
  ToolMutationClass,
  EnforcementCoverage,
  RegistryCoverageReport,
  GuardToolRegistryConfig,
  RegistryResult,
  ToolBinder,
  RegistryConstructionErrorCode,
} from './tool-registry.js';

// repo-merge-gate (#7) — the PURE repo-side merge decision (Placement B). No I/O; protection is input.
export { gateDecision } from './merge-gate.js';
export type {
  GateDecisionInput, GateDecision, ReceiptView, RequiredContext, ProtectionState,
  GateReason, GateStatusState, EnforcementState,
} from './merge-gate.js';

// deploy-gate (#8) — the PURE deploy authorization decision. No I/O; pipeline enforcement is input.
export { deployGate } from './deploy-gate.js';
export type {
  DeployGateInput, DeployGateDecision, DeployReceiptView, DeployRequiredContext,
  DeployEnforcementState, DeployTarget, DeployGateReason,
} from './deploy-gate.js';
