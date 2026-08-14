/**
 * @coderifts/agent-guard — fail-closed guard for AI agent tool calls.
 *
 * Preflight contract changes before they execute. Security core FROZEN (agent-guard-api v1.0).
 *
 * An additive orchestration layer (withCodeRifts) now sits ALONGSIDE the frozen security core: it
 * composes the frozen primitives behind one entry point and reports a separate, narrower
 * composition-level assurance. It never modifies or re-decides any frozen primitive.
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
// Pure receipt-chain LINKAGE verifier (not signature verification; package never self-attests a chain).
export {
  verifyReceiptChainLinkage,
  previousReceiptCommitment,
  decodeReceiptBodyPrev,
  RECEIPT_PREV_NULL,
} from './receipt-chain.js';
export type {
  ReceiptChainLinkageResult,
  ReceiptChainLinkageReason,
} from './receipt-chain.js';
// P0-b/c client-enforcement gate: decision↔action reconciliation, §111 degraded, §115 safe_for_agent,
// and local artifact_digest / input_fingerprint recomputation.
export { evaluateEnvelope, computeArtifactDigest, computeBundleFingerprint } from './enforcement-gate.js';
export type { GateResult } from './enforcement-gate.js';
// ID842 step 1 — host-independent T2 execution-time fingerprint recheck (opt-in requireExecutionStateMatch).
export {
  checkExecutionTimeFingerprint,
  authorizedFingerprintFromEnvelope,
  computeCanonicalBundleFingerprint,
  EXECUTION_TIME_FP_REASONS,
} from './execution-time-fingerprint.js';
export type {
  CheckExecutionTimeFingerprintArgs,
  ExecutionTimeFingerprintVerdict,
  ExecutionTimeFpReason,
  BundleFingerprintContext,
} from './execution-time-fingerprint.js';
// Guard-local readDecision: present-but-unrecognised execution_action does NOT fall through to
// the decision map (SDK ladder did — that reinvented permission). Missing action still maps.
export { readDecision } from './read-decision.js';
export type { ReadDecisionResult, ReadDecisionReason } from './read-decision.js';
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
  GuardExecutionProof,
  ExecutionResultHash,
  GuardToolCallContext,
} from './types.js';

// Guard-produced execution proof (assembled from observed state only; never caller-supplied).
export {
  buildExecutionProof,
  hashExecutionResult,
  assertEnforcedReceiptInvariant,
  EXECUTION_PROOF_SPEC,
} from './execution-proof.js';

// ID645 — human-readable final-answer proof block (render layer over GuardExecutionProof).
// Does not change the proof shape; surfaces limits; null currently_authorized ≠ pass.
export {
  renderFinalAnswerProof,
  attachProofToAgentResponse,
  deriveProofBanner,
} from './final-answer-proof.js';
export type {
  RenderFinalAnswerProofOptions,
  AttachProofToAgentResponseOptions,
  FinalAnswerProofFormat,
  FinalAnswerProofBanner,
} from './final-answer-proof.js';

// Freshness: pure assess + runner collect (values into guardToolCall). Opt-in resolvePriorContent.
export {
  assessFreshness,
  assessWriteStylePrior,
  contentByteIdentical,
  computePathSetTreeHash,
  freshnessAllowsEnforce,
  isWriteStyleCall,
  artifactIdsForResolve,
  collectFreshnessCallContext,
  buildFreshnessBasis,
} from './freshness.js';
export type {
  FreshnessOutcome,
  FreshnessCheckLevel,
  FreshnessAssessInput,
  FreshnessAssessResult,
  WriteStylePriorInput,
  WriteStylePriorResult,
  FreshnessWiringState,
  FreshnessBasis,
  FreshnessCallContext,
  PriorContentResolver,
  FreshnessDegradeReason,
} from './freshness.js';

// Conditional-write surface (reporting + host helper executeIfUnchanged). Opt-in requireConditionalWrite.
// The package still never invents business writes — adapters perform I/O under the helper.
export {
  buildConditionalWriteBasis,
  tokensEqual,
  conditionalWriteResidual,
  RESIDUAL_UNCONDITIONAL_WRITE,
  executeIfUnchanged,
  StaleVersionTokenAbort,
} from './conditional-write.js';
export type {
  VersionToken,
  VersionedContent,
  ConditionalWriteReport,
  ConditionalWriteBasis,
  ConditionalWriteCallContext,
  ExecuteIfUnchangedOutcome,
  ExecuteIfUnchangedArgs,
} from './conditional-write.js';

// Filesystem CAS adapter (mtime + content-hash token, atomic rename). First execution-state CAS enabler.
export {
  createFsVersionToken,
  readVersionedFile,
  writeFileIfUnchanged,
  createFsPriorContentResolver,
  fsTokenContentHash,
  FS_VERSION_TOKEN_PREFIX,
  FS_ABSENT_TOKEN,
} from './cas-adapters/fs.js';

// HTTP/API CAS adapter — ETag/If-Match discipline; host-injected I/O only (no fetch).
export {
  createApiVersionToken,
  writeApiIfUnchanged,
  apiTokenRaw,
  API_VERSION_TOKEN_PREFIX,
  API_ABSENT_TOKEN,
} from './cas-adapters/api.js';
export type {
  WriteApiIfUnchangedArgs,
  ApiHostWriteReport,
  ApiWriteResult,
} from './cas-adapters/api.js';

// DB optimistic-lock CAS adapter — version column discipline; host-injected I/O only (no SQL drivers).
export {
  createDbVersionToken,
  writeDbIfUnchanged,
  dbTokenRaw,
  DB_VERSION_TOKEN_PREFIX,
  DB_ABSENT_TOKEN,
} from './cas-adapters/db.js';
export type {
  WriteDbIfUnchangedArgs,
  DbHostWriteReport,
  DbWriteResult,
} from './cas-adapters/db.js';

// Registry compareAndSwap CAS adapter — host-injected I/O only (no registry SDKs).
export {
  createRegistryVersionToken,
  writeRegistryIfUnchanged,
  registryTokenRaw,
  REGISTRY_VERSION_TOKEN_PREFIX,
  REGISTRY_ABSENT_TOKEN,
} from './cas-adapters/registry.js';
export type {
  WriteRegistryIfUnchangedArgs,
  RegistryHostCasReport,
  RegistryWriteResult,
} from './cas-adapters/registry.js';

// CAS attestation binder — separate cas-attestation.v1 record linking GuardExecutionProof +
// ExecuteIfUnchangedOutcome. Does not mutate the proof shape (ID781 option A follow-on).
export {
  buildCasAttestation,
  isGuardExecutionProof,
  isExecuteIfUnchangedOutcome,
  CAS_ATTESTATION_SPEC,
} from './cas-attestation.js';
export type {
  CasAttestation,
  CasAttestationCas,
  CasAttestationLimits,
} from './cas-attestation.js';

// artifactResolver — automatic base/head contract artifacts from a pure git snapshot (upstream of
// preflight; produces artifacts, never decides). Companion to MISSING_ARTIFACT_CONTENT.
export { resolve as resolveArtifacts, classifyByName, blobMapKey } from './artifact-resolver.js';
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
// bindDeploy — pure deploy-TIME caller over deployGate (host asserts env; pipeline action not observed).
export { bindDeploy, DEPLOY_REPAIRABLE_REASONS } from './deploy-bind.js';
export type {
  BindDeployInput, BindDeployResult, HostAssertedEnvironment,
} from './deploy-bind.js';

// enforcement-coverage report (#9) — the PURE tetrad aggregator. No I/O; reads the primitives' states.
export { coverageReport } from './coverage-report.js';
export type {
  CoverageReportInput, CoverageReport, Applicability, PlacementId, PlacementStrength,
  OverallCoverage, HonestClaimKey, PerPlacementRow,
  RuntimePlacementInput, MergePlacementInput, DeployPlacementInput, ContentPlacementInput,
} from './coverage-report.js';

// withCodeRifts (S1+S2+observation) — additive orchestration ABOVE the frozen primitives. Wraps
// guardToolRegistry with a mandatory operation; reports the registry's untouched report + a narrower
// composition assurance; optional onEvent (pass-through) + onSettledCall (table settled-call observation).
export {
  withCodeRifts,
  foldTableSettledCalls,
  guardedFractionAmongRoutes,
} from './with-coderifts.js';
export type {
  WithCodeRiftsInput, WithCodeRiftsResult, WithCodeRiftsRegistryConfig, CompositionAssurance,
  SettledCallObservation, CallRoute, CallTerminal, TableSettledCallRouteCounts,
  ReceiptThreadHandle, ReceiptCursorSkipReason,
} from './with-coderifts.js';

// ID632 slice 1 — thin OpenAI tool-calling adapter over withCodeRifts (reference adapter).
// Shape converter only; assurance objects pass through untouched.
// ID827 phase 1 — bindOpenAIGuardOutcome (Option B proof binder; additive, guard@6.1).
export {
  withCodeRiftsOpenAI,
  openAIToolAdapter,
  toOpenAITools,
  protectedToolToOpenAI,
  bindOpenAIGuardOutcome,
  defaultSerializeOpenAIToolResult,
} from './adapters/openai.js';
export type {
  OpenAIFunctionTool,
  WithCodeRiftsOpenAIResult,
  OpenAIToolMessage,
  ProofBoundOpenAIToolMessage,
  BindOpenAIGuardOutcomeArgs,
} from './adapters/openai.js';

// ID632 slice 2 — thin Anthropic tool_use adapter (same pattern; only the tool shape differs).
// ID827 phase 2 — bindAnthropicGuardOutcome (Option B proof binder; additive, guard@6.1).
export {
  withCodeRiftsAnthropic,
  anthropicToolAdapter,
  toAnthropicTools,
  protectedToolToAnthropic,
  bindAnthropicGuardOutcome,
  defaultSerializeAnthropicToolResult,
} from './adapters/anthropic.js';
export type {
  AnthropicTool,
  WithCodeRiftsAnthropicResult,
  AnthropicToolResult,
  ProofBoundAnthropicToolResult,
  BindAnthropicGuardOutcomeArgs,
} from './adapters/anthropic.js';

// ID632 slice 3 — thin LangChain/LangGraph tool adapter (plain descriptors; no framework dep).
// ID827 phase 2 — bindLangGraphGuardOutcome (Option B proof binder; additive, guard@6.1).
export {
  withCodeRiftsLangGraph,
  langGraphToolAdapter,
  toLangGraphTools,
  protectedToolToLangGraph,
  bindLangGraphGuardOutcome,
  defaultSerializeLangGraphToolResult,
} from './adapters/langgraph.js';
export type {
  LangGraphToolDescriptor,
  WithCodeRiftsLangGraphResult,
  LangGraphToolMessage,
  ProofBoundLangGraphToolMessage,
  BindLangGraphGuardOutcomeArgs,
} from './adapters/langgraph.js';

// ID632 slice 4 — thin Google Gemini function-calling adapter (functionDeclarations wrapper).
// ID827 phase 2 — bindGeminiGuardOutcome (Option B proof binder; object response; additive, guard@6.1).
export {
  withCodeRiftsGemini,
  geminiToolAdapter,
  toGeminiTools,
  protectedToolToFunctionDeclaration,
  bindGeminiGuardOutcome,
  defaultSerializeGeminiToolResult,
} from './adapters/gemini.js';
export type {
  GeminiFunctionDeclaration,
  GeminiTool,
  WithCodeRiftsGeminiResult,
  GeminiFunctionResponse,
  ProofBoundGeminiFunctionResponse,
  BindGeminiGuardOutcomeArgs,
} from './adapters/gemini.js';

// Option A safe dispatcher — protected table + one framework tool call → ProofBound* only.
// Closes manual-binder gap; no parallel guard path (uses ProtectedTool.execute → guardToolCall).
export {
  executeProtectedTool,
  executeOpenAIToolCall,
  executeAnthropicToolCall,
  executeGeminiToolCall,
  executeLangGraphToolCall,
  isGuardOutcome,
  surfaceEnvelopeFields,
} from './execute-tool-call.js';
export type {
  ProtectedToolTableInput,
  SurfacedEnvelopeFields,
  ExecuteOpenAIToolCallArgs,
  ExecuteAnthropicToolCallArgs,
  ExecuteGeminiToolCallArgs,
  ExecuteLangGraphToolCallArgs,
} from './execute-tool-call.js';
