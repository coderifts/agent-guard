/**
 * @coderifts/agent-guard — guardToolCall (the security-core control flow).
 *
 * Order (frozen spec): redactor(call) -> input_fingerprint on the redacted call -> detect ->
 * preflight (unless SKIPPED) -> decide -> executeFactory(envelope, redactedCall) IFF SKIPPED or
 * CONTINUE / CONTINUE_WITH_MONITORING (or observeOnly). Fail-closed on every unknown; INTEGRITY
 * causes always resolve CLOSED + trip the breaker; enforced:true only on a LIVE receipt-verified
 * ALLOW/MONITOR; LKG is dormant in v1 (binding fields absent => UNUSABLE => closed). onEvent never throws.
 */

import { createHash } from 'node:crypto';
import { readDecision, isClosedAction } from './read-decision.js';
import type {
  GuardConfig, GuardOutcome, GuardVerdict, ApprovedVerdict, UnavailableCause, AvailabilityCause,
  IntegrityCause, ToolCallDescriptor, ExecuteFactory, GuardEvent, ReceiptVerifiedEnvelope,
  DecisionResultEnvelope, UnavailableVerdict, Artifact, ExecutionAction,
} from './types.js';
import { builtinDetector } from './detector.js';
import { bindReceiptToEnvelope } from './receipt-binding.js';
import type { BindCause, VerifyReceiptResultLike } from './receipt-binding.js';
import { evaluateEnvelope } from './enforcement-gate.js';
import {
  checkExecutionTimeFingerprint,
  isUnmeasurableExecutionStateReason,
  EXECUTION_STATE_UNMEASURABLE_NOTE,
} from './execution-time-fingerprint.js';
import { buildExecutionProof } from './execution-proof.js';
import { freezeCoverageObserved, type CoverageObserved } from './coverage-observed.js';
import {
  buildFreshnessBasis,
  isWriteStyleCall,
  isMutatingCall,
  type FreshnessBasis,
  type FreshnessCallContext,
} from './freshness.js';
import {
  buildConditionalWriteBasis,
  type ConditionalWriteBasis,
  type ConditionalWriteCallContext,
} from './conditional-write.js';
import { observeCommit, type CommitObservation } from './commit-observation.js';
import {
  buildCasAttestation,
  evaluateCasEvidence,
  isExecuteIfUnchangedOutcome,
  strictCommitObservation,
  COMMIT_EVIDENCE_MISSING,
} from './cas-attestation.js';
import type { CommitLabel } from './cas-attestation.js';
import {
  deliverMonitoring,
  monitoringDeliveryFailClosed,
  type MonitoringDelivery,
} from './monitoring-delivery.js';
import { tryIssueMonitoringAttestation } from './monitoring-attestation.js';
import { observePolicyPresence } from './policy.js';
import { buildDenyRemedy, denyErrorForReason } from './deny-remedy.js';
import type { PolicyPresence } from './policy.js';
import {
  isExecutionGrantEnabled,
  isSignerUnavailableError,
  v2WireFields,
  readExecutionGrantToken,
  resolveStateNonceForCall,
  type ExecutionGrantCallContext,
  type ExecutionGrantObservation,
} from './execution-grant.js';

// Per-config breaker state (time-window; not consecutive).
const breakers = new WeakMap<GuardConfig, { fails: number[] }>();

const nowMs = () => Date.now();
const iso = () => new Date().toISOString();

function emit(config: GuardConfig, e: GuardEvent): void {
  if (config.onEvent) { try { config.onEvent(e); } catch { /* onEvent never throws out */ } }
}

/**
 * Read host-owned previousReceipt once for this preflight. Does not store the result on config
 * or anywhere else — a getter may return a different value on the next call.
 */
function resolvePreviousReceipt(config: GuardConfig): string | undefined {
  const pr = config.previousReceipt;
  if (pr === undefined || pr === null) return undefined;
  let raw: unknown;
  if (typeof pr === 'function') {
    try { raw = pr(); } catch { return undefined; }
  } else {
    raw = pr;
  }
  if (typeof raw !== 'string') return undefined;
  const s = raw.trim();
  return s.length > 0 ? s : undefined;
}

function fingerprint(call: ToolCallDescriptor): string {
  const canon = JSON.stringify({ toolName: call.toolName, arguments: call.arguments, artifacts: call.artifacts, filesTouched: call.filesTouched, diff: call.diff });
  return 'sha256:' + createHash('sha256').update(canon).digest('hex');
}

function breakerRecord(config: GuardConfig): void {
  let s = breakers.get(config); if (!s) { s = { fails: [] }; breakers.set(config, s); }
  s.fails.push(nowMs());
}
function breakerTripped(config: GuardConfig): boolean {
  const s = breakers.get(config); if (!s) return false;
  const win = config.breakerWindowMs ?? 60000;
  const t = nowMs();
  s.fails = s.fails.filter((x) => t - x < win);
  return s.fails.length >= (config.maxUnavailablePerWindow ?? 3);
}

function requestAsksForGrant(request: unknown): boolean {
  return !!(
    request
    && typeof request === 'object'
    && (request as { include_execution_grant?: unknown }).include_execution_grant === true
  );
}

function classifyError(err: unknown, config: GuardConfig, grantRequested = false): { cause: UnavailableCause; integrity: boolean } {
  const e = err as { name?: string; status?: number; code?: string; message?: string; body?: { status?: number } } | undefined;
  const name = e?.name;
  const status = e?.status ?? e?.body?.status;
  if (name === 'TimeoutError' || name === 'AbortError' || e?.code === 'ABORT_ERR') return { cause: 'TIMEOUT', integrity: false };
  if (status === 429 || name === 'RateLimitError') return { cause: 'RATE_LIMITED', integrity: false };
  if (status === 413) return { cause: 'PAYLOAD_TOO_LARGE', integrity: true };
  if (status === 422) return { cause: 'REQUEST_REJECTED', integrity: true };
  if (status === 400 || status === 401 || status === 409) return { cause: 'REQUEST_REJECTED', integrity: true };
  // SIGNER_UNAVAILABLE is grant-path only. Gating keeps grant-OFF 5xx as SERVER_ERROR (9.5.0).
  // Naked 503 while THIS request asked for a grant is the signer-off class, not availability.
  if (grantRequested && (isSignerUnavailableError(err) || status === 503)) {
    return { cause: 'SIGNER_UNAVAILABLE', integrity: true };
  }
  if (typeof status === 'number' && status >= 500) return { cause: 'SERVER_ERROR', integrity: false };
  if (name === 'TypeError' || /fetch failed|network|ENOTFOUND|ECONNREFUSED|EAI_AGAIN/i.test(String(e?.message))) return { cause: 'NETWORK', integrity: false };
  if (name === 'ApiError') return { cause: 'SERVER_ERROR', integrity: false };
  return { cause: 'INVALID_RESPONSE', integrity: true }; // unrecognized => integrity => closed
}

function withTimeout<R>(p: Promise<R>, ms: number): Promise<R> {
  return new Promise<R>((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error(`preflight timed out after ${ms}ms`), { name: 'TimeoutError' })), Math.max(1, ms));
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

async function preflightWithRetry(config: GuardConfig, request: unknown): Promise<{ ok: true; response: unknown } | { ok: false; cause: UnavailableCause; integrity: boolean }> {
  const retries = config.retries ?? 1;
  const timeoutMs = config.timeoutMs ?? 2000;
  const budget = config.totalBudgetMs ?? 4500;
  const start = nowMs();
  let last: { cause: UnavailableCause; integrity: boolean } = { cause: 'TIMEOUT', integrity: false };
  for (let attempt = 0; attempt <= retries; attempt++) {
    const remaining = budget - (nowMs() - start);
    if (remaining <= 0) return { ok: false, cause: 'TIMEOUT', integrity: false };
    try {
      // AUTHORIZE preflight: authorizeChangeSet is the SDK 2.0.0 wrapper that sets
      // preflight_mode:'authorize' before calling preflightChangeSet. Widened via `as unknown as`
      // (mirrors the verifyReceipt cast) because GuardConfig.client is typed as the SDK client and
      // the method is reached structurally. Never call the raw mode-less preflightChangeSet here.
      const response = await withTimeout((config.client as unknown as { authorizeChangeSet(r: unknown): Promise<unknown> }).authorizeChangeSet(request), Math.min(timeoutMs, remaining));
      return { ok: true, response };
    } catch (err) {
      last = classifyError(err, config, requestAsksForGrant(request));
      if (last.integrity) return { ok: false, ...last }; // integrity: never retry
    }
  }
  return { ok: false, ...last };
}

/**
 * Verify the envelope's receipt AND bind it to THIS envelope (P0 substitution fix). Returns the
 * BRANDED envelope only when the receipt is valid, current, AND the LOCALLY-recomputed decision body
 * hash + fingerprint + operation/environment/audience scope all match. On a valid-but-unbound receipt
 * the `cause` is RECEIPT_ENVELOPE_MISMATCH; on a bad signature it is RECEIPT_UNVERIFIED. Fail-closed:
 * any mismatch returns { verified: null }.
 */
async function verifyEnvelope(
  config: GuardConfig,
  envelope: DecisionResultEnvelope | null,
): Promise<{ verified: ReceiptVerifiedEnvelope | null; cause?: BindCause }> {
  if (!envelope) return { verified: null };
  if (config.verifyReceipts === false) return { verified: null }; // opt-out => cannot brand => unenforceable + LKG unusable
  const token = envelope.receipt?.token;
  if (!token) return { verified: null };
  try {
    const r = await (config.client as unknown as {
      verifyReceipt(t: string): Promise<VerifyReceiptResultLike>;
    }).verifyReceipt(token);
    const bind = bindReceiptToEnvelope(
      envelope as unknown as Record<string, unknown>,
      r,
      { operation: config.operation, environment: config.environment, audience: config.audience },
    );
    if (bind.ok) return { verified: envelope as ReceiptVerifiedEnvelope };
    emit(config, { type: 'receipt_unverified', at: iso(), decisionId: envelope.decision_id, cause: bind.detail });
    return { verified: null, cause: bind.cause };
  } catch {
    // verification threw => treat as unverified (bad signature / transport)
    return { verified: null, cause: 'RECEIPT_UNVERIFIED' };
  }
}

// ── Outcome builders (keep the discriminated union satisfied) ────────────────────
// Every path attaches proof + freshness + conditional_write bases (guard-produced only).
async function runEnforced<T>(
  config: GuardConfig,
  factory: ExecuteFactory<T>,
  approved: ApprovedVerdict,
  redacted: ToolCallDescriptor,
  freshness: FreshnessBasis,
  conditional_write: ConditionalWriteBasis,
  monitoring_delivery?: MonitoringDelivery,
  monitoring_attestation?: string,
  grantCtx?: ExecutionGrantCallContext,
  grantObs?: ExecutionGrantObservation,
): Promise<GuardOutcome<T>> {
  emit(config, { type: 'execution_started', at: iso(), action: approved.action, decisionId: approved.envelope.decision_id });
  try {
    const result = grantCtx
      ? await factory(approved.envelope, redacted, grantCtx)
      : await factory(approved.envelope, redacted);
    const base = { executionAttempted: true as const, executed: true as const, enforced: true as const, result, verdict: approved, preflighted: true as const };
    return finishExecuted(config, base, freshness, conditional_write, redacted, result, monitoring_delivery, monitoring_attestation, grantObs);
  } catch (error) {
    emit(config, { type: 'factory_error', at: iso(), action: approved.action });
    const base = { executionAttempted: true as const, executed: false as const, enforced: true as const, error, verdict: approved, preflighted: true as const };
    return finishExecuted(config, base, freshness, conditional_write, redacted, undefined, monitoring_delivery, monitoring_attestation, grantObs);
  }
}
async function runUnenforced<T>(
  config: GuardConfig,
  factory: ExecuteFactory<T>,
  envelope: DecisionResultEnvelope | null,
  verdict: GuardVerdict,
  preflighted: boolean,
  redacted: ToolCallDescriptor,
  freshness: FreshnessBasis,
  conditional_write: ConditionalWriteBasis,
  monitoring_delivery?: MonitoringDelivery,
  monitoring_attestation?: string,
  grantCtx?: ExecutionGrantCallContext,
  grantObs?: ExecutionGrantObservation,
): Promise<GuardOutcome<T>> {
  emit(config, { type: 'execution_started', at: iso() });
  try {
    const result = grantCtx
      ? await factory(envelope, redacted, grantCtx)
      : await factory(envelope, redacted);
    const base = { executionAttempted: true as const, executed: true as const, enforced: false as const, result, verdict, preflighted };
    return finishExecuted(config, base, freshness, conditional_write, redacted, result, monitoring_delivery, monitoring_attestation, grantObs);
  } catch (error) {
    emit(config, { type: 'factory_error', at: iso() });
    const base = { executionAttempted: true as const, executed: false as const, enforced: false as const, error, verdict, preflighted };
    return finishExecuted(config, base, freshness, conditional_write, redacted, undefined, monitoring_delivery, monitoring_attestation, grantObs);
  }
}
function attachPolicyPresence<T>(outcome: GuardOutcome<T>, config: GuardConfig): GuardOutcome<T> {
  if (config.systemPrompt == null) return outcome;
  const policy_presence: PolicyPresence = observePolicyPresence(config.systemPrompt);
  return { ...outcome, policy_presence };
}

function coverageSnap(config: GuardConfig): { coverageObserved?: CoverageObserved } {
  if (!config.coverageObserver) return {};
  return { coverageObserved: freezeCoverageObserved(config.coverageObserver.snapshot()) };
}

function coverageOutcomeFieldsFrom(s: { coverageObserved?: CoverageObserved }): { coverage_observed?: CoverageObserved } {
  return s.coverageObserved ? { coverage_observed: s.coverageObserved } : {};
}

/**
 * Every refusal the guard reaches before the factory runs. `call` is optional so
 * the refusal does not depend on it: without it the outcome is exactly what it
 * was before the remedy existed; with it the outcome additionally names the
 * next step.
 *
 * The remedy is attached AFTER the verdict. No branch below reads it, and none
 * can turn executed:false into anything else.
 */
function blocked<T>(
  config: GuardConfig,
  verdict: GuardVerdict,
  preflighted: boolean,
  freshness: FreshnessBasis,
  conditional_write: ConditionalWriteBasis,
  monitoring_delivery?: MonitoringDelivery,
  monitoring_attestation?: string,
  grantObs?: ExecutionGrantObservation,
  call?: ToolCallDescriptor,
): GuardOutcome<T> {
  const commit_observation: CommitObservation = {
    status: 'not_observed', observed_at: iso(), host_attestation: 'absent',
  };
  const base = { executionAttempted: false as const, executed: false as const, enforced: false as const, verdict, preflighted };
  const cov = coverageSnap(config);
  // Only an UNAVAILABLE verdict carries a cause. A BLOCK or REQUEST_APPROVAL is a
  // policy decision on a grant that verified fine — obtaining another grant is not
  // the next step there, so those refusals carry no remedy.
  const cause = 'cause' in verdict ? verdict.cause : null;
  const remedy = call
    ? buildDenyRemedy({
        error: denyErrorForReason(cause),
        target: call.toolName || null,
        // The guard's own input fingerprint, already sha256:<hex>.
        fingerprint: fingerprint(call),
        observed: { cause, resolution: 'resolution' in verdict ? verdict.resolution : null },
      })
    : null;
  const out = {
    ...base,
    proof: buildExecutionProof({
      ...base,
      conditionalWriteBasis: conditional_write,
      commitObservation: commit_observation,
      monitoringDelivery: monitoring_delivery,
      ...(monitoring_attestation ? { monitoringAttestation: monitoring_attestation } : {}),
      ...cov,
    }),
    freshness,
    conditional_write,
    commit_observation,
    ...(monitoring_delivery ? { monitoring_delivery } : {}),
    ...(monitoring_attestation ? { monitoring_attestation } : {}),
    ...coverageOutcomeFieldsFrom(cov),
    ...(grantObs ? { execution_grant: grantObs } : {}),
    ...(remedy ? { remedy } : {}),
  } as GuardOutcome<T>;
  return attachPolicyPresence(out, config);
}

async function finishExecuted<T>(
  config: GuardConfig,
  base: { executionAttempted: true; executed: boolean; enforced: boolean; verdict: GuardVerdict; preflighted: boolean; result?: T; error?: unknown },
  freshness: FreshnessBasis,
  conditional_write: ConditionalWriteBasis,
  redacted: ToolCallDescriptor,
  result: unknown,
  monitoring_delivery?: MonitoringDelivery,
  monitoring_attestation?: string,
  grantObs?: ExecutionGrantObservation,
): Promise<GuardOutcome<T>> {
  const enabled = config.requireCommitObservation !== false;
  const commit_observation = await observeCommit({
    enabled,
    call: redacted,
    result,
    now: iso(),
    preflightOnObserved: (artifacts) => preflightWithRetry(config, {
      artifacts,
      context: { operation: config.operation ?? 'tool_call', environment: config.environment, audience: config.audience },
      previous_receipt: resolvePreviousReceipt(config),
    }),
  });
  if (!enabled) {
    emit(config, {
      type: 'commit_observation_check_disabled',
      at: iso(),
      cause: 'requireCommitObservation_false',
    });
  } else if (commit_observation.status === 'observed_drift') {
    emit(config, {
      type: 'commit_observed_drift',
      at: iso(),
      observed_fp: commit_observation.observed_fp,
      expected_fp: commit_observation.expected_fp,
      token: commit_observation.token,
    });
  }
  const casOpts = {
    registry: config.executorAttestation && config.executorAttestation.registry,
    ...(config.profile === 'ENFORCING_STRICT' ? { profile: 'ENFORCING_STRICT' as const } : {}),
    ...(config.profile === 'ENFORCING_ATOMIC' ? { profile: 'ENFORCING_ATOMIC' as const } : {}),
  };
  const cas_evidence = result !== undefined
    ? evaluateCasEvidence(result, casOpts)
    : undefined;
  const strictObs = config.profile === 'ENFORCING_STRICT'
    ? strictCommitObservation(result, cas_evidence, casOpts)
    : null;
  const cov = coverageSnap(config);
  const proofInput = {
    ...base,
    conditionalWriteBasis: conditional_write,
    commitObservation: commit_observation,
    monitoringDelivery: monitoring_delivery,
    ...(monitoring_attestation ? { monitoringAttestation: monitoring_attestation } : {}),
    ...(cas_evidence ? { casEvidence: cas_evidence } : {}),
    ...(strictObs ? {
      commitLabel: strictObs.commit_label,
      commitEvidenceReason: strictObs.commit_evidence_reason,
    } : {}),
    ...cov,
  };
  let proof = buildExecutionProof(proofInput);
  let atomicLabel: { commit_label: CommitLabel; commit_evidence_reason?: typeof COMMIT_EVIDENCE_MISSING } | null = null;
  if (result !== undefined && isExecuteIfUnchangedOutcome(result)) {
    try {
      const att = buildCasAttestation(proof, result, casOpts);
      if (config.profile === 'ENFORCING_ATOMIC') {
        if (att.derived.authorized_and_committed) {
          atomicLabel = { commit_label: 'authorized_and_committed' };
        } else if (att.derived.authorized_and_host_reported_committed) {
          atomicLabel = { commit_label: 'authorized_and_host_reported_committed' };
        } else {
          atomicLabel = {
            commit_label: 'authorized_not_committed',
            commit_evidence_reason: COMMIT_EVIDENCE_MISSING,
          };
        }
        proof = buildExecutionProof({
          ...proofInput,
          commitLabel: atomicLabel.commit_label,
          commitEvidenceReason: atomicLabel.commit_evidence_reason,
        });
      }
    } catch { /* label already set; never throw */ }
  }
  const labelBits = atomicLabel || (strictObs ? {
    commit_label: strictObs.commit_label,
    ...(strictObs.commit_evidence_reason
      ? { commit_evidence_reason: strictObs.commit_evidence_reason }
      : {}),
  } : null);
  const out = {
    ...base,
    proof,
    freshness,
    conditional_write,
    commit_observation,
    ...(monitoring_delivery ? { monitoring_delivery } : {}),
    ...(monitoring_attestation ? { monitoring_attestation } : {}),
    ...(cas_evidence ? { cas_evidence } : {}),
    ...(labelBits ? {
      commit_label: labelBits.commit_label,
      ...('commit_evidence_reason' in labelBits && labelBits.commit_evidence_reason
        ? { commit_evidence_reason: labelBits.commit_evidence_reason }
        : {}),
    } : {}),
    ...coverageOutcomeFieldsFrom(cov),
    ...(grantObs ? { execution_grant: grantObs } : {}),
  } as GuardOutcome<T>;
  return attachPolicyPresence(out, config);
}

function preflightBeforeByIdFrom(arts: Artifact[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!Array.isArray(arts)) return out;
  for (const a of arts) {
    if (a && typeof a.id === 'string' && a.id && typeof a.before === 'string') {
      out[a.id] = a.before;
    }
  }
  return out;
}

function freshnessFor(
  config: GuardConfig,
  redacted: ToolCallDescriptor,
  ctx: FreshnessCallContext,
  preflightArts?: Artifact[],
): { basis: FreshnessBasis; blockCause?: 'FRESHNESS_REQUIRED' | 'FRESHNESS_FAILED' } {
  return buildFreshnessBasis({
    writeStyle: isWriteStyleCall(redacted),
    requireFreshness: config.requireFreshness === true,
    ctx,
    preflightBeforeById: preflightBeforeByIdFrom(preflightArts ?? redacted.artifacts),
    allowStaleContext: config.allowStaleContext,
  });
}

function conditionalWriteFor(
  config: GuardConfig,
  redacted: ToolCallDescriptor,
  ctx: ConditionalWriteCallContext,
  detectedArts?: Artifact[],
): { basis: ConditionalWriteBasis; blockCause?: 'CONDITIONAL_WRITE_REQUIRED' } {
  // The policy gates on MUTATION, not on write-style. Detected artifacts are consulted as well as
  // the descriptor's, because the detector may carry the resulting state the caller did not lift.
  const mutating = isMutatingCall(redacted)
    || (Array.isArray(detectedArts) && isMutatingCall({ artifacts: detectedArts }));
  return buildConditionalWriteBasis({
    writeStyle: isWriteStyleCall(redacted),
    mutating,
    requireConditionalWrite: config.requireConditionalWrite === true,
    ctx,
  });
}

/** Split legacy FreshnessCallContext 4th arg from optional conditional-write host report fields. */
function splitCallContext(callContext?: FreshnessCallContext & ConditionalWriteCallContext): {
  fctx: FreshnessCallContext;
  cwctx: ConditionalWriteCallContext;
} {
  if (!callContext || typeof callContext !== 'object') {
    return { fctx: { wiring: 'NOT_CONFIGURED' }, cwctx: {} };
  }
  const {
    conditional_write,
    conditioned_on_token,
    versioned_content,
    wiring,
    priorResolved,
    degrade,
  } = callContext as FreshnessCallContext & ConditionalWriteCallContext;
  const fctx: FreshnessCallContext = {
    wiring: wiring ?? 'NOT_CONFIGURED',
    ...(priorResolved !== undefined ? { priorResolved } : {}),
    ...(degrade !== undefined ? { degrade } : {}),
  };
  const cwctx: ConditionalWriteCallContext = {
    ...(conditional_write !== undefined ? { conditional_write } : {}),
    ...(conditioned_on_token !== undefined ? { conditioned_on_token } : {}),
    ...(versioned_content !== undefined ? { versioned_content } : {}),
  };
  return { fctx, cwctx };
}

/**
 * True iff at least one supplied artifact carries analyzable before/after content. A preflight
 * trigger with no such content cannot be analyzed by the server (an empty list comes back as an
 * opaque REQUEST_REJECTED), so the guard fails closed LOCALLY with MISSING_ARTIFACT_CONTENT instead.
 * Reads defensively — the caller's artifacts are untrusted runtime data.
 */
function hasAnalyzableContent(artifacts: Artifact[] | undefined): boolean {
  if (!Array.isArray(artifacts) || artifacts.length === 0) return false;
  return artifacts.some((a) => {
    if (!a || typeof a !== 'object') return false;
    const before = (a as { before?: unknown }).before;
    const after = (a as { after?: unknown }).after;
    return (typeof before === 'string' && before.length > 0) || (typeof after === 'string' && after.length > 0);
  });
}

type UvArm =
  | { cause: IntegrityCause; failPolicy: 'closed' | 'open' | 'lkg'; resolution: 'CLOSED'; action: 'STOP' }
  | { cause: AvailabilityCause; failPolicy: 'closed' | 'open' | 'lkg'; resolution: 'CLOSED'; action: 'STOP' }
  | { cause: AvailabilityCause; failPolicy: 'open'; resolution: 'OPEN_PASSTHROUGH'; action: 'CONTINUE' }
  | { cause: AvailabilityCause; failPolicy: 'lkg'; resolution: 'LKG_SUBSTITUTION'; action: 'CONTINUE' | 'CONTINUE_WITH_MONITORING'; lkgEnvelope: ReceiptVerifiedEnvelope };

function unavailableVerdict(parts: UvArm, count: number): UnavailableVerdict {
  return { kind: 'UNAVAILABLE', decisionMissing: true, unavailableCount: count, ...parts };
}

/**
 * @param callContext  Runner-collected freshness values (optional) plus optional conditional-write
 *   host report fields. When omitted, freshness wiring is NOT_CONFIGURED and conditional_write is
 *   not_reported. The tool-registry runner calls collectFreshnessCallContext and passes the result.
 */
export async function guardToolCall<T>(
  call: ToolCallDescriptor,
  executeFactory: ExecuteFactory<T>,
  config: GuardConfig,
  callContext?: FreshnessCallContext & ConditionalWriteCallContext,
): Promise<GuardOutcome<T>> {
  const failPolicy = config.failPolicy ?? 'closed';
  const { fctx, cwctx } = splitCallContext(callContext);

  // 12. redactor runs FIRST; everything downstream uses the redacted descriptor.
  let redacted: ToolCallDescriptor;
  try {
    redacted = config.redactor ? config.redactor(call) : call;
  } catch {
    // A redactor throw is a CONFIG_ERROR (integrity) => closed.
    breakerRecord(config);
    return closedIntegrity(config, 'CONFIG_ERROR', failPolicy, fctx, cwctx, call);
  }
  const inputFp = fingerprint(redacted); // used for LKG lookup (dormant in v1)

  // 8/9. detector is fail-safe but a THROW is a DETECTOR_ERROR (integrity) => closed.
  const detector = config.detector ?? builtinDetector;
  let detection;
  try {
    detection = detector.detect(redacted);
  } catch {
    breakerRecord(config);
    return closedIntegrity(config, 'DETECTOR_ERROR', failPolicy, fctx, cwctx, redacted);
  }

  // requireExplicitArtifacts strict SKIP gate: suppress only when nonContract===true AND no signal.
  const suppressedByStrict = config.requireExplicitArtifacts === true && redacted.nonContract === true
    && (!detection.artifacts || detection.artifacts.length === 0) && detection.confident && !detection.trigger;

  // SKIPPED path: not a contract call => execute with enforced:false, preflighted:false.
  if (!detection.trigger || suppressedByStrict) {
    emit(config, { type: 'detection_skip', at: iso(), signals: detection.signals, detectorVersion: detector.version });
    const verdict: GuardVerdict = { kind: 'SKIPPED', reason: 'NOT_A_CONTRACT_CALL', signals: detection.signals, detectorVersion: detector.version };
    const { basis } = freshnessFor(config, redacted, fctx);
    const { basis: cwBasis } = conditionalWriteFor(config, redacted, cwctx);
    return runUnenforced(config, executeFactory, null, verdict, false, redacted, basis, cwBasis);
  }

  // Freshness permission gate for write-style under requireFreshness / DEGRADED (before preflight I/O).
  {
    const arts = (detection.artifacts && detection.artifacts.length > 0)
      ? detection.artifacts
      : redacted.artifacts;
    const { blockCause } = freshnessFor(config, redacted, fctx, arts);
    if (blockCause === 'FRESHNESS_REQUIRED' || blockCause === 'FRESHNESS_FAILED') {
      breakerRecord(config);
      return closedIntegrity(config, blockCause, failPolicy, fctx, cwctx, redacted, arts);
    }
  }

  // Conditional-write policy (requireConditionalWrite): a MUTATION without host report true → refuse.
  {
    const { blockCause } = conditionalWriteFor(config, redacted, cwctx, detection.artifacts);
    if (blockCause === 'CONDITIONAL_WRITE_REQUIRED') {
      breakerRecord(config);
      return closedIntegrity(config, blockCause, failPolicy, fctx, cwctx, redacted, detection.artifacts);
    }
  }

  // MISSING_ARTIFACT_CONTENT — developer-adoption fail-closed (audit #1). The detector says a contract
  // change is happening (trigger:true) but the caller supplied NO analyzable content: no artifacts, or
  // artifacts without before/after. Sending an empty list to the server returns an opaque
  // REQUEST_REJECTED; instead fail closed LOCALLY with a clear, actionable cause so the developer knows
  // to pass artifacts:[{ id, type, before, after }]. The tool does NOT execute (fail-closed preserved).
  // This can only fire when preflight is genuinely required — a non-contract/readonly call already
  // returned via the SKIPPED path above. It is NOT a server-availability failure, so it does NOT trip
  // the breaker (a developer's missing content must not degrade the open-policy path for later calls).
  if (!hasAnalyzableContent(detection.artifacts)) {
    emit(config, { type: 'artifact_content_missing', at: iso(), cause: 'MISSING_ARTIFACT_CONTENT', signals: detection.signals });
    const count = (breakers.get(config)?.fails.length) ?? 0;
    const v = unavailableVerdict({ cause: 'MISSING_ARTIFACT_CONTENT', failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
    const { basis } = freshnessFor(config, redacted, fctx, detection.artifacts);
    const { basis: cw } = conditionalWriteFor(config, redacted, cwctx, detection.artifacts);
    return blocked(config, v, false, basis, cw, undefined, undefined, undefined, redacted);
  }

  // config validation: lkg policy requires an LkgStore.
  if (failPolicy === 'lkg' && !config.lkg) {
    breakerRecord(config);
    return closedIntegrity(config, 'CONFIG_ERROR', failPolicy, fctx, cwctx, redacted, detection.artifacts);
  }

  // build the preflight request from the detected artifacts.
  // previous_receipt: host-supplied only (GuardConfig.previousReceipt). Never hardcoded-undefined
  // forever — when the host provides a prior token (string or getter), thread it so the issuer can
  // hash it into the signed `prev` slot. The guard does not retain or advance the value.
  //
  // executionGrant (9.6.0): per-invocation locals — never stored on GuardConfig (shared across
  // overlapping calls). Default OFF is this object without include_execution_grant (9.5.0 shape).
  const request: {
    artifacts: Artifact[];
    context: { operation: string; environment?: string; audience?: string };
    previous_receipt: string | undefined;
    idempotency_key: string | undefined;
    include_execution_grant?: true;
    state_nonce?: string;
    /**
     * The V2 binding (AUDIT P1 / RES-1). Set only when grantVersion is 'v2'
     * AND the deployment configured the field — see v2WireFields.
     */
    grant_version?: 'v2';
    executor_id?: string;
    adapter_id?: string;
    target_uri?: string;
    tenant_id?: string;
    policy_hash?: string;
    audience_hash?: string;
  } & Record<string, unknown> = {
    artifacts: detection.artifacts,
    context: { operation: config.operation ?? 'tool_call', environment: config.environment, audience: config.audience },
    previous_receipt: resolvePreviousReceipt(config),
    idempotency_key: undefined as string | undefined,
  };

  let grantObs: ExecutionGrantObservation | undefined;
  let grantForCall: string | null = null;
  if (isExecutionGrantEnabled(config)) {
    grantObs = { requested: true, arrived: false };
    const nonceRes = await resolveStateNonceForCall(config, redacted, detection.artifacts);
    if (!nonceRes.ok) {
      breakerRecord(config);
      return closedIntegrity(
        config, 'EXECUTION_GRANT_NONCE_UNRESOLVABLE', failPolicy, fctx, cwctx, redacted, detection.artifacts,
        undefined, undefined, grantObs,
      );
    }
    request.include_execution_grant = true;
    if (nonceRes.nonce) request.state_nonce = nonceRes.nonce;

    // ── V2 WIRE FIELDS (AUDIT P1 / RES-1) ────────────────────────────────────
    // The builder used to send include_execution_grant and state_nonce and
    // nothing else, so the V2 binding the config demanded never reached the
    // wire. Each configured field is attached; each unconfigured one is NAMED
    // in the observation rather than sent as an empty placeholder, which the
    // server would otherwise bind as a real value.
    const wire = v2WireFields(config);
    if (config.executionGrant?.grantVersion === 'v2') {
      request.grant_version = 'v2';
      for (const [k, v] of Object.entries(wire.fields)) request[k] = v;
    }
    // Recorded ONLY for v2. On v1 these fields are not "absent" — they are not
    // part of that grant shape at all, and stamping six absences onto every v1
    // observation would report a gap where there is no field. It also keeps the
    // v1 observation byte-identical for the callers already pinning it.
    if (config.executionGrant?.grantVersion === 'v2') {
      grantObs = {
        ...grantObs,
        grant_version: 'v2',
        v2_fields_sent: Object.keys(wire.fields),
        v2_fields_absent: wire.absent,
      };
    }
  }

  // request-attributable payload cap => PAYLOAD_TOO_LARGE (integrity) => closed.
  const cap = config.maxPayloadBytes ?? 1_000_000;
  if (Buffer.byteLength(JSON.stringify(request), 'utf8') > cap) {
    breakerRecord(config);
    return closedIntegrity(config, 'PAYLOAD_TOO_LARGE', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }

  emit(config, { type: 'preflight_start', at: iso() });
  const pf = await preflightWithRetry(config, request);

  if (!pf.ok) {
    // UNAVAILABLE. Integrity => always closed + breaker. Availability => failPolicy.
    breakerRecord(config);
    const count = (breakers.get(config)?.fails.length) ?? 1;
    const { basis } = freshnessFor(config, redacted, fctx, detection.artifacts);
    const { basis: cw } = conditionalWriteFor(config, redacted, cwctx, detection.artifacts);
    if (pf.integrity) {
      emit(config, { type: 'breaker_tripped', at: iso(), cause: pf.cause });
      const v = unavailableVerdict({ cause: pf.cause as IntegrityCause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
      return blocked(config, v, false, basis, cw, undefined, undefined, grantObs, redacted);
    }
    // availability
    const availCause = pf.cause as AvailabilityCause;
    // A grant was requested for THIS call: never OPEN_PASSTHROUGH / LKG-execute without a token.
    // failPolicy 'open' remains the 9.5.0 opt-in only when the grant path is off.
    if (grantObs && grantObs.requested) {
      if (breakerTripped(config)) emit(config, { type: 'breaker_tripped', at: iso(), cause: availCause });
      const v = unavailableVerdict({ cause: availCause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
      return blocked(config, v, false, basis, cw, undefined, undefined, grantObs, redacted);
    }
    if (failPolicy === 'open' && !breakerTripped(config)) {
      emit(config, { type: 'preflight_unavailable', at: iso(), cause: availCause, action: 'CONTINUE' });
      const v = unavailableVerdict({ cause: availCause, failPolicy: 'open', resolution: 'OPEN_PASSTHROUGH', action: 'CONTINUE' }, count);
      return runUnenforced(config, executeFactory, null, v, false, redacted, basis, cw, undefined, undefined, undefined, grantObs);
    }
    if (failPolicy === 'lkg') {
      const lkg = await tryLkg(config, inputFp);
      if (lkg) {
        emit(config, { type: 'preflight_unavailable', at: iso(), cause: availCause, action: lkg.action });
        const v = unavailableVerdict({ cause: availCause, failPolicy: 'lkg', resolution: 'LKG_SUBSTITUTION', action: lkg.action, lkgEnvelope: lkg.envelope }, count);
        return runUnenforced(config, executeFactory, lkg.envelope, v, false, redacted, basis, cw); // LKG NEVER enforces
      }
      // LKG unusable (dormant in v1: binding fields absent) => closed.
    }
    if (breakerTripped(config)) emit(config, { type: 'breaker_tripped', at: iso(), cause: availCause });
    const v = unavailableVerdict({ cause: availCause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
    return blocked(config, v, false, basis, cw, undefined, undefined, grantObs, redacted);
  }

  // We have a response. Read the decision (envelope-first) and verify the receipt.
  const rd = readDecision(pf.response);
  // PRESENT but unrecognised action — halt with its own code before any decision map or reconcile.
  if (rd.reason === 'EXECUTION_ACTION_UNRECOGNISED') {
    breakerRecord(config);
    return closedIntegrity(config, 'EXECUTION_ACTION_UNRECOGNISED', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }
  // Missing EA on v2 / non-legacy-1.0 — reuse closedIntegrity halt arm, cause UNREADABLE_DECISION.
  // executed:false, enforced:false (blocked()). Never remap to CONTINUE.
  if (rd.reason === 'UNREADABLE_DECISION') {
    breakerRecord(config);
    return closedIntegrity(config, 'UNREADABLE_DECISION', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }
  if (!rd.envelope) {
    // Known action but no envelope => integrity => closed.
    breakerRecord(config);
    return closedIntegrity(config, 'SCHEMA_INVALID', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }
  const envelope = rd.envelope;
  // Past unrecognised early-return: action is a closed ExecutionAction (or we treat non-closed as integrity).
  if (!isClosedAction(rd.executionAction)) {
    breakerRecord(config);
    return closedIntegrity(config, 'EXECUTION_ACTION_UNRECOGNISED', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }
  const closedAction: ExecutionAction = rd.executionAction;

  // 5. expiry check before honoring any decision.
  const expired = isExpired(envelope);

  const bindResult = await verifyEnvelope(config, envelope);
  const verified = bindResult.verified;
  const receiptVerified = !!verified;
  if (!receiptVerified) emit(config, { type: 'receipt_unverified', at: iso(), decisionId: envelope.decision_id });
  emit(config, { type: 'preflight_result', at: iso(), action: closedAction, decisionId: envelope.decision_id });

  // A receipt that fails to verify OR fails to BIND to this envelope (P0 substitution/replay/scope) is
  // an INTEGRITY attack signal => fail closed. RECEIPT_ENVELOPE_MISMATCH names a valid-but-unbound
  // receipt (e.g. a real BLOCK receipt wrapped in a forged ALLOW envelope); RECEIPT_UNVERIFIED a bad
  // signature. Both trip the breaker and STOP — the guard NEVER executes off an unbound receipt.
  if (config.verifyReceipts !== false && !receiptVerified && envelope.receipt?.token) {
    breakerRecord(config);
    return closedIntegrity(config, bindResult.cause ?? 'RECEIPT_UNVERIFIED', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }

  // ── Client-side authorization gate (P0-b/c): mirror §106/§111/§115 before honoring any action. ──
  // Threat model (bounded): without a receipt, fields including execution_action are not
  // tamper-evident — a proxy can flip them, so the gate never trusts the raw action alone and
  // reconciles decision↔action (stricter wins). With a receipt, decision_body_hash covers the
  // RFC 8785-canonical envelope (minus receipt and the hash) and the signature covers that hash,
  // so a flip without the signing key fails the bind. Either way: a PRESENT-but-unrecognised
  // action has already halted above; known actions are reconciled, safe_for_agent and degraded
  // are fail-closed, artifacts bind locally. Only allow-class + safe + non-degraded + bound runs.
  const gate = evaluateEnvelope(pf.response, envelope as unknown as Record<string, unknown>, closedAction, detection.artifacts);
  if (gate.verdict === 'fail-closed') {
    breakerRecord(config);
    return closedIntegrity(config, gate.cause, failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }
  if (gate.verdict === 'block-strict') {
    // A real (or stricter-reconciled) BLOCK / REQUIRE_APPROVAL — clean block; the factory never runs.
    const { basis } = freshnessFor(config, redacted, fctx, detection.artifacts);
    const { basis: cw } = conditionalWriteFor(config, redacted, cwctx, detection.artifacts);
    return gate.decision === 'BLOCK'
      ? blocked(config, { kind: 'BLOCK', action: 'STOP', envelope, receiptVerified }, true, basis, cw, undefined, undefined, grantObs, redacted)
      : blocked(config, { kind: 'APPROVAL', action: 'REQUEST_APPROVAL', envelope, receiptVerified }, true, basis, cw, undefined, undefined, grantObs, redacted);
  }
  const kind = gate.kind; // 'ALLOW' | 'MONITOR' — allow-class, safe, non-degraded, artifact-bound.

  // Native grant: allow-class authorize that requested a grant must RECEIVE one.
  // BLOCK/RA never mint a grant — missing token there is not EXECUTION_GRANT_MISSING.
  if (grantObs && grantObs.requested) {
    grantForCall = readExecutionGrantToken(pf.response);
    grantObs = { requested: true, arrived: !!grantForCall };
    if (!grantForCall) {
      breakerRecord(config);
      return closedIntegrity(
        config, 'EXECUTION_GRANT_MISSING', failPolicy, fctx, cwctx, redacted, detection.artifacts,
        undefined, undefined, grantObs,
      );
    }
  }
  const grantCtx: ExecutionGrantCallContext | undefined = grantObs
    ? { execution_grant: grantForCall }
    : undefined;

  // An expired decision cannot be honored fresh => closed (integrity: wrong-time state).
  if (expired) {
    breakerRecord(config);
    return closedIntegrity(config, 'SCHEMA_INVALID', failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }

  // MONITOR gate: host must ASSERT monitoring is wired (monitoringSinkWired === true) AND supply
  // onEvent. Presence of a function alone is not enough — () => {} used to unlock this gate while
  // observing nothing. The package still cannot prove delivery; the declaration is a host claim.
  // Absent declaration = unwired (breaking for onEvent-only callers; closes the empty-callback hole).
  // Declared true without onEvent = contradiction → unwired (fail closed).
  const sinkWired = config.monitoringSinkWired === true && typeof config.onEvent === 'function';
  if (kind === 'MONITOR') {
    if (sinkWired) emit(config, { type: 'monitoring_required', at: iso(), decisionId: envelope.decision_id });
    else emit(config, { type: 'monitoring_unwired', at: iso(), decisionId: envelope.decision_id });
  }

  let monitoringDelivery: MonitoringDelivery | undefined;
  let monitoringAttestation: string | undefined;
  if (kind === 'MONITOR') {
    if (!sinkWired) {
      monitoringDelivery = {
        status: 'not_delivered',
        evidence: { at: iso(), sink_kind: 'callback' },
        reason: 'sink_not_wired',
      };
    } else {
      monitoringDelivery = await deliverMonitoring({
        sink: config.monitoringSink,
        timeoutMs: config.monitoringSinkTimeoutMs,
        ackHmacKey: config.ackHmacKey,
        payload: {
          at: iso(),
          decision_id: typeof envelope.decision_id === 'string' ? envelope.decision_id : undefined,
          action: 'CONTINUE_WITH_MONITORING',
          kind: 'MONITOR',
        },
        now: iso(),
      });
      if (monitoringDelivery.status === 'not_delivered') {
        emit(config, {
          type: 'monitoring_not_delivered',
          at: iso(),
          decisionId: envelope.decision_id,
          cause: monitoringDelivery.reason,
        });
      }
    }
    monitoringAttestation = await tryIssueMonitoringAttestation({
      config: config.monitoringAttestation,
      delivery: monitoringDelivery,
      envelope,
      now: iso(),
    });
    if (sinkWired && monitoringDelivery.status === 'not_delivered' && monitoringDeliveryFailClosed(config)) {
      breakerRecord(config);
      return closedIntegrity(
        config, 'MONITORING_UNWIRED', failPolicy, fctx, cwctx, redacted, detection.artifacts,
        monitoringDelivery, monitoringAttestation, grantObs,
      );
    }
  }

  // Freshness re-check immediately before any execution (ACTIVE assessment uses preflight befores).
  const { basis: freshBasis, blockCause: freshBlock } = freshnessFor(
    config, redacted, fctx, detection.artifacts,
  );
  if (freshBlock === 'FRESHNESS_REQUIRED' || freshBlock === 'FRESHNESS_FAILED') {
    breakerRecord(config);
    return closedIntegrity(config, freshBlock, failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }

  // Conditional-write re-check immediately before enforced execution (same conjunct class as freshness).
  const { basis: cwBasis, blockCause: cwBlock } = conditionalWriteFor(config, redacted, cwctx, detection.artifacts);
  if (cwBlock === 'CONDITIONAL_WRITE_REQUIRED') {
    breakerRecord(config);
    return closedIntegrity(config, cwBlock, failPolicy, fctx, cwctx, redacted, detection.artifacts, undefined, undefined, grantObs);
  }

  // observeOnly is an EXPLICIT report-only opt-in: execute but never enforce (the one sanctioned
  // unenforced-execution mode alongside failPolicy=open; both are documented opt-ins, not the default).
  if (config.observeOnly) {
    emit(config, { type: 'observe_only_passthrough', at: iso(), action: closedAction });
    const verdict: GuardVerdict = kind === 'ALLOW'
      ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified }
      : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
    return runUnenforced(config, executeFactory, envelope, verdict, true, redacted, freshBasis, cwBasis, monitoringDelivery, monitoringAttestation, grantCtx, grantObs);
  }

  // Advisory CWM (sink WAS wired): delivery failed but failPolicy/observeOnly said not to block.
  // Proceed unenforced with the reason visible. Unwired MONITOR still falls through to
  // MONITORING_UNWIRED (CE-CC-04). ENFORCING not_delivered already returned closedIntegrity.
  if (kind === 'MONITOR' && sinkWired && monitoringDelivery && monitoringDelivery.status === 'not_delivered') {
    const degraded: GuardVerdict = { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
    return runUnenforced(
      config, executeFactory, envelope, degraded, true, redacted, freshBasis, cwBasis, monitoringDelivery, monitoringAttestation, grantCtx, grantObs,
    );
  }

  // ── enforced ⟺ executed INVARIANT (contract-triggering path): execute ONLY when we can ENFORCE. ──
  // enforceable = a bound-verified receipt AND (MONITOR) a wired sink. Anything else FAILS CLOSED —
  // the guard NEVER runs the factory *as enforced* on a contract change. Explicit opt-downs
  // ('warn' mismatch, requireExecutionStateMatch:false) run unenforced (enforced:false) so the
  // field tells the truth. Closes CE-EP-06 (no receipt), CE-EP-08 (verifyReceipts:false),
  // CE-CC-04 (MONITOR without a monitoring sink). Freshness + conditional-write already applied.
  const enforceable = receiptVerified && (kind === 'ALLOW' || sinkWired);
  if (enforceable) {
    // T2 fingerprint recheck immediately before executeFactory (host-independent crbundle.v1
    // over CURRENT artifacts). Refuses on *observed* execution-state drift — this is not a
    // full TOCTOU close (recheck and executeFactory are not atomic; no observed_token_at_commit
    // CAS). guard@8: default ON (absent → true). Explicit opt-down: false | 'warn'.
    const execStateMode = config.requireExecutionStateMatch === undefined
      ? true
      : config.requireExecutionStateMatch;
    // false opt-down: T2 does not run. Proceed-on-drift remains, but enforced:false —
    // the check was not performed (NOT_CHECKED). Same runUnenforced arm as 'warn' mismatch.
    if (execStateMode === false) {
      emit(config, {
        type: 'execution_state_check_disabled',
        at: iso(),
        decisionId: envelope.decision_id,
        cause: 'requireExecutionStateMatch_false',
      });
      const offVerdict: GuardVerdict = kind === 'ALLOW'
        ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified }
        : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
      return runUnenforced(
        config, executeFactory, envelope, offVerdict, true, redacted, freshBasis, cwBasis, monitoringDelivery, monitoringAttestation, grantCtx, grantObs,
      );
    }
    const et = checkExecutionTimeFingerprint({
      artifacts: detection.artifacts,
      context: {
        operation: config.operation ?? 'tool_call',
        environment: config.environment,
      },
      envelope: envelope as unknown as Record<string, unknown>,
    });
    if (!et.match) {
      const unmeasurable = isUnmeasurableExecutionStateReason(et.reason);
      if (execStateMode === true) {
        breakerRecord(config);
        return closedIntegrity(
          config,
          unmeasurable ? 'EXECUTION_STATE_UNMEASURABLE' : 'EXECUTION_STATE_DRIFT',
          failPolicy,
          fctx,
          cwctx,
          redacted,
          detection.artifacts,
          undefined,
          undefined,
          grantObs,
        );
      }
      // warn opt-down: emit, then run unenforced — a measured mismatch is not an enforced run.
      if (unmeasurable) {
        emit(config, {
          type: 'execution_state_unmeasurable',
          at: iso(),
          decisionId: envelope.decision_id,
          current_fingerprint: et.current_fingerprint,
          authorized_fingerprint: et.authorized_fingerprint,
          reason: et.reason,
          note: EXECUTION_STATE_UNMEASURABLE_NOTE,
        });
      } else {
        emit(config, {
          type: 'execution_state_drift_observed',
          at: iso(),
          decisionId: envelope.decision_id,
          current_fingerprint: et.current_fingerprint,
          authorized_fingerprint: et.authorized_fingerprint,
          reason: et.reason,
        });
      }
      const warnVerdict: GuardVerdict = kind === 'ALLOW'
        ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified }
        : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
      return runUnenforced(
        config, executeFactory, envelope, warnVerdict, true, redacted, freshBasis, cwBasis, monitoringDelivery, monitoringAttestation, grantCtx, grantObs,
      );
    }
    const approved: ApprovedVerdict = kind === 'ALLOW'
      ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified: true }
      : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified: true };
    return runEnforced(config, executeFactory, approved, redacted, freshBasis, cwBasis, monitoringDelivery, monitoringAttestation, grantCtx, grantObs);
  }
  breakerRecord(config);
  return closedIntegrity(
    config,
    receiptVerified ? 'MONITORING_UNWIRED' : 'RECEIPT_MISSING',
    failPolicy,
    fctx,
    cwctx,
    redacted,
    detection.artifacts,
    monitoringDelivery,
    monitoringAttestation,
    grantObs,
  );
}

function closedIntegrity<T>(
  config: GuardConfig,
  cause: IntegrityCause,
  failPolicy: 'closed' | 'open' | 'lkg',
  fctx: FreshnessCallContext,
  cwctx: ConditionalWriteCallContext,
  redacted: ToolCallDescriptor,
  arts?: Artifact[],
  monitoring_delivery?: MonitoringDelivery,
  monitoring_attestation?: string,
  grantObs?: ExecutionGrantObservation,
): GuardOutcome<T> {
  const count = (breakers.get(config)?.fails.length) ?? 1;
  emit(config, { type: 'breaker_tripped', at: iso(), cause });
  const v = unavailableVerdict({ cause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
  const { basis } = freshnessFor(config, redacted, fctx, arts);
  const { basis: cw } = conditionalWriteFor(config, redacted, cwctx, arts);
  return blocked(config, v, false, basis, cw, monitoring_delivery, monitoring_attestation, grantObs, redacted);
}

function isExpired(envelope: DecisionResultEnvelope): boolean {
  const exp = envelope.expires_at;
  if (typeof exp !== 'string') return false;
  const t = Date.parse(exp);
  return Number.isFinite(t) && t < Date.now();
}

/** LKG substitution attempt. Dormant in v1: binding fields (ruleset_hash/environment/operation/
 * audience) are absent from decision-result.v1, so any binding that cannot be evaluated => UNUSABLE. */
async function tryLkg(config: GuardConfig, inputFp: string): Promise<{ envelope: ReceiptVerifiedEnvelope; action: 'CONTINUE' | 'CONTINUE_WITH_MONITORING' } | null> {
  if (!config.lkg) return null;
  let cached: DecisionResultEnvelope | null;
  try { cached = await config.lkg.get(inputFp); } catch { return null; }
  if (!cached) return null;
  // Receipt verification + BINDING is UNCONDITIONAL for LKG (verifyReceipts:false => cannot brand =>
  // unusable). An LKG envelope whose receipt does not bind to it (substitution) is also unusable.
  const { verified } = await verifyEnvelope(config, cached);
  if (!verified) return null;
  // Eligibility (rule 15): decision ALLOW|WARN, unexpired, age<lkgMaxAgeMs, fingerprint + ruleset_hash
  // + environment + operation + audience all match. Any binding that cannot be evaluated => UNUSABLE.
  const dec = (cached.decision as string) ?? '';
  if (dec !== 'ALLOW' && dec !== 'WARN') return null;
  if (isExpired(cached)) return null;
  const maxAge = config.lkgMaxAgeMs ?? 900000;
  const evalAt = Date.parse(cached.evaluated_at);
  if (Number.isFinite(evalAt) && Date.now() - evalAt > maxAge) return null;
  // Binding fields are NOT present in the frozen schema => cannot be evaluated => UNUSABLE (closed).
  const bindings: Array<unknown> = [
    (cached as unknown as Record<string, unknown>).ruleset_hash,
    (cached as unknown as Record<string, unknown>).environment,
    (cached as unknown as Record<string, unknown>).operation,
    (cached as unknown as Record<string, unknown>).audience,
  ];
  if (bindings.some((b) => b === undefined)) return null; // any absent binding => UNUSABLE => closed
  const action = dec === 'ALLOW' ? 'CONTINUE' : 'CONTINUE_WITH_MONITORING';
  return { envelope: verified, action };
}
