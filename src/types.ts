/**
 * @coderifts/agent-guard — public types (FROZEN security core, agent-guard-api v1.0, 2026-07-26).
 *
 * Transcribed VERBATIM from agent-guard-api.FROZEN-v1.0.md § Core API. The discriminated unions
 * encode the frozen invariants at the type level (tsc-verified): eager-execution ordering — NOT
 * TOCTOU proper — (ExecuteFactory signature: the mutation cannot be built before the verdict; the
 * measurement-to-commit race still needs a host conditional write),
 * retry-footgun (executionAttempted split), enforced-bypass (ApprovedVerdict + receiptVerified on
 * every arm), integrity-fail-open (discriminated UnavailableVerdict), unverified-envelope execution
 * (branded ReceiptVerifiedEnvelope). Fail-closed by default.
 */

import type { CodeRifts, DecisionResultEnvelope, ExecutionAction, Artifact } from '@coderifts/sdk';

export type { CodeRifts, DecisionResultEnvelope, ExecutionAction, Artifact } from '@coderifts/sdk';

// A DecisionResultEnvelope whose receipt has been verified by the mandatory
// verifier. The brand is unforgeable: only the guard's verify step returns it.
export type ReceiptVerifiedEnvelope =
  DecisionResultEnvelope & { readonly __receiptVerified: unique symbol };

export interface GuardConfig {
  client: CodeRifts;
  failPolicy?: 'closed' | 'open' | 'lkg';   // default 'closed'
  timeoutMs?: number;                        // per attempt; default 2000
  retries?: number;                          // transport retries; default 1
  totalBudgetMs?: number;                    // hard ceiling; default 4500
  maxUnavailablePerWindow?: number;          // open->closed breaker count; default 3
  breakerWindowMs?: number;                  // breaker window (time-based, not consecutive); default 60000
  maxPayloadBytes?: number;                  // request-attributable cap; over => never permissive; default 1_000_000
  environment?: string;                      // bound into preflight + LKG match
  operation?: string;                        // default 'tool_call'; bound into LKG match
  audience?: string;                         // optional; bound into LKG match
  detector?: TriggerDetector;                // default builtinDetector (fail-safe, versioned)
  requireExplicitArtifacts?: boolean;        // strict SKIP gate; default false
  lkg?: LkgStore;                            // required iff failPolicy==='lkg'
  lkgMaxAgeMs?: number;                      // default 900000 (15min)
  observeOnly?: boolean;                     // preflight + report; executes regardless but marks enforced:false; default false
  redactor?: (d: ToolCallDescriptor) => ToolCallDescriptor; // D4: runs BEFORE fingerprint/anything leaves the process
  verifyReceipts?: boolean;                  // verify returned + lkg receipt signatures; default true
  onEvent?: (e: GuardEvent) => void;         // wrapped; never throws; lifecycle emitter only — NOT proof of monitoring
  /**
   * Host ASSERTION that a monitoring sink is intentionally wired for WARN /
   * CONTINUE_WITH_MONITORING. Required together with a present `onEvent` for MONITOR to proceed.
   *
   * - `true`  + `onEvent` present  → monitoring treated as wired (gate opens for MONITOR).
   * - `true`  + no `onEvent`       → contradiction → fail-closed MONITORING_UNWIRED.
   * - absent / `false`             → monitoring treated as unwired (even if `onEvent` exists).
   *
   * This is a claim the host records. Measured delivery (ack) lives on `monitoringSink`
   * and is recorded as `monitoring_delivery` on the CWM outcome. A no-op `onEvent`
   * remains indistinguishable from a real logger; it yields `sent_unacked`.
   */
  monitoringSinkWired?: boolean;
  /**
   * Optional dedicated CWM delivery sink (callback that may return an ack, or HTTP POST).
   * Distinct from `onEvent` (lifecycle, never throws). Absent → `sent_unacked` when the
   * MONITOR gate is otherwise wired (claim + onEvent only; no ack semantics).
   */
  monitoringSink?: import('./monitoring-delivery.js').MonitoringSink;
  /** Per-sink invocation timeout. Default 5000ms. */
  monitoringSinkTimeoutMs?: number;
  /**
   * Optional HMAC key for ack verification (callback signature field or HTTP ack header).
   * No key → no verification, no penalty. Invalid HMAC → `not_delivered`.
   */
  ackHmacKey?: string | Buffer;
  /** Forwarded from withCodeRifts. Used with failPolicy/observeOnly for delivery fail-closed teeth. */
  profile?: 'ENFORCING_STRICT';
  /**
   * Optional prior chain-receipt token for the preflight `previous_receipt` field (server hashes it
   * into the signed `prev` slot). Host-owned only: a string the host updates between calls, or a
   * zero-arg getter the host supplies. The guard reads it once per preflight and does NOT store,
   * advance, or remember it — the package remains stateless across calls.
   */
  previousReceipt?: string | (() => string | undefined | null);
  /**
   * Optional host resolver for freshness recompute (opt-in). The RUNNER invokes this and passes
   * VALUES into guardToolCall — the pure assessFreshness path never calls it.
   * Absent → freshness wiring NOT_CONFIGURED (existing integrations keep working).
   */
  resolvePriorContent?: import('./freshness.js').PriorContentResolver;
  /**
   * Policy: when true, a write-style call without ACTIVE freshness measurement does not proceed
   * (fail-closed at the permission). Default false — API remains opt-in.
   */
  requireFreshness?: boolean;
  /** Forwarded into assessFreshness when tree/contract STALE_CONTEXT is evaluated. */
  allowStaleContext?: boolean;
  /**
   * Policy: when true, a write-style call must report conditional_write:true (host conditioned
   * the mutation on a version token). false / not_reported → no enforced:true.
   * Default false — API remains opt-in. This package never writes; it only reports and refuses.
   */
  requireConditionalWrite?: boolean;
  /**
   * Policy (ID842): T2 execution-time fingerprint recheck immediately before executeFactory.
   * Host-independent — recomputes crbundle.v1 over CURRENT artifacts; does not trust a host-supplied
   * expected_fingerprint for the T2 measurement.
   *
   * Tri-state (guard@8: default fail-closed; `'warn'` / `false` are explicit opt-down):
   *   - true / absent   → enforce (default) — mismatch → EXECUTION_STATE_DRIFT (STOP);
   *                       missing authorized fp / missing artifacts → EXECUTION_STATE_UNMEASURABLE (STOP)
   *   - 'warn'          → emit then run unenforced (enforced:false on mismatch)
   *   - false           → off — no T2 recheck
   *
   * Recheck refuses on *observed* execution-state drift. It does not make execute
   * atomic with the measurement (no observed_token_at_commit CAS).
   */
  requireExecutionStateMatch?: boolean | 'warn';
  /**
   * T3 post-commit observation. Default ON (absent → true). false → not_observed +
   * commit_observation_check_disabled. Never changes `enforced`.
   * Under `profile: 'ENFORCING_STRICT'`, false is a construction abort (same class as
   * requireExecutionStateMatch:false).
   */
  requireCommitObservation?: boolean;
  /**
   * S6 auto-recheck. Default OFF. When set (with applyFix), a BLOCK that carries
   * remediation_transaction may re-preflight after the HOST applies a fix.
   * Forwarded from withCodeRifts({ autoRecheck }).
   */
  autoRecheck?: import('./auto-recheck.js').AutoRecheckConfig;
  /**
   * S1 auto-derive. Default OFF. When true (or `{ readers }`), the wrap layer
   * fills before/after from current-state readers + the call's intended write
   * when the host did not supply args.artifacts. Not a fingerprint preimage field.
   */
  autoDerive?: boolean | import('./auto-derive.js').AutoDeriveConfig;
  /**
   * S2-F2a R3. Customer-pinned executor key registry. When set, a CAS outcome
   * that carries an attestation token is verified (sdk verifyExecutionAttestation).
   * Observation-side only — never a verdict/preimage field.
   */
  executorAttestation?: import('./cas-attestation.js').ExecutorAttestationConfig;
  /**
   * Opt-in CWM monitoring attestation. Host supplies kid + sign(bytes) — never a raw key.
   * When set and a CWM arm ran, the outcome carries `monitoring_attestation` (cr.monitor.attest.v1).
   * Absent → today's CWM outcome is byte-identical (no field). Observation-side only.
   */
  monitoringAttestation?: import('./monitoring-attestation.js').MonitoringAttestationConfig;
  /**
   * Optional host system-prompt / instruction text. Observation only — never a verdict
   * input, never a preimage field.
   *
   * - supplied + policy marker found → outcome.policy_presence = 'detected' (silent)
   * - supplied + marker absent → 'absent' + a once-per-process warn
   * - not supplied → field omitted (semantically 'unknown'; no warn; byte-identical)
   */
  systemPrompt?: string;
  /**
   * Composition-scoped coverage observer (withCodeRifts). Observation only —
   * never a verdict input, never a preimage field. Absent → no coverage_observed
   * on the outcome/proof (byte-identical to 9.4.0 for direct guardToolCall).
   */
  coverageObserver?: import('./coverage-observed.js').CoverageObserver;
}

export interface ToolCallDescriptor {
  toolName: string;
  arguments: unknown;
  artifacts?: Artifact[];
  nonContract?: boolean;                     // strict-mode assertion; overridden by any real signal
  intent?: string;                           // UNTRUSTED: adds triggers, never removes
  filesTouched?: string[];
  diff?: string;
}

// D1 — the mutating work is created ONLY after the verdict, by the factory.
// A pre-constructed (eager) promise cannot be smuggled in: the factory is
// invoked by the guard after preflight, and only when the action permits.
export type ExecuteFactory<T> = (envelope: DecisionResultEnvelope | null, redactedCall: ToolCallDescriptor) => Promise<T>;

// D3/D6 — executed + enforced discriminate every path; errors are captured.
// ApprovedVerdict: only a receipt-verified live ALLOW/MONITOR can carry enforced:true.
export type ApprovedVerdict =
  ( { kind: 'ALLOW'; action: 'CONTINUE'; envelope: DecisionResultEnvelope }
  | { kind: 'MONITOR'; action: 'CONTINUE_WITH_MONITORING'; envelope: DecisionResultEnvelope } )
  & { receiptVerified: true };

// GuardExecutionProof is defined in execution-proof.ts (assembled only from guard-observed state).
import type { GuardExecutionProof } from './execution-proof.js';
export type { GuardExecutionProof, ExecutionResultHash } from './execution-proof.js';
import type { FreshnessBasis, FreshnessCallContext } from './freshness.js';
export type { FreshnessBasis, FreshnessWiringState, FreshnessCallContext, PriorContentResolver } from './freshness.js';
import type { ConditionalWriteBasis, ConditionalWriteCallContext } from './conditional-write.js';
export type {
  ConditionalWriteBasis,
  ConditionalWriteCallContext,
  ConditionalWriteReport,
  VersionedContent,
  VersionToken,
} from './conditional-write.js';
import type { CommitObservation } from './commit-observation.js';
export type {
  CommitObservation,
  CommitObservationStatus,
  CommitHostAttestation,
  CommitObservationBlast,
} from './commit-observation.js';
import type { MonitoringDelivery } from './monitoring-delivery.js';
export type {
  MonitoringDelivery,
  MonitoringDeliveryStatus,
  MonitoringDeliveryEvidence,
  MonitoringSink,
  MonitoringSinkHttp,
  MonitoringSinkCallback,
  MonitoringSinkPayload,
} from './monitoring-delivery.js';

/**
 * Runner-collected context for guardToolCall (4th arg).
 * FreshnessCallContext shape (wiring required) remains valid — conditional-write fields are optional.
 * Default conditional_write when omitted: 'not_reported'.
 */
export type GuardToolCallContext = FreshnessCallContext & ConditionalWriteCallContext;

type GuardOutcomeCore<T> =
  // enforced:true is its OWN arm — only ApprovedVerdict + receiptVerified:true + preflighted:true reach it.
  | { executionAttempted: true;  executed: true;  enforced: true;  result: T;   verdict: ApprovedVerdict; preflighted: true; proof: GuardExecutionProof; freshness: FreshnessBasis; conditional_write: ConditionalWriteBasis; commit_observation: CommitObservation; monitoring_delivery?: MonitoringDelivery }
  // executed but NOT enforced (SKIPPED / observeOnly / open- or lkg-UNAVAILABLE pass-through):
  | { executionAttempted: true;  executed: true;  enforced: false; result: T;   verdict: GuardVerdict; preflighted: boolean; proof: GuardExecutionProof; freshness: FreshnessBasis; conditional_write: ConditionalWriteBasis; commit_observation: CommitObservation; monitoring_delivery?: MonitoringDelivery }
  // guard blocked before the factory ran:
  | { executionAttempted: false; executed: false; enforced: false;              verdict: GuardVerdict; preflighted: boolean; proof: GuardExecutionProof; freshness: FreshnessBasis; conditional_write: ConditionalWriteBasis; commit_observation: CommitObservation; monitoring_delivery?: MonitoringDelivery }
  // factory threw AFTER a fully-enforced approval (side effect may have landed; enforced passes through per rule 11):
  | { executionAttempted: true;  executed: false; enforced: true;  error: unknown; verdict: ApprovedVerdict; preflighted: true; proof: GuardExecutionProof; freshness: FreshnessBasis; conditional_write: ConditionalWriteBasis; commit_observation: CommitObservation; monitoring_delivery?: MonitoringDelivery }
  // factory threw after an UNENFORCED execution (SKIPPED / observeOnly / open- or lkg-pass-through):
  | { executionAttempted: true;  executed: false; enforced: false; error: unknown; verdict: GuardVerdict; preflighted: boolean; proof: GuardExecutionProof; freshness: FreshnessBasis; conditional_write: ConditionalWriteBasis; commit_observation: CommitObservation; monitoring_delivery?: MonitoringDelivery };

/** S6 + S1 + F2a additive observation (optional). Absent when those wrap layers did not run. */
export type GuardOutcome<T> = GuardOutcomeCore<T>
  & import('./auto-recheck.js').RecheckObservation
  & import('./auto-derive.js').AutoDeriveObservation
  & { cas_evidence?: import('./cas-attestation.js').CasEvidence }
  & {
    /**
     * ENFORCING_STRICT only (P0-3). Existing CasAttestation.derived names.
     * Absent on non-strict outcomes so those stay byte-identical to 9.0.0.
     */
    commit_label?: import('./cas-attestation.js').CommitLabel;
    commit_evidence_reason?: 'commit_evidence_missing';
    /** cr.monitor.attest.v1 token. Present only when monitoringAttestation was configured on a CWM arm. */
    monitoring_attestation?: string;
    /**
     * Observation only: whether the host-supplied systemPrompt contains the
     * canonical policy marker. Omitted when systemPrompt was not supplied
     * (unknown; byte-identical to previous outcomes). Never a verdict input.
     */
    policy_presence?: import('./policy.js').PolicyPresence;
    /**
     * Observed tool-traffic coverage for this withCodeRifts run. Omitted when no
     * observer is wired (direct guardToolCall). Observation only; not a preimage.
     */
    coverage_observed?: import('./coverage-observed.js').CoverageObserved;
  };
// On EVERY arm (success AND factory-threw), enforced:true correlates strictly
// with ApprovedVerdict + receiptVerified:true + preflighted:true.
// proof is always present and is guard-produced (not caller-writable).
// freshness is always present: per-call forensic basis (NOT_CONFIGURED | DEGRADED | ACTIVE+assessment).
// conditional_write is always present: three-valued host report (default not_reported).
// commit_observation is always present (T3): not_observed when no reader / factory did not run / opt-out.
// monitoring_delivery is present on CWM/MONITOR arms only (tri-state; omitted on ALLOW/SKIPPED/etc).

export type GuardVerdict =
  | { kind: 'ALLOW';    action: 'CONTINUE';                 envelope: DecisionResultEnvelope; receiptVerified: boolean }
  | { kind: 'MONITOR';  action: 'CONTINUE_WITH_MONITORING'; envelope: DecisionResultEnvelope; receiptVerified: boolean }
  | { kind: 'APPROVAL'; action: 'REQUEST_APPROVAL';         envelope: DecisionResultEnvelope; receiptVerified: boolean }
  | { kind: 'BLOCK';    action: 'STOP';                     envelope: DecisionResultEnvelope; receiptVerified: boolean }
  | { kind: 'SKIPPED';  reason: 'NOT_A_CONTRACT_CALL';      signals: string[]; detectorVersion: string }
  | UnavailableVerdict;

// UNAVAILABLE: configured failPolicy and RESOLVED outcome are distinct fields.
// action is bound to resolution; an IntegrityCause can only resolve CLOSED.
export type UnavailableVerdict = { kind: 'UNAVAILABLE';
    decisionMissing: true; unavailableCount: number } & (
  // integrity => always closed, under ANY configured policy (breaker/integrity):
  | { cause: IntegrityCause;    failPolicy: 'closed'|'open'|'lkg'; resolution: 'CLOSED'; action: 'STOP' }
  // availability resolved closed (closed policy, or open policy after breaker trip):
  | { cause: AvailabilityCause; failPolicy: 'closed'|'open'|'lkg'; resolution: 'CLOSED'; action: 'STOP' }
  // availability + open, within breaker — failPolicy MUST be 'open':
  | { cause: AvailabilityCause; failPolicy: 'open'; resolution: 'OPEN_PASSTHROUGH'; action: 'CONTINUE' }
  // availability + lkg — failPolicy MUST be 'lkg'; the envelope is TYPE-verified:
  | { cause: AvailabilityCause; failPolicy: 'lkg'; resolution: 'LKG_SUBSTITUTION';
      action: 'CONTINUE' | 'CONTINUE_WITH_MONITORING'; lkgEnvelope: ReceiptVerifiedEnvelope }
);

// AVAILABILITY causes MAY fall under failPolicy (the server is reachable-ish
// but slow/down); INTEGRITY causes mean the system state is wrong and ALWAYS
// resolve closed + trip the breaker, regardless of failPolicy.
export type AvailabilityCause = 'TIMEOUT' | 'NETWORK' | 'SERVER_ERROR' | 'RATE_LIMITED';
export type IntegrityCause =
  'INVALID_RESPONSE' | 'UNSUPPORTED_VERSION' | 'SCHEMA_INVALID'
  | 'RECEIPT_UNVERIFIED' | 'DETECTOR_ERROR' | 'CONFIG_ERROR'
  | 'PAYLOAD_TOO_LARGE'   // 413 or local maxPayloadBytes cap
  | 'REQUEST_REJECTED'    // 422 and other request-attributable rejections
  | 'RECEIPT_ENVELOPE_MISMATCH'   // P0-a: valid receipt NOT bound to THIS envelope (substitution/replay/scope)
  // P0-b/c client-enforcement gates (§106/§111/§115 mirrored client-side):
  | 'DECISION_INCONSISTENT'       // decision↔execution_action mismatch (known action disagrees), missing decision, or safe_for_agent=false on allow-class
  | 'EXECUTION_ACTION_UNRECOGNISED' // execution_action PRESENT but outside the closed set (version skew) — not the same as missing; not a decision↔action mismatch
  | 'UNREADABLE_DECISION'         // missing execution_action on a v2 / non-legacy-1.0 body — never map ALLOW→CONTINUE
  | 'ANALYSIS_DEGRADED'           // analysis_complete=false / degraded_reasons / degraded / coverage_gap (§111)
  | 'ARTIFACT_MISMATCH'           // envelope artifact_digest / input_fingerprint ≠ locally-recomputed value
  | 'RECEIPT_MISSING'             // contract-triggering executable decision with no verifiable receipt (no unenforced execute)
  | 'MONITORING_UNWIRED'          // CONTINUE_WITH_MONITORING but monitoring not declared+callback-agreeing → cannot enforce monitoring
  | 'MISSING_ARTIFACT_CONTENT'   // detector triggered (preflight required) but no analyzable artifacts[] with before/after → fail closed LOCALLY (developer must supply content), never send an empty list to the server
  | 'FRESHNESS_REQUIRED'         // write-style (or requireFreshness) without ACTIVE measurement (NOT_CONFIGURED / DEGRADED)
  | 'FRESHNESS_FAILED'           // ACTIVE measurement ran; assessFreshness failClosed (TARGET_MUTATED / STALE / TAMPER / UNKNOWN)
  | 'CONDITIONAL_WRITE_REQUIRED' // write-style + requireConditionalWrite but host report is false or not_reported
  | 'EXECUTION_STATE_DRIFT'      // ID842: T2 current artifacts crbundle.v1 fingerprint ≠ receipt-authorized fingerprint
  | 'EXECUTION_STATE_UNMEASURABLE' // T2 cannot assert (missing authorized fingerprint or missing artifacts) — not silent ALLOW
export type UnavailableCause = AvailabilityCause | IntegrityCause;

// D-detector — fail-safe + versioned (the trust core; the Grok corpus of 68
// vectors is its mandatory fixture set).
export interface TriggerDetector {
  version: string;
  detect(call: ToolCallDescriptor):
    { trigger: boolean; artifacts: Artifact[]; signals: string[]; confident: boolean };
}

export interface LkgStore {
  // get returns a plain envelope; the guard's mandatory verify step brands it
  // as ReceiptVerifiedEnvelope before it can populate an LKG_SUBSTITUTION arm.
  // With verifyReceipts:false the verify step cannot brand it => LKG unusable => closed.
  get(inputFingerprint: string): Promise<DecisionResultEnvelope | null>;
  put(env: DecisionResultEnvelope): Promise<void>;
}

export type GuardEvent =
  | { type: 'preflight_start'|'preflight_result'|'preflight_unavailable'
          |'detection_skip'|'execution_started'|'execution_skipped'
          |'monitoring_required'|'monitoring_unwired'|'monitoring_not_delivered'|'receipt_unverified'
          |'breaker_tripped'|'observe_only_passthrough'|'factory_error'
          |'artifact_content_missing'    // detector triggered but no analyzable artifacts[] → local fail-closed
          |'execution_state_check_disabled' // requireExecutionStateMatch:false — T2 not run; enforced:false
          |'commit_observation_check_disabled'; // requireCommitObservation:false — T3 not run; enforced unchanged
      at: string; correlationId?: string; decisionId?: string;
      action?: ExecutionAction; cause?: string; durationMs?: number;
      signals?: string[]; detectorVersion?: string }
  /** ID842 step 3a — warn-mode only: real T2 fingerprint drift observed; execution still proceeds. */
  | { type: 'execution_state_drift_observed'; at: string; decisionId?: string;
      current_fingerprint: string | null; authorized_fingerprint: string | null; reason: string }
  /**
   * ID842 warn-mode only: T2 recheck could not measure (nothing to compare). Quiet — not evidence of
   * drift and not evidence of safety. Distinct from `execution_state_drift_observed` so hosts can
   * filter noise before a future default-to-warn flip.
   */
  | { type: 'execution_state_unmeasurable'; at: string; decisionId?: string;
      current_fingerprint: string | null; authorized_fingerprint: string | null; reason: string;
      note: string }
  /** T3: observed post-write state ≠ authorized after / intended post token. Not a BLOCK. enforced unchanged. */
  | { type: 'commit_observed_drift'; at: string; decisionId?: string;
      observed_fp?: string; expected_fp?: string; token?: string }
  /**
   * S6: one re-preflight attempt after applyFix. from_fp/to_fp are observation-only
   * (not a preimage). cause set when applyFix threw.
   */
  | { type: 'recheck_attempt'; at: string; attempt: number; decisionId?: string;
      from_fp?: string | null; to_fp?: string | null; cause?: string }
  /**
   * S1: auto-derive reader threw or timed out. Wrap falls back to today's fragment path.
   * Observation-only — not a BLOCK on derivation itself.
   */
  | { type: 'derive_failed'; at: string; cause: string };
