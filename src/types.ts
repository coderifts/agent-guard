/**
 * @coderifts/agent-guard — public types (FROZEN security core, agent-guard-api v1.0, 2026-07-26).
 *
 * Transcribed VERBATIM from agent-guard-api.FROZEN-v1.0.md § Core API. The discriminated unions
 * encode the frozen invariants at the type level (tsc-verified): TOCTOU (ExecuteFactory signature),
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
  onEvent?: (e: GuardEvent) => void;         // wrapped; never throws
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

export type GuardOutcome<T> =
  // enforced:true is its OWN arm — only ApprovedVerdict + receiptVerified:true + preflighted:true reach it.
  | { executionAttempted: true;  executed: true;  enforced: true;  result: T;   verdict: ApprovedVerdict; preflighted: true }
  // executed but NOT enforced (SKIPPED / observeOnly / open- or lkg-UNAVAILABLE pass-through):
  | { executionAttempted: true;  executed: true;  enforced: false; result: T;   verdict: GuardVerdict; preflighted: boolean }
  // guard blocked before the factory ran:
  | { executionAttempted: false; executed: false; enforced: false;              verdict: GuardVerdict; preflighted: boolean }
  // factory threw AFTER a fully-enforced approval (side effect may have landed; enforced passes through per rule 11):
  | { executionAttempted: true;  executed: false; enforced: true;  error: unknown; verdict: ApprovedVerdict; preflighted: true }
  // factory threw after an UNENFORCED execution (SKIPPED / observeOnly / open- or lkg-pass-through):
  | { executionAttempted: true;  executed: false; enforced: false; error: unknown; verdict: GuardVerdict; preflighted: boolean };
// On EVERY arm (success AND factory-threw), enforced:true correlates strictly
// with ApprovedVerdict + receiptVerified:true + preflighted:true.

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
  | 'DECISION_INCONSISTENT'       // decision↔execution_action mismatch, missing decision, or safe_for_agent=false on allow-class
  | 'ANALYSIS_DEGRADED'           // analysis_complete=false / degraded_reasons / degraded / coverage_gap (§111)
  | 'ARTIFACT_MISMATCH'           // envelope artifact_digest / input_fingerprint ≠ locally-recomputed value
  | 'RECEIPT_MISSING'             // contract-triggering executable decision with no verifiable receipt (no unenforced execute)
  | 'MONITORING_UNWIRED';         // CONTINUE_WITH_MONITORING but no onEvent sink → cannot enforce monitoring
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
          |'monitoring_required'|'monitoring_unwired'|'receipt_unverified'
          |'breaker_tripped'|'observe_only_passthrough'|'factory_error';
      at: string; correlationId?: string; decisionId?: string;
      action?: ExecutionAction; cause?: string; durationMs?: number;
      signals?: string[]; detectorVersion?: string };
