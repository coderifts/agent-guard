/**
 * Guard-produced execution proof block.
 *
 * Assembled ONLY from state the guard itself observed while handling a call. Callers cannot supply
 * fields into this object: builders take GuardOutcome-internal facts, not a host "proof" option.
 * The returned object is deeply frozen so post-return mutation of proof fields is rejected.
 *
 * What this block proves (when the corresponding fields are present):
 *  - preflight happened          → preflighted + decision_id
 *  - receipt was fresh           → receipt.status === 'VERIFIED_CURRENT' + expires_at
 *  - scope matched               → binds_to.operation + currently_authorized
 *  - ran on the guarded path     → execution.enforced === true (runtime-asserted only with
 *                                  receipt.verified + preflighted; same invariant the types encode)
 *  - artifact checked vs executed → change_fp is WHAT WAS CHECKED; execution_result_hash is NOT a
 *                                  general claim that the applied side effect matched that fp
 *
 * What this block must never claim: that the change is safe, that the host cannot bypass the
 * package, or that an absent field means compliance. Those limits are explicit on every block.
 */

import { createHash } from 'node:crypto';
import type { GuardVerdict } from './types.js';
import type { CommitObservation } from './commit-observation.js';
import type { MonitoringDelivery } from './monitoring-delivery.js';
import type { CasEvidence } from './cas-attestation.js';

/** Machine-readable schema id for this block. */
export const EXECUTION_PROOF_SPEC = 'guard-execution-proof.v1' as const;

/**
 * Hash of the factory return value — only when the value is already byte-stable.
 *
 * Not hashed (and the block says so) when:
 *  - the factory did not run / threw / produced no result
 *  - the result is an object, array, number, boolean, null, bigint, symbol, function — any of these
 *    would require a serialization choice (key order, undefined, non-JSON values) that reformats
 *    the value rather than hashing the bytes the factory returned
 *
 * A hash of a string/Buffer does NOT prove the contract artifacts applied match change_fp_checked.
 * That gap is named on limits.
 */
export type ExecutionResultHash =
  | { status: 'hashed'; algorithm: 'sha256'; value: string }
  | {
      status: 'not_hashed';
      reason:
        | 'not_executed'
        | 'execution_threw'
        | 'result_not_byte_stable'
        | 'result_type_unsupported';
    };

export type GuardExecutionProof = {
  proof_spec: typeof EXECUTION_PROOF_SPEC;
  /** Observed: true iff this call completed a preflight round-trip that produced a decision envelope. */
  preflighted: boolean;
  /** Observed from the decision envelope when preflighted; null otherwise. */
  decision_id: string | null;
  receipt: {
    /**
     * Observed: true only when the guard's verify+bind step branded the envelope
     * (requires valid signature, status VERIFIED_CURRENT, body hash + fp + scope match).
     */
    verified: boolean;
    /**
     * Observed derivation: bind requires status === 'VERIFIED_CURRENT', so verified ⇒ this value.
     * null when the receipt was not verified (or no receipt path).
     */
    status: 'VERIFIED_CURRENT' | null;
    /** Observed from the envelope when present; null when no envelope. */
    expires_at: string | null;
  };
  /**
   * Observed from the authenticated envelope fields when an envelope exists.
   * change_fp is the fingerprint of WHAT WAS CHECKED (preflighted), not of what the factory applied.
   * null when no envelope (SKIPPED / unavailable without envelope).
   */
  binds_to: {
    operation: string | null;
    change_fp: string | null;
  } | null;
  /**
   * Observed at verify time: true iff receipt.verified (VERIFIED_CURRENT + bind).
   * false when an envelope/receipt was present but did not verify.
   * null when there was no receipt path to evaluate (SKIPPED, no envelope).
   */
  currently_authorized: boolean | null;
  execution: {
    attempted: boolean;
    executed: boolean;
    enforced: boolean;
  };
  /**
   * Observed: kind of the guard verdict that produced this outcome.
   * On a blocked call this is how the block is named (BLOCK / APPROVAL / UNAVAILABLE / …).
   */
  verdict_kind: string;
  execution_result_hash: ExecutionResultHash;
  /**
   * Explicit non-claims. Readers that treat missing fields as "ok" are wrong; these are always set.
   */
  limits: {
    does_not_claim_change_safe: true;
    does_not_claim_host_cannot_bypass: true;
    does_not_claim_absent_field_is_compliance: true;
    change_fp_is_what_was_checked_not_what_executed: true;
    calls_outside_guarded_path_invisible: true;
    execution_result_hash_is_not_artifact_match_proof: true;
    /**
     * conditional_write:true is the HOST's assertion that it conditioned the write on a version
     * token. The guard does NOT and CANNOT independently verify that a compare-and-swap actually
     * occurred at commit time — the guard never writes. Absence is reported as 'not_reported',
     * never as false. (ID781 option A: honesty label; real CAS attestation is separate work.)
     */
    conditional_write_is_host_asserted_not_cas_verified: true;
    /**
     * commit_observation is observed at T3, not atomic: another writer may act between write
     * and observation; token-only adapters compare version token not content; host attestation
     * is a host claim layered on the measurement.
     */
    commit_observation_is_observed_at_t3_not_atomic: true;
  };
  /** T3 post-commit observation. Always present; not_observed when nothing was re-read. */
  commit_observation: CommitObservation;
  /**
   * CWM monitoring delivery (N-4). Present only on CONTINUE_WITH_MONITORING arms.
   * Observation-side — never a verdict/preimage field. delivered_acked ≠ human attention.
   */
  monitoring_delivery?: MonitoringDelivery;
  /**
   * S2-F2a R3 CAS evidence class (observation). Present when a CAS outcome was
   * observed. Not a preimage field. executor_attested only after registry verify.
   */
  cas_evidence?: CasEvidence;
  /**
   * S6 auto-recheck trail (observation). Present when the wrap-layer loop ran.
   * Additive; not a preimage field. Final outcome is the last decision.
   */
  recheck_trail?: ReadonlyArray<{
    attempt: number;
    decision_id: string | null;
    fingerprint: string | null;
    execution_action: string | null;
  }>;
};

export type ProofBuildInput = {
  preflighted: boolean;
  executionAttempted: boolean;
  executed: boolean;
  enforced: boolean;
  verdict: GuardVerdict;
  /** Present only when executed:true (factory returned). */
  result?: unknown;
  /** Present only when factory threw. */
  error?: unknown;
  /** Optional conditional-write basis for the enforced+policy invariant. */
  conditionalWriteBasis?: {
    require_conditional_write: boolean;
    write_style: boolean;
    conditional_write: true | false | 'not_reported';
  };
  /** T3 observation assembled by the guard after executeFactory (or not_observed). */
  commitObservation?: CommitObservation;
  /** CWM delivery evidence; omit on non-MONITOR arms. */
  monitoringDelivery?: MonitoringDelivery;
  /** S2-F2a R3 CAS evidence (observation). */
  casEvidence?: CasEvidence;
  /** S6 trail passthrough (observation). */
  recheckTrail?: ReadonlyArray<{
    attempt: number;
    decision_id: string | null;
    fingerprint: string | null;
    execution_action: string | null;
  }>;
};

const LIMITS: GuardExecutionProof['limits'] = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
  conditional_write_is_host_asserted_not_cas_verified: true,
  commit_observation_is_observed_at_t3_not_atomic: true,
});

/**
 * Runtime twin of the type-level enforced⟺receiptVerified invariant.
 * Throws if enforced:true is paired with anything other than receiptVerified+preflighted.
 * When requireConditionalWrite+writeStyle: enforced:true also requires conditional_write:true
 * (same refusal class as the permission gate — not a parallel path).
 * The proof block is read by consumers that do not have our TypeScript brands.
 */
export function assertEnforcedReceiptInvariant(input: {
  enforced: boolean;
  preflighted: boolean;
  receiptVerified: boolean;
  /** Policy requireConditionalWrite for this call (optional; omit = not checked here). */
  requireConditionalWrite?: boolean;
  writeStyle?: boolean;
  /** Host report: true | false | 'not_reported'. */
  conditionalWrite?: true | false | 'not_reported';
}): void {
  if (input.enforced === true) {
    if (input.preflighted !== true || input.receiptVerified !== true) {
      throw new Error(
        '@coderifts/agent-guard: enforced:true without receiptVerified+preflighted (runtime invariant)',
      );
    }
    if (input.requireConditionalWrite === true && input.writeStyle === true) {
      if (input.conditionalWrite !== true) {
        throw new Error(
          '@coderifts/agent-guard: enforced:true without conditional_write:true under requireConditionalWrite (runtime invariant)',
        );
      }
    }
  }
}

function receiptVerifiedOf(verdict: GuardVerdict): boolean {
  if ('receiptVerified' in verdict && typeof (verdict as { receiptVerified?: unknown }).receiptVerified === 'boolean') {
    return (verdict as { receiptVerified: boolean }).receiptVerified === true;
  }
  return false;
}

function envelopeOf(verdict: GuardVerdict): {
  decision_id?: unknown;
  expires_at?: unknown;
  operation?: unknown;
  fingerprint?: unknown;
} | null {
  if ('envelope' in verdict && verdict.envelope && typeof verdict.envelope === 'object') {
    return verdict.envelope as {
      decision_id?: unknown;
      expires_at?: unknown;
      operation?: unknown;
      fingerprint?: unknown;
    };
  }
  return null;
}

/**
 * Honest byte hash of a factory return. Only string / Buffer / Uint8Array are hashed as raw bytes.
 * Everything else is not_hashed with an explicit reason — never a JSON reformat hash.
 */
export function hashExecutionResult(result: unknown): ExecutionResultHash {
  if (typeof result === 'string') {
    return {
      status: 'hashed',
      algorithm: 'sha256',
      value: 'sha256:' + createHash('sha256').update(result, 'utf8').digest('hex'),
    };
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(result)) {
    return {
      status: 'hashed',
      algorithm: 'sha256',
      value: 'sha256:' + createHash('sha256').update(result).digest('hex'),
    };
  }
  if (result instanceof Uint8Array) {
    return {
      status: 'hashed',
      algorithm: 'sha256',
      value: 'sha256:' + createHash('sha256').update(result).digest('hex'),
    };
  }
  return { status: 'not_hashed', reason: 'result_not_byte_stable' };
}

function executionResultHashOf(input: ProofBuildInput): ExecutionResultHash {
  if (input.executionAttempted && !input.executed && 'error' in input && input.error !== undefined) {
    return { status: 'not_hashed', reason: 'execution_threw' };
  }
  if (!input.executed) {
    return { status: 'not_hashed', reason: 'not_executed' };
  }
  if (!('result' in input)) {
    return { status: 'not_hashed', reason: 'result_type_unsupported' };
  }
  return hashExecutionResult(input.result);
}

/**
 * Build the proof block from guard-observed outcome facts only.
 * Never accepts a caller-supplied proof object or partial field map.
 */
export function buildExecutionProof(input: ProofBuildInput): GuardExecutionProof {
  const receiptVerified = receiptVerifiedOf(input.verdict);
  const cwb = input.conditionalWriteBasis;
  assertEnforcedReceiptInvariant({
    enforced: input.enforced,
    preflighted: input.preflighted,
    receiptVerified,
    requireConditionalWrite: cwb?.require_conditional_write,
    writeStyle: cwb?.write_style,
    conditionalWrite: cwb?.conditional_write,
  });

  const env = envelopeOf(input.verdict);
  const hasEnvelope = env !== null;

  let decision_id: string | null = null;
  let expires_at: string | null = null;
  let binds_to: GuardExecutionProof['binds_to'] = null;

  if (hasEnvelope && env) {
    decision_id = typeof env.decision_id === 'string' ? env.decision_id : null;
    expires_at = typeof env.expires_at === 'string' ? env.expires_at : null;
    binds_to = Object.freeze({
      operation: typeof env.operation === 'string' ? env.operation : null,
      change_fp: typeof env.fingerprint === 'string' ? env.fingerprint : null,
    });
  }

  // currently_authorized: only evaluable when a receipt path existed.
  // verified ⇒ true (bind required VERIFIED_CURRENT). envelope present but not verified ⇒ false.
  // no envelope (SKIPPED / some UNAVAILABLE) ⇒ null.
  let currently_authorized: boolean | null = null;
  if (hasEnvelope) {
    currently_authorized = receiptVerified;
  }

  const proof: GuardExecutionProof = {
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: input.preflighted === true,
    decision_id,
    receipt: Object.freeze({
      verified: receiptVerified,
      status: receiptVerified ? ('VERIFIED_CURRENT' as const) : null,
      expires_at,
    }),
    binds_to: binds_to ? Object.freeze(binds_to) : null,
    currently_authorized,
    execution: Object.freeze({
      attempted: input.executionAttempted === true,
      executed: input.executed === true,
      enforced: input.enforced === true,
    }),
    verdict_kind: typeof input.verdict?.kind === 'string' ? input.verdict.kind : 'UNKNOWN',
    execution_result_hash: Object.freeze(executionResultHashOf(input)),
    limits: LIMITS,
    commit_observation: freezeCommitObservation(input.commitObservation),
  };
  if (input.monitoringDelivery && typeof input.monitoringDelivery === 'object') {
    proof.monitoring_delivery = freezeMonitoringDelivery(input.monitoringDelivery);
  }
  if (input.casEvidence && typeof input.casEvidence === 'object') {
    proof.cas_evidence = Object.freeze({ ...input.casEvidence });
  }
  if (Array.isArray(input.recheckTrail) && input.recheckTrail.length > 0) {
    proof.recheck_trail = Object.freeze(input.recheckTrail.map((e) => Object.freeze({ ...e })));
  }

  return freezeProof(proof);
}

function freezeMonitoringDelivery(d: MonitoringDelivery): MonitoringDelivery {
  return Object.freeze({
    status: d.status,
    ...(d.reason ? { reason: d.reason } : {}),
    ...(d.evidence ? { evidence: Object.freeze({ ...d.evidence }) } : {}),
  });
}

function freezeCommitObservation(obs: CommitObservation | undefined): CommitObservation {
  const o: CommitObservation = obs && typeof obs === 'object'
    ? { ...obs, ...(obs.blast ? { blast: Object.freeze({ ...obs.blast }) } : {}) }
    : { status: 'not_observed', observed_at: '', host_attestation: 'absent' };
  return Object.freeze(o);
}

function freezeProof(p: GuardExecutionProof): GuardExecutionProof {
  return Object.freeze(p);
}
