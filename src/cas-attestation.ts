/**
 * CAS attestation binder (ID781 option A follow-on) — separate record linking a frozen
 * GuardExecutionProof (v1) with an ExecuteIfUnchangedOutcome.
 *
 * Does NOT mutate execution-proof assembly or conditional-write outcome types.
 * Additive `cas_evidence` is observation-only (optional on the proof / outcome).
 * Does NOT claim that the host write is unique, that version tokens equal change_fp, or that
 * committed_stale_detected is "safe". Those non-claims are always set on `limits`.
 *
 * The proof's own limit `conditional_write_is_host_asserted_not_cas_verified` names this gap;
 * this module is the separate attestation surface that pairs proof + CAS outcome without
 * widening the proof spec.
 */

import { verifyExecutionAttestation } from '@coderifts/sdk';
import type { ExecutorKeyRegistry } from '@coderifts/sdk';
import type { GuardExecutionProof, ExecutionResultHash } from './execution-proof.js';
import { EXECUTION_PROOF_SPEC } from './execution-proof.js';
import type { ExecuteIfUnchangedOutcome, VersionToken } from './conditional-write.js';

/** Machine-readable schema id — mirrors EXECUTION_PROOF_SPEC style. */
export const CAS_ATTESTATION_SPEC = 'cas-attestation.v1' as const;

/**
 * Explicit non-claims. Always set (same discipline as GuardExecutionProof.limits).
 * Readers that treat missing fields as "ok" are wrong.
 */
export type CasAttestationLimits = {
  /** Host may have performed other writes outside executeIfUnchanged. */
  does_not_claim_only_write_on_host: true;
  /** version_token / post_commit_token are opaque CAS resource versions — not change_fp identity. */
  does_not_claim_version_token_proves_change_fp_match: true;
  /** committed_stale_detected means write ran and post-check disagreed — not "safe" or rolled back. */
  does_not_claim_committed_stale_is_safe: true;
  /** execution_result_hash hashes the factory return, not CAS file bytes / token equality. */
  does_not_claim_execution_result_hash_equals_cas_bytes: true;
  /** Same host-bypass residual as the proof family — package cannot force host CAS use. */
  does_not_claim_host_cannot_bypass: true;
  /** Attestation is linkage of two inputs, not a re-decision of governance ALLOW/BLOCK. */
  does_not_claim_governance_redecision: true;
};

const LIMITS: CasAttestationLimits = Object.freeze({
  does_not_claim_only_write_on_host: true,
  does_not_claim_version_token_proves_change_fp_match: true,
  does_not_claim_committed_stale_is_safe: true,
  does_not_claim_execution_result_hash_equals_cas_bytes: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_governance_redecision: true,
});

/** CAS branch projection — only fields present on the measured outcome branch. */
export type CasAttestationCas =
  | {
      status: 'committed';
      write_ran: true;
      version_token: VersionToken;
    }
  | {
      status: 'refused';
      write_ran: false;
      reason: 'stale_version_token';
      expected_token: VersionToken;
      current_token: VersionToken | null;
    }
  | {
      status: 'committed_stale_detected';
      write_ran: true;
      reason: 'stale_during_commit';
      expected_token: VersionToken;
      post_commit_token: VersionToken | null;
    };

/**
 * Frozen cas-attestation.v1 record.
 * References are lifted from the proof; cas is projected from the outcome; derived flags
 * are only what is honestly computable from those two inputs.
 */
export type CasAttestation = {
  attestation_spec: typeof CAS_ATTESTATION_SPEC;
  references: {
    decision_id: string | null;
    change_fp: string | null;
    operation: string | null;
    execution_result_hash: ExecutionResultHash;
    receipt_verified: boolean;
  };
  cas: CasAttestationCas;
  derived: {
    /**
     * receipt.verified === true AND outcome.status === 'committed'
     * (clean commit only — committed_stale_detected is NOT this flag).
     */
    authorized_and_committed: boolean;
    /** Write mutation ran: committed or committed_stale_detected. */
    write_ran: boolean;
    /** outcome.status === 'committed_stale_detected'. */
    stale_during_commit: boolean;
    /** outcome.status === 'refused'. */
    refused: boolean;
  };
  /**
   * Observation-side CAS evidence class (S2-F2a R3). Never a verdict/preimage field.
   * executor_attested only after a customer-pinned registry verifies the token.
   * A lying/invalid attestation stays host_claimed with attest_status visible
   * (same principle as N-4's lying sink). No registry → host_claimed, no penalty.
   */
  cas_evidence: CasEvidence;
  limits: CasAttestationLimits;
};

/** Tri-state CAS evidence (N-4 monitoring_delivery is the pattern). */
export type CasEvidenceClass = 'executor_attested' | 'host_claimed' | 'absent';

export type CasEvidence = {
  class: CasEvidenceClass;
  attest_status: string | null;
  executor_kid: string | null;
  grant_jti: string | null;
};

export type ExecutorAttestationConfig = {
  /** Customer-pinned executor key registry. Required to attempt verification. */
  registry: ExecutorKeyRegistry;
};

export type EvaluateCasEvidenceOpts = {
  registry?: ExecutorKeyRegistry | null;
  grant?: string | null;
  receipt_digest?: string | null;
};

const ABSENT_EVIDENCE: CasEvidence = Object.freeze({
  class: 'absent',
  attest_status: null,
  executor_kid: null,
  grant_jti: null,
});

function hostClaimed(status: string | null, kid: string | null, jti: string | null): CasEvidence {
  return Object.freeze({
    class: 'host_claimed',
    attest_status: status,
    executor_kid: kid,
    grant_jti: jti,
  });
}

/** Pull the attestation token from the CAS outcome or the mutation response body. */
export function extractExecutorAttestationToken(outcome: unknown): string | null {
  if (!outcome || typeof outcome !== 'object') return null;
  const o = outcome as Record<string, unknown>;
  if (typeof o.executor_attestation === 'string' && o.executor_attestation.length > 0) {
    return o.executor_attestation;
  }
  const r = o.result;
  if (r && typeof r === 'object') {
    const tok = (r as Record<string, unknown>).executor_attestation;
    if (typeof tok === 'string' && tok.length > 0) return tok;
  }
  return null;
}

function intendedFromOutcome(outcome: unknown): { grant?: string; receipt_digest?: string } {
  const intended: { grant?: string; receipt_digest?: string } = {};
  if (!outcome || typeof outcome !== 'object') return intended;
  const o = outcome as Record<string, unknown>;
  const r = o.result && typeof o.result === 'object' ? (o.result as Record<string, unknown>) : o;
  if (typeof r.grant === 'string' && r.grant.length > 0) intended.grant = r.grant;
  else if (typeof r.execution_grant === 'string' && r.execution_grant.length > 0) {
    intended.grant = r.execution_grant;
  }
  if (typeof r.receipt_digest === 'string' && r.receipt_digest.length > 0) {
    intended.receipt_digest = r.receipt_digest;
  }
  return intended;
}

/**
 * Observation-side CAS evidence. Does not change authorized_and_committed.
 * Invalid attestation never upgrades the class (lying token stays host_claimed).
 */
export function evaluateCasEvidence(
  outcome: unknown,
  opts: EvaluateCasEvidenceOpts = {},
): CasEvidence {
  if (!isExecuteIfUnchangedOutcome(outcome)) return ABSENT_EVIDENCE;
  if (outcome.status === 'refused') return ABSENT_EVIDENCE;

  const token = extractExecutorAttestationToken(outcome);
  const registry = opts.registry;
  const fromOutcome = intendedFromOutcome(outcome);
  const grant = opts.grant || fromOutcome.grant || null;
  const receipt_digest = opts.receipt_digest || fromOutcome.receipt_digest || null;

  if (!registry || !Array.isArray(registry.keys)) {
    return hostClaimed(null, null, null);
  }
  if (!token) {
    return hostClaimed(null, null, null);
  }

  const intended: { grant?: string; receipt_digest?: string } = {};
  if (grant) intended.grant = grant;
  if (receipt_digest) intended.receipt_digest = receipt_digest;
  const wantsIntended = Object.keys(intended).length > 0;

  let verified;
  try {
    verified = verifyExecutionAttestation(token, {
      registry,
      ...(wantsIntended ? { intended } : {}),
    });
  } catch {
    return hostClaimed('ATTEST_MALFORMED', null, null);
  }

  const payload = verified.payload && typeof verified.payload === 'object'
    ? verified.payload as Record<string, unknown>
    : null;
  const kid = payload && typeof payload.executor_kid === 'string' ? payload.executor_kid : null;
  const jti = payload && typeof payload.grant_jti === 'string' ? payload.grant_jti : null;

  if (verified.valid === true
      && (verified.status === 'ATTEST_VALID' || verified.status === 'ATTEST_RETIRED_KEY_VALID_AT_ISSUE')) {
    return Object.freeze({
      class: 'executor_attested',
      attest_status: verified.status,
      executor_kid: kid,
      grant_jti: jti,
    });
  }
  return hostClaimed(verified.status, kid, jti);
}

/** Type guard: object carries the frozen v1 proof_spec. */
export function isGuardExecutionProof(x: unknown): x is GuardExecutionProof {
  if (!x || typeof x !== 'object') return false;
  const p = x as { proof_spec?: unknown; receipt?: unknown; execution_result_hash?: unknown };
  return p.proof_spec === EXECUTION_PROOF_SPEC
    && p.receipt != null
    && typeof p.receipt === 'object'
    && p.execution_result_hash != null
    && typeof p.execution_result_hash === 'object';
}

/** Type guard: object is one of the three ExecuteIfUnchangedOutcome branches. */
export function isExecuteIfUnchangedOutcome(x: unknown): x is ExecuteIfUnchangedOutcome<unknown> {
  if (!x || typeof x !== 'object') return false;
  const o = x as { status?: unknown };
  if (o.status === 'committed') {
    const c = x as { version_token?: unknown };
    return typeof c.version_token === 'string';
  }
  if (o.status === 'refused') {
    const r = x as { reason?: unknown; expected_token?: unknown };
    return r.reason === 'stale_version_token' && typeof r.expected_token === 'string';
  }
  if (o.status === 'committed_stale_detected') {
    const s = x as { reason?: unknown; expected_token?: unknown };
    return s.reason === 'stale_during_commit' && typeof s.expected_token === 'string';
  }
  return false;
}

function freezeExecutionResultHash(h: ExecutionResultHash): ExecutionResultHash {
  return Object.freeze({ ...h }) as ExecutionResultHash;
}

function projectCas(outcome: ExecuteIfUnchangedOutcome<unknown>): CasAttestationCas {
  if (outcome.status === 'committed') {
    return Object.freeze({
      status: 'committed',
      write_ran: true as const,
      version_token: outcome.version_token,
    });
  }
  if (outcome.status === 'refused') {
    return Object.freeze({
      status: 'refused',
      write_ran: false as const,
      reason: 'stale_version_token' as const,
      expected_token: outcome.expected_token,
      current_token: outcome.current_token == null ? null : outcome.current_token,
    });
  }
  // committed_stale_detected
  return Object.freeze({
    status: 'committed_stale_detected',
    write_ran: true as const,
    reason: 'stale_during_commit' as const,
    expected_token: outcome.expected_token,
    post_commit_token: outcome.post_commit_token == null ? null : outcome.post_commit_token,
  });
}

/**
 * Bind a frozen GuardExecutionProof with an ExecuteIfUnchangedOutcome into a cas-attestation.v1.
 *
 * Validation-first: rejects non-v1 proofs and non-outcome shapes (throws TypeError —
 * builders fail closed; the human render layer soft-fails instead).
 */
export function buildCasAttestation(
  proof: GuardExecutionProof,
  outcome: ExecuteIfUnchangedOutcome<unknown>,
  opts: EvaluateCasEvidenceOpts = {},
): CasAttestation {
  if (!isGuardExecutionProof(proof)) {
    throw new TypeError(
      '@coderifts/agent-guard: buildCasAttestation requires a valid guard-execution-proof.v1 object '
      + '(proof_spec mismatch or missing required fields)',
    );
  }
  if (!isExecuteIfUnchangedOutcome(outcome)) {
    throw new TypeError(
      '@coderifts/agent-guard: buildCasAttestation requires a valid ExecuteIfUnchangedOutcome '
      + '(status committed | refused | committed_stale_detected with branch fields)',
    );
  }

  const receipt_verified = proof.receipt.verified === true;
  const cas = projectCas(outcome);
  const write_ran = cas.write_ran === true;
  const stale_during_commit = cas.status === 'committed_stale_detected';
  const refused = cas.status === 'refused';
  const authorized_and_committed = receipt_verified && cas.status === 'committed';

  const attestation: CasAttestation = {
    attestation_spec: CAS_ATTESTATION_SPEC,
    references: Object.freeze({
      decision_id: proof.decision_id,
      change_fp: proof.binds_to != null ? proof.binds_to.change_fp : null,
      operation: proof.binds_to != null ? proof.binds_to.operation : null,
      execution_result_hash: freezeExecutionResultHash(proof.execution_result_hash),
      receipt_verified,
    }),
    cas,
    derived: Object.freeze({
      authorized_and_committed,
      write_ran,
      stale_during_commit,
      refused,
    }),
    cas_evidence: evaluateCasEvidence(outcome, opts),
    limits: LIMITS,
  };

  return freezeAttestation(attestation);
}

function freezeAttestation(a: CasAttestation): CasAttestation {
  return Object.freeze(a);
}
