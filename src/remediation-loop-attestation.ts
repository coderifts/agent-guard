/**
 * Remediation-loop attestation (audit item 7 completion) — pure binder that ties a prior
 * BLOCK decision (with its remediation transaction) to a later ALLOW execution chain
 * (GuardExecutionProof + optional cas-attestation.v1).
 *
 * Does NOT modify cas-attestation.ts, execution-proof.ts, or envelope types.
 * Does NOT claim that the patch fixed required_changes, that recheck_scope was honored
 * server-side, that no other changes rode along, or that the new decision was caused by
 * the remediation — see limits (always set).
 *
 * Linkage mechanism (measured, app remediation-transaction.js):
 *   resubmission.reference_fingerprint + fingerprint_profile + modified_is_not_permission
 *   + next_preflight_required + recheck_scope. No decision_id prev-link on re-preflight.
 *
 * Future stronger form (NOT built here): server-echoed remediation_of on the re-authorize
 * path would bind decision_id→decision_id; this record only links measured fingerprints.
 *
 * DecisionResultEnvelope (SDK typed) does NOT declare remediation_transaction /
 * required_changes / resubmission — those ride on BLOCK envelopes at runtime when the app
 * attaches them. Access is via a narrow validated reader (measured field names only).
 */

import type { DecisionResultEnvelope } from './types.js';
import type { GuardExecutionProof } from './execution-proof.js';
import { isGuardExecutionProof } from './cas-attestation.js';
import type { CasAttestation } from './cas-attestation.js';
import { CAS_ATTESTATION_SPEC } from './cas-attestation.js';

/** Machine-readable schema id — mirrors cas-attestation.v1 / guard-execution-proof.v1 style. */
export const REMEDIATION_LOOP_ATTESTATION_SPEC = 'remediation-loop-attestation.v1' as const;

/**
 * Explicit non-claims. Always set (same discipline as CasAttestation.limits).
 * Readers that treat missing fields as "ok" are wrong.
 */
export type RemediationLoopAttestationLimits = {
  /** Does not claim the host patch addressed required_changes (semantic, unverifiable here). */
  does_not_claim_patch_addressed_required_changes: true;
  /** Does not claim recheck_scope was honored server-side on the re-preflight. */
  does_not_claim_recheck_scope_honored: true;
  /** Does not claim no unrelated changes rode along in the new change set. */
  does_not_claim_no_other_changes: true;
  /** Does not claim the new ALLOW was caused by the remediation (correlation ≠ causation). */
  does_not_claim_allow_caused_by_remediation: true;
  /**
   * Unchanged input is not permission (mirrors resubmission.modified_is_not_permission /
   * unchanged_input → deterministic_block). Attestation refuses when fingerprints match.
   */
  does_not_claim_unchanged_input_is_permission: true;
  /** Same host-bypass residual — package cannot force the host to re-preflight or CAS-commit. */
  does_not_claim_host_cannot_bypass: true;
};

const LIMITS: RemediationLoopAttestationLimits = Object.freeze({
  does_not_claim_patch_addressed_required_changes: true,
  does_not_claim_recheck_scope_honored: true,
  does_not_claim_no_other_changes: true,
  does_not_claim_allow_caused_by_remediation: true,
  does_not_claim_unchanged_input_is_permission: true,
  does_not_claim_host_cannot_bypass: true,
});

/** Measured remediation_transaction shape (app remediation-transaction.js, fixed key order). */
export type RemediationTransactionView = {
  required_changes: unknown[];
  resubmission: {
    reference_fingerprint: string;
    fingerprint_profile?: string;
    modified_is_not_permission?: boolean;
    unchanged_input?: string;
    modified_input?: string;
  };
  next_preflight_required?: boolean;
  recheck_scope?: unknown;
};

/**
 * Frozen remediation-loop-attestation.v1 record.
 * References are lifted from measured identifiers only; derived flags are only what is
 * honestly computable from the typed inputs.
 */
export type RemediationLoopAttestation = {
  attestation_spec: typeof REMEDIATION_LOOP_ATTESTATION_SPEC;
  references: {
    block: {
      decision_id: string;
      reference_fingerprint: string;
      required_changes_count: number;
      recheck_scope: unknown | null;
      fingerprint_profile: string | null;
      next_preflight_required: boolean | null;
    };
    allow: {
      decision_id: string | null;
      change_fp: string;
    };
    cas: {
      status: string;
      authorized_and_committed: boolean;
    } | null;
  };
  derived: {
    /** reference_fingerprint !== allow.change_fp (required for closure). */
    input_changed: true;
    /**
     * True only when cas-attestation is supplied AND cas.derived.authorized_and_committed.
     * Absent cas → false (recheck+authorize linkage only, not CAS commit).
     */
    loop_committed: boolean;
  };
  limits: RemediationLoopAttestationLimits;
};

// ── Narrow readers (runtime fields not on DecisionResultEnvelope type) ───────

/**
 * Read remediation_transaction from a BLOCK envelope object.
 * Typed DecisionResultEnvelope does not declare this field (measured absent from
 * decision-result.v1.d.ts); app attaches it at runtime on BLOCK. Measured names only
 * (remediation-transaction.js).
 */
export function readRemediationTransaction(
  envelope: unknown,
): RemediationTransactionView | null {
  if (!envelope || typeof envelope !== 'object') return null;
  const e = envelope as Record<string, unknown>;
  const tx = e.remediation_transaction;
  if (!tx || typeof tx !== 'object') return null;
  const t = tx as Record<string, unknown>;
  if (!Array.isArray(t.required_changes)) return null;
  const resub = t.resubmission;
  if (!resub || typeof resub !== 'object') return null;
  const r = resub as Record<string, unknown>;
  if (typeof r.reference_fingerprint !== 'string' || !r.reference_fingerprint) return null;
  return {
    required_changes: t.required_changes,
    resubmission: {
      reference_fingerprint: r.reference_fingerprint,
      fingerprint_profile:
        typeof r.fingerprint_profile === 'string' ? r.fingerprint_profile : undefined,
      modified_is_not_permission:
        typeof r.modified_is_not_permission === 'boolean'
          ? r.modified_is_not_permission
          : undefined,
      unchanged_input: typeof r.unchanged_input === 'string' ? r.unchanged_input : undefined,
      modified_input: typeof r.modified_input === 'string' ? r.modified_input : undefined,
    },
    next_preflight_required:
      typeof t.next_preflight_required === 'boolean' ? t.next_preflight_required : undefined,
    recheck_scope: 'recheck_scope' in t ? t.recheck_scope : undefined,
  };
}

/**
 * Validate prior envelope is a BLOCK with a usable remediation transaction.
 * Returns measured identifiers or null if shape invalid.
 */
export function readPriorBlockRemediation(envelope: unknown): {
  decision_id: string;
  reference_fingerprint: string;
  required_changes_count: number;
  recheck_scope: unknown | null;
  fingerprint_profile: string | null;
  next_preflight_required: boolean | null;
} | null {
  if (!envelope || typeof envelope !== 'object') return null;
  const e = envelope as Record<string, unknown>;
  if (e.decision !== 'BLOCK') return null;
  if (typeof e.decision_id !== 'string' || !e.decision_id) return null;
  const tx = readRemediationTransaction(envelope);
  if (!tx) return null;
  return {
    decision_id: e.decision_id,
    reference_fingerprint: tx.resubmission.reference_fingerprint,
    required_changes_count: tx.required_changes.length,
    recheck_scope: tx.recheck_scope !== undefined ? tx.recheck_scope : null,
    fingerprint_profile: tx.resubmission.fingerprint_profile ?? null,
    next_preflight_required:
      tx.next_preflight_required !== undefined ? tx.next_preflight_required : null,
  };
}

export function isCasAttestation(x: unknown): x is CasAttestation {
  if (!x || typeof x !== 'object') return false;
  const a = x as { attestation_spec?: unknown; derived?: unknown; cas?: unknown };
  return a.attestation_spec === CAS_ATTESTATION_SPEC
    && a.derived != null
    && typeof a.derived === 'object'
    && a.cas != null
    && typeof a.cas === 'object';
}

/**
 * Bind prior BLOCK envelope + ALLOW proof (+ optional cas-attestation) into
 * remediation-loop-attestation.v1.
 *
 * Validation-first: TypeError on invalid shapes / not-BLOCK / missing remediation tx /
 * missing allow change_fp / unchanged fingerprint (modified_is_not_permission).
 */
export function buildRemediationLoopAttestation(
  priorBlockEnvelope: DecisionResultEnvelope | Record<string, unknown>,
  allowProof: GuardExecutionProof,
  casAttestation?: CasAttestation | null,
): RemediationLoopAttestation {
  const block = readPriorBlockRemediation(priorBlockEnvelope);
  if (!block) {
    throw new TypeError(
      '@coderifts/agent-guard: buildRemediationLoopAttestation requires a BLOCK envelope '
      + 'with a valid remediation_transaction '
      + '(required_changes[], resubmission.reference_fingerprint) — measured app shape; '
      + 'not declared on DecisionResultEnvelope types',
    );
  }

  if (!isGuardExecutionProof(allowProof)) {
    throw new TypeError(
      '@coderifts/agent-guard: buildRemediationLoopAttestation requires a valid '
      + 'guard-execution-proof.v1 object',
    );
  }

  const allowChangeFp =
    allowProof.binds_to != null && typeof allowProof.binds_to.change_fp === 'string'
      ? allowProof.binds_to.change_fp
      : null;
  if (!allowChangeFp) {
    throw new TypeError(
      '@coderifts/agent-guard: buildRemediationLoopAttestation requires allow proof '
      + 'binds_to.change_fp (measured identifier for the new change set)',
    );
  }

  // Unchanged input is explicitly not permission (resubmission.modified_is_not_permission).
  if (block.reference_fingerprint === allowChangeFp) {
    throw new TypeError(
      '@coderifts/agent-guard: buildRemediationLoopAttestation: input_unchanged '
      + '(reference_fingerprint === allow change_fp); modified_is_not_permission — '
      + 'refuse to attest loop closure',
    );
  }

  let casRef: RemediationLoopAttestation['references']['cas'] = null;
  let loop_committed = false;
  if (casAttestation != null && casAttestation !== undefined) {
    if (!isCasAttestation(casAttestation)) {
      throw new TypeError(
        '@coderifts/agent-guard: buildRemediationLoopAttestation casAttestation must be '
        + 'cas-attestation.v1 when provided',
      );
    }
    casRef = Object.freeze({
      status: String(casAttestation.cas.status),
      authorized_and_committed: casAttestation.derived.authorized_and_committed === true,
    });
    loop_committed = casAttestation.derived.authorized_and_committed === true;
  }

  const record: RemediationLoopAttestation = {
    attestation_spec: REMEDIATION_LOOP_ATTESTATION_SPEC,
    references: Object.freeze({
      block: Object.freeze({
        decision_id: block.decision_id,
        reference_fingerprint: block.reference_fingerprint,
        required_changes_count: block.required_changes_count,
        recheck_scope: block.recheck_scope,
        fingerprint_profile: block.fingerprint_profile,
        next_preflight_required: block.next_preflight_required,
      }),
      allow: Object.freeze({
        decision_id: allowProof.decision_id,
        change_fp: allowChangeFp,
      }),
      cas: casRef,
    }),
    derived: Object.freeze({
      input_changed: true as const,
      loop_committed,
    }),
    limits: LIMITS,
  };

  return freezeLoopAttestation(record);
}

function freezeLoopAttestation(a: RemediationLoopAttestation): RemediationLoopAttestation {
  return Object.freeze(a);
}
