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
import type { ExecuteIfUnchangedOutcome, IndeterminateReason, VersionToken } from './conditional-write.js';

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
    }
  | {
      status: 'indeterminate';
      /**
       * 'unknown' is a THIRD value, never a default to false. Collapsing it to false would say the
       * write did not run, which is a claim we do not have; collapsing it to true would say it did.
       */
      write_ran: 'unknown';
      reason: IndeterminateReason;
      expected_token: VersionToken;
      observed_token: VersionToken | null;
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
    /**
     * ATOMIC / v2 only: host-reported commit. Never co-named with authorized_and_committed.
     * Absent on non-ATOMIC records (byte-identical 9.0.0 derived).
     */
    authorized_and_host_reported_committed?: boolean;
    /** Write mutation ran: committed or committed_stale_detected. */
    write_ran: boolean;
    /** outcome.status === 'committed_stale_detected'. */
    stale_during_commit: boolean;
    /** outcome.status === 'refused'. */
    refused: boolean;
    /**
     * outcome.status === 'indeterminate'. Downstream MUST block on this: it is not a pass, and it
     * is not a failure either. Reconciliation is required before anything may proceed.
     */
    indeterminate: boolean;
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
  /**
   * The PINNED CodeRifts ISSUER keyring, used to AUTHENTICATE an execution grant before it can
   * count as a kernel binding under an enforcing profile (1433).
   *
   * IT LIVES HERE, not on `executionGrant`, and the difference matters: `executionGrant` gates
   * whether the guard REQUESTS a grant, and setting `enabled: true` merely to supply a key would
   * turn on a request path the caller never asked for. This section is the verification side, and
   * a key for checking evidence belongs with the other key for checking evidence.
   *
   * Absent under an enforcing profile is FAIL-CLOSED: a grant that cannot be authenticated does
   * not become a binding.
   */
  issuerKeyring?: { keys?: Array<{ kid?: string; public_key_pem?: string; status?: string }> } | null;
};

export type EvaluateCasEvidenceOpts = {
  registry?: ExecutorKeyRegistry | null;
  grant?: string | null;
  receipt_digest?: string | null;
  grant_fields?: {
    jti?: string;
    scope_hash?: string;
    state_nonce?: string;
    receipt_digest?: string;
  } | null;
  /**
   * ISSUER keyring for the execution grant — the pinned CodeRifts public keys, NOT the executor
   * registry above. Supplied, a grant is AUTHENTICATED before it counts as a kernel binding.
   *
   * ── WHY THIS EXISTS (1431) ───────────────────────────────────────────────────────────────
   *
   * MEASURED, then closed. The guard authenticated the receipt (vendored verify.js) and the
   * executor attestation (SDK verifyExecutionAttestation) and never the grant. The SDK's
   * cross-check DECODES the grant (`parseGrantFields`) to compare jti / scope_hash / state_nonce
   * against the attestation's payload, so a token whose payload simply copied those three values
   * — with the literal word NEM-ALAIRAS in the signature slot — passed, and ENFORCING_STRICT
   * went from `authorized_not_committed` to `authorized_and_committed` on the strength of it.
   *
   * A binding checked against an unauthenticated document is not a binding.
   *
   * OMITTED IS FAIL-CLOSED, and this is a behaviour change worth stating: a caller who supplies a
   * grant but no issuer keyring can no longer have it counted as a kernel binding, because
   * nothing here can tell a real grant from a copied one. The observation degrades to
   * `authorized_not_committed` / `commit_evidence_missing` — the honest name for "we could not
   * check" — rather than keeping the old, unearned upgrade.
   */
  grant_keyring?: { keys?: Array<{ kid?: string; public_key_pem?: string; status?: string }> } | null;
  /** Clock injection for grant expiry, tests only. */
  now?: number;
  /** Strict-only tightening of derived.authorized_and_committed. Absent = 9.0.0 formula. */
  profile?: 'ENFORCING_STRICT' | 'ENFORCING_ATOMIC';
};

/**
 * THE CORE PREDICATE, quoted rather than recomputed (1459).
 *
 * MEASURED before this wiring: the guard reached the right answer with a formula of its own —
 * `receipt_verified && committed && class === 'executor_attested' && strictCommitObservation(...)`.
 * Correct, and bespoke. The auditor's point is that a predicate written twice is a predicate that
 * drifts, and the Atomic bypass was exactly that: two formulas for one question, disagreeing.
 *
 * So the guard now shapes its inputs and QUOTES `verifiedExecutionBinding`. The named shortfall
 * states (UNAUTHORIZED / COMMIT_UNPROVEN / ONE_RUN_UNPROVEN / …) surface here as a result, so an
 * operator reads the same vocabulary the CLI, Prove and conformance print.
 *
 * Loaded lazily and behind try/catch: a packaging fault must surface as NOT authorized, never as a
 * crash inside the guard, and never as a silent fallback to the old local formula.
 */
function coreBinding(): { verifiedExecutionBinding: Function } | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
    return require('./vendor/verified-execution-binding.js');
  } catch (_) { return null; }
}

/** Result of authenticating a supplied grant against the pinned issuer keyring. */
export type GrantAuthentication = {
  /** true only when a signature verified against a pinned issuer key. */
  authenticated: boolean;
  /** The verifier's status, or why authentication was not even attempted. */
  status: string;
  reason: string | null;
};

/**
 * Authenticate an execution grant against the pinned ISSUER keyring, through the vendored
 * canonical core (receipt-verifier verify-grant.js — cr.exec.v1 AND cr.exec.v2).
 *
 * Loaded lazily and behind try/catch so a host that never supplies a keyring never pays for it,
 * and so a packaging fault surfaces as NOT authenticated rather than as a crash inside the guard.
 */
export function authenticateGrant(
  token: string | null | undefined,
  keyring: EvaluateCasEvidenceOpts['grant_keyring'],
  now?: number,
): GrantAuthentication {
  if (typeof token !== 'string' || token.length === 0) {
    return { authenticated: false, status: 'NO_GRANT', reason: 'no_grant_supplied' };
  }
  if (!keyring || !Array.isArray(keyring.keys) || keyring.keys.length === 0) {
    return { authenticated: false, status: 'NO_KEYRING', reason: 'grant_keyring_not_supplied' };
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { createPublicKey } = require('node:crypto');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const core = require('./vendor/verify-grant.js');
    const ring = new Map<string, unknown>();
    for (const k of keyring.keys) {
      if (!k || typeof k.kid !== 'string' || typeof k.public_key_pem !== 'string') continue;
      ring.set(k.kid, {
        publicKey: createPublicKey(k.public_key_pem),
        status: k.status || 'active',
        retired_at: null,
        compromised_at: null,
      });
    }
    if (ring.size === 0) {
      return { authenticated: false, status: 'NO_KEYRING', reason: 'grant_keyring_has_no_usable_key' };
    }
    const r = core.verifyExecutionGrant(token, {
      ctx: { keyring: ring, expectedKid: null },
      ...(Number.isFinite(now) ? { now } : {}),
    });
    return {
      authenticated: r.valid === true,
      status: String(r.status || 'UNKNOWN'),
      reason: r.reason ? String(r.reason) : null,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      authenticated: false,
      status: 'VERIFIER_UNAVAILABLE',
      reason: message || 'the vendored grant verifier could not run',
    };
  }
}

/** Existing CasAttestation.derived name and its honest sibling — not a parallel taxonomy. */
export type CommitLabel = 'authorized_and_committed' | 'authorized_not_committed' | 'authorized_and_host_reported_committed';
export const COMMIT_EVIDENCE_MISSING = 'commit_evidence_missing' as const;

export type StrictCommitObservation = {
  commit_label: CommitLabel;
  commit_evidence_reason?: typeof COMMIT_EVIDENCE_MISSING;
};

/**
 * Was a kernel binding supplied that this guard can actually STAND BEHIND?
 *
 * 1431 — a grant counts only when its signature verified against the pinned issuer keyring. It
 * used to count on being a non-empty string, which is how a token reading NEM-ALAIRAS in the
 * signature slot upgraded ENFORCING_STRICT to authorized_and_committed.
 *
 * `grant_fields` and a bare `receipt_digest` are UNCHANGED and still count. They are host-asserted
 * values that were never claimed to be authenticated — the attestation cross-check is what gives
 * them meaning, and narrowing them here would change a contract nobody complained about. The grant
 * is different precisely because it LOOKS like a signed document.
 */
function bindingIntendedSupplied(outcome: unknown, opts: EvaluateCasEvidenceOpts): boolean {
  const from = intendedFromOutcome(outcome);
  const grant = (opts.grant && String(opts.grant)) || (from.grant && String(from.grant)) || '';
  const grantAuthenticated = grant.length > 0
    && authenticateGrant(grant, opts.grant_keyring, opts.now).authenticated;
  if (grantAuthenticated) return true;

  // ── UNDER AN ENFORCING PROFILE, NOTHING WEAKER COUNTS (1433) ─────────────────────────────
  //
  // MEASURED, then closed. 1431 made an unauthenticated grant stop counting ON ITS OWN, and this
  // predicate is an OR — so the same forged token plus a bare `receipt_digest` went straight back
  // to authorized_and_committed. Reproduced:
  //
  //   forged grant + issuer keyring                → authorized_not_committed   (1431 held)
  //   forged grant + bare receipt_digest           → authorized_and_committed   (the bypass)
  //   forged grant + bare grant_fields             → authorized_and_committed   (the bypass)
  //   bare receipt_digest alone, no grant          → authorized_and_committed
  //
  // `receipt_digest` and `grant_fields` are HOST-ASSERTED values: a caller writes them, nothing
  // signs them. They are legitimate as ADVISORY corroboration and they stay legitimate outside an
  // enforcing profile, where the label is weaker and says so. Inside one they cannot stand in for
  // a signature, because the whole meaning of ENFORCING_STRICT is that the guard checked.
  const enforcing = opts.profile === 'ENFORCING_STRICT' || opts.profile === 'ENFORCING_ATOMIC';
  if (enforcing) return false;

  if (opts.receipt_digest && String(opts.receipt_digest).length > 0) return true;
  if (from.receipt_digest && String(from.receipt_digest).length > 0) return true;
  const gf = opts.grant_fields;
  if (gf && (gf.jti || gf.scope_hash || gf.receipt_digest)) return true;
  return false;
}

/**
 * ENFORCING_STRICT success name. authorized_and_committed only when the evidence class is
 * executor_attested AND a kernel binding (grant jti / scope_hash / receipt_digest) was supplied
 * so the attestation actually cross-checked this outcome. Otherwise authorized_not_committed
 * with reason commit_evidence_missing. Observation-side — does not change enforced.
 */
export function strictCommitObservation(
  outcome: unknown,
  evidence: CasEvidence | undefined,
  opts: EvaluateCasEvidenceOpts = {},
): StrictCommitObservation {
  const crossChecked = evidence != null
    && evidence.class === 'executor_attested'
    && bindingIntendedSupplied(outcome, opts);
  if (crossChecked) {
    return { commit_label: 'authorized_and_committed' };
  }
  return {
    commit_label: 'authorized_not_committed',
    commit_evidence_reason: COMMIT_EVIDENCE_MISSING,
  };
}

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
  const grant_fields = opts.grant_fields || null;

  if (!registry || !Array.isArray(registry.keys)) {
    return hostClaimed(null, null, null);
  }
  if (!token) {
    return hostClaimed(null, null, null);
  }

  const intended: {
    grant?: string;
    receipt_digest?: string;
    grant_fields?: NonNullable<EvaluateCasEvidenceOpts['grant_fields']>;
  } = {};
  if (grant) intended.grant = grant;
  if (receipt_digest) intended.receipt_digest = receipt_digest;
  if (grant_fields) intended.grant_fields = grant_fields;
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
  if (o.status === 'indeterminate') {
    const i = x as { reason?: unknown; expected_token?: unknown };
    return (i.reason === 'response_lost'
      || i.reason === 'ambiguous_provider_reply'
      || i.reason === 'observation_failed')
      && typeof i.expected_token === 'string';
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
  if (outcome.status === 'indeterminate') {
    return Object.freeze({
      status: 'indeterminate',
      write_ran: 'unknown' as const,
      reason: outcome.reason,
      expected_token: outcome.expected_token,
      observed_token: outcome.observed_token == null ? null : outcome.observed_token,
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
  const indeterminate = cas.status === 'indeterminate';
  const cas_evidence = evaluateCasEvidence(outcome, opts);
  let authorized_and_committed = receipt_verified && cas.status === 'committed';
  let binding: { state?: string; shortfalls?: string[] } | null = null;
  let authorized_and_host_reported_committed = false;
  // ENFORCING_STRICT: the existing derived name now requires executor_attested + kernel
  // cross-check. Non-strict keeps the 9.0.0 formula (receipt verified + clean commit).
  // ── ONE PREDICATE FOR BOTH ENFORCING PROFILES ────────────────────────────────────────────
  //
  // The intersection is computed by the vendored core; this block only SHAPES the guard's inputs
  // into the core's vocabulary. `required` names the two authorities an enforcing guard can
  // actually establish from a tool outcome: it holds a grant and an attestation, and it does not
  // hold a prove artifact or a provider readback — asking the core for `one_run_root` here would
  // report a shortfall about evidence this surface never receives.
  const enforcingProfile = opts.profile === 'ENFORCING_STRICT' || opts.profile === 'ENFORCING_ATOMIC';
  if (enforcingProfile) {
    const core = coreBinding();
    const from = intendedFromOutcome(outcome);
    const grantToken = (opts.grant && String(opts.grant)) || (from.grant && String(from.grant)) || '';
    const attToken = extractExecutorAttestationToken(outcome);
    if (!core) {
      // FAIL-CLOSED, and named. Falling back to the local formula would recreate the second
      // predicate this change exists to remove.
      authorized_and_committed = false;
      binding = { state: 'UNAUTHORIZED', shortfalls: ['the vendored core predicate could not be loaded'] };
    } else {
      const keyring = opts.grant_keyring && Array.isArray(opts.grant_keyring.keys)
        ? new Map(opts.grant_keyring.keys
          .filter((k) => k && typeof k.kid === 'string' && typeof k.public_key_pem === 'string')
          .map((k) => [k.kid, {
            // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
            publicKey: require('node:crypto').createPublicKey(k.public_key_pem),
            status: k.status || 'active',
            retired_at: null,
            compromised_at: null,
          }]))
        : null;
      const r = core.verifiedExecutionBinding({
        receipt: { verified: receipt_verified },
        grant: { token: grantToken, keyring, expectedKid: null, ...(Number.isFinite(opts.now) ? { now: opts.now } : {}) },
        attestation: {
          token: attToken,
          registry: opts.registry,
          // The SDK's verifier, handed in rather than reimplemented — the core holds no
          // attestation format knowledge of its own.
          // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
          verify: (t: string, o: unknown) => require('@coderifts/sdk').verifyExecutionAttestation(t, o),
        },
        committed: cas.status === 'committed',
        required: ['issuer_grant', 'executor_attestation'],
      });
      binding = { state: r.state, shortfalls: r.shortfalls };
      authorized_and_committed = r.authorized_and_committed === true;
    }
  }
  if (opts.profile === 'ENFORCING_ATOMIC') {
    // ── REPRODUCED THEN CLOSED (1447 / 1459) ────────────────────────────────────────────
    //
    // This branch used to read:
    //
    //     authorized_and_committed = receipt_verified && committed && class === 'executor_attested'
    //
    // and never asked whether the GRANT was signed by anyone. Measured on the public 17.2.0, with
    // a forged-signature grant and a REAL attestation from a trusted executor bound to that
    // grant's jti and scope:
    //
    //     ENFORCING_STRICT  authorized_and_committed = false
    //     ENFORCING_ATOMIC  authorized_and_committed = true
    //
    // Two profiles of one product, one set of bytes, opposite answers. The attestation was doing
    // all the work, and an attestation only ever says "I committed the grant with these ids" — it
    // cannot say the ids belonged to a grant anyone authorized.
    //
    // BOTH branches now QUOTE the same predicate rather than each computing a formula. Strict is
    // unchanged in behaviour and Atomic is brought up to it, which is the direction a disagreement
    // between two enforcing profiles has to be resolved in.
    // The verdict itself now comes from the core above — both enforcing profiles quote it, which
    // is what makes them incapable of disagreeing. This branch keeps only the ATOMIC-only
    // OBSERVATION name, which is a different fact and was never part of the bypass.
    const hostClaimed = cas_evidence.class === 'host_claimed';
    authorized_and_host_reported_committed = receipt_verified && cas.status === 'committed' && hostClaimed;
  }

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
      indeterminate,
      ...(opts.profile === 'ENFORCING_ATOMIC'
        ? { authorized_and_host_reported_committed }
        : {}),
      // The core's NAMED state, carried so an operator reads why rather than only whether.
      ...(binding ? { authorization_state: binding.state } : {}),
    }),
    cas_evidence,
    limits: LIMITS,
  };

  return freezeAttestation(attestation);
}

function freezeAttestation(a: CasAttestation): CasAttestation {
  return Object.freeze(a);
}
