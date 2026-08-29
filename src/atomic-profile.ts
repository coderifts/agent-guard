/**
 * ENFORCING_ATOMIC_V1 — versioned profile (roadmap 1090).
 *
 * STRICT_V1 is frozen and is not edited. ATOMIC is a NEW profile: construction
 * aborts with ATOMIC_PROFILE_UNSATISFIED when the invariant conjunction is not
 * wired. Executor behaviour (nonce consume-once, CAS, read-back, attestation)
 * is still observed per call; construction only demands the wiring.
 */
import { verifyPostureReceipt } from './posture-receipt.js';
import type { PostureVerifyInput } from './posture-receipt.js';

export const PROFILE_ENFORCING_ATOMIC_V1 = 'ENFORCING_ATOMIC_V1' as const;

/**
 * ENFORCING_ATOMIC_V2 (roadmap 1167) — V1 plus a VERIFIED credential boundary.
 *
 * WHY A NEW NAME RATHER THAN A STRICTER _V1. with-coderifts.ts:228 states the
 * rule this package learned from its own 10.0.0 and 12.0.0 releases: "The next
 * tightening MUST be `_V2`; adding a condition to `_V1` reintroduces the defect
 * this type exists to remove." A caller who wrote `_V1` keeps exactly the
 * contract they asked for; the stricter check costs them nothing.
 *
 * WHAT V2's credential_boundary PROVES:
 *   A signed `cr.posture.receipt.v1` verified against a caller-supplied key
 *   (registry or pinned PEM) asserts `verdict: 'PASS'` — the credential
 *   boundary was read back out of the live catalog at `measured_at`, that
 *   reading is inside the caller's freshness window, and the receipt is bound
 *   to this `deployment_id`.
 *
 * WHAT IT DOES NOT PROVE, and this list is the point rather than a caveat:
 *   · NOT a tuple the CALLER did not name. executor_id, adapter_id, target_uri
 *     and policy_hash ARE now bound (AUDIT P1 / RES-3) — but each only when the
 *     construction configures it. The earlier text here said the producer does
 *     not sign those fields; re-measured 2026-08-29 against capability-demo
 *     demo/src/posture.js, the issuer spreads them into the SIGNED canonical
 *     body whenever they carry real content, so binding them is backed by the
 *     producer rather than asserted over it. What has NOT changed is the rule
 *     underneath: a field nobody configured is reported in the verifier's
 *     `not_bound` list, never defaulted into looking checked.
 *   · NOT an expiry. The receipt carries `measured_at` and no `expires_at`, so
 *     the age check is a FRESHNESS window the CALLER supplies via `maxAgeMs`.
 *     A guard-side default would present our policy as the receipt's statement.
 *   · NOT executor behaviour. Same honest limit as every other invariant here:
 *     construction demands wiring, and a read-back at `measured_at` is a fact
 *     about that moment, not about the write that happens afterwards.
 */
export const PROFILE_ENFORCING_ATOMIC_V2 = 'ENFORCING_ATOMIC_V2' as const;

/**
 * The unsuffixed wire value stays pinned to V1 FOREVER (with-coderifts.ts:231-233).
 * Re-pointing it at V2 would silently move every existing caller — the migration
 * the versioned names exist to refuse.
 */
export const GUARD_ATOMIC_WIRE_VALUE = 'ENFORCING_ATOMIC' as const;
export type AtomicProfileSpelling = 'ENFORCING_ATOMIC' | 'ENFORCING_ATOMIC_V1' | 'ENFORCING_ATOMIC_V2';

export const ATOMIC_PROFILE_UNSATISFIED = 'ATOMIC_PROFILE_UNSATISFIED' as const;

export type AtomicOutcome = 'AUTHORIZED_COMMITTED' | 'REFUSED' | 'INDETERMINATE';

/** Frozen invariant names — adding one is ATOMIC_V2, not an edit here. */
export const ATOMIC_INVARIANTS = Object.freeze([
  'verified_receipt',
  'verified_grant_v2',
  'exact_executor',
  'exact_target',
  'after_payload_hash',
  'fresh_nonce',
  'nonce_consumed_once',
  'target_CAS',
  'read_back',
  'executor_attestation',
  'credential_boundary',
] as const);

export type MutatorRegister = {
  registerMutator: (name: string) => MutatorRegister;
  has: (name: string) => boolean;
  list: () => readonly string[];
};

export function createMutatorRegister(): MutatorRegister {
  const names = new Set<string>();
  const api: MutatorRegister = {
    registerMutator(name: string) {
      if (typeof name !== 'string' || name.trim() === '') {
        throw new Error('registerMutator: non-empty name required');
      }
      names.add(name);
      return api;
    },
    has(name: string) {
      return names.has(name);
    },
    list() {
      return Object.freeze([...names]);
    },
  };
  return api;
}

export function isEnforcingAtomic(profile: unknown): profile is AtomicProfileSpelling {
  return profile === 'ENFORCING_ATOMIC'
    || profile === PROFILE_ENFORCING_ATOMIC_V1
    || profile === PROFILE_ENFORCING_ATOMIC_V2;
}

/** V2 only. The unsuffixed alias is V1 and must never answer true here. */
export function isEnforcingAtomicV2(profile: unknown): boolean {
  return profile === PROFILE_ENFORCING_ATOMIC_V2;
}

export type AtomicConstructionInput = {
  executionGrant?: { enabled?: boolean; resolveStateNonce?: unknown; grantVersion?: string } | null;
  executorId?: string;
  adapterId?: string;
  targetUri?: string;
  /**
   * MEASURED: executorId/adapterId/targetUri already existed here; policyHash
   * did not exist anywhere in this package — its only mention was the comment
   * above saying it was not bound. Added so the tuple can be STATED, not so it
   * can be assumed: leaving it unset binds nothing, and says so.
   */
  policyHash?: string;
  executorAttestation?: { registry?: unknown } | null;
  mutatorRegister?: MutatorRegister | null;
  casAdapter?: unknown;
  readBack?: unknown;
  credentialBoundary?: unknown;
  /** V2 ONLY. Ignored on V1, whose credential_boundary check is frozen. */
  profile?: AtomicProfileSpelling;
};

/**
 * V2 caller-supplied freshness window must be finite, positive, and ≤ 24h.
 * A larger value is not a freshness check (the receipt has no expires_at).
 */
export const ATOMIC_V2_MAX_AGE_MS_CAP = 86_400_000;

/**
 * V2 credential_boundary input. A bare `true` is deliberately NOT assignable.
 */
export type VerifiedCredentialBoundary = {
  postureReceipt: string;
  registry?: PostureVerifyInput['registry'];
  pinnedKeyPem?: string;
  deploymentId?: string;
  maxAgeMs?: number;
  now?: () => number;
};

export const CREDENTIAL_BOUNDARY_BARE_REJECTED =
  'credential_boundary: a verified cr.posture.receipt.v1 is required; a bare assertion is no '
  + 'longer accepted. ENFORCING_ATOMIC_V1 still accepts the bare form and is frozen — move to '
  + '_V2 to get this check.';

export function atomicConstructionProblems(input: AtomicConstructionInput): string[] {
  const problems: string[] = [];
  const grant = input.executionGrant;
  if (!(grant && grant.enabled === true)) {
    problems.push('verified_grant_v2: executionGrant.enabled must be true');
  }
  if (!(grant && grant.grantVersion === 'v2')) {
    problems.push('verified_grant_v2: executionGrant.grantVersion must be \'v2\'');
  }
  if (typeof grant?.resolveStateNonce !== 'function') {
    problems.push('fresh_nonce: executionGrant.resolveStateNonce required');
  }
  if (typeof input.executorId !== 'string' || input.executorId.length === 0) {
    problems.push('exact_executor: executorId required');
  }
  if (typeof input.targetUri !== 'string' || input.targetUri.length === 0) {
    problems.push('exact_target: targetUri required');
  }
  if (typeof input.adapterId !== 'string' || input.adapterId.length === 0) {
    problems.push('after_payload_hash: adapterId required (payload bind surface)');
  }
  if (!(input.executorAttestation && input.executorAttestation.registry)) {
    problems.push('executor_attestation: executorAttestation.registry required');
  }
  if (!input.mutatorRegister || typeof input.mutatorRegister.registerMutator !== 'function'
      || input.mutatorRegister.list().length === 0) {
    problems.push('credential_boundary: mutatorRegister with ≥1 registerMutator required');
  }
  if (input.casAdapter == null) {
    problems.push('target_CAS: casAdapter required');
  }
  if (typeof input.readBack !== 'function') {
    problems.push('read_back: readBack function required');
  }
  if (input.credentialBoundary !== true && typeof input.credentialBoundary !== 'object') {
    problems.push('credential_boundary: credentialBoundary assertion required');
  }

  // ── V2 ONLY (1167). The two lines above are the FROZEN V1 check and are not
  // edited: on V1 a bare `true` still satisfies credential_boundary, exactly as
  // it did before this file gained a V2. Everything below runs only when the
  // caller asked for _V2, which is what makes the tightening opt-in.
  if (isEnforcingAtomicV2(input.profile)) {
    const cb = input.credentialBoundary as Partial<VerifiedCredentialBoundary> | true | undefined;
    if (cb === true || !cb || typeof cb !== 'object' || typeof cb.postureReceipt !== 'string') {
      problems.push(CREDENTIAL_BOUNDARY_BARE_REJECTED);
    } else if (!cb.registry && !cb.pinnedKeyPem) {
      problems.push(
        'credential_boundary: credentialBoundary.registry or .pinnedKeyPem required — the posture '
        + 'receipt is verified against a caller-supplied key; this package never fetches one.',
      );
    } else {
      const deploymentId = typeof cb.deploymentId === 'string' ? cb.deploymentId : '';
      if (deploymentId.length === 0) {
        problems.push(
          'credential_boundary: credentialBoundary.deploymentId required under ENFORCING_ATOMIC_V2 — '
          + 'the posture receipt must be bound to this deployment.',
        );
      }
      const maxAgeMs = cb.maxAgeMs;
      const maxAgeOk = typeof maxAgeMs === 'number'
        && Number.isFinite(maxAgeMs)
        && maxAgeMs > 0
        && maxAgeMs <= ATOMIC_V2_MAX_AGE_MS_CAP;
      if (typeof maxAgeMs !== 'number' || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0) {
        problems.push(
          'credential_boundary: credentialBoundary.maxAgeMs required under ENFORCING_ATOMIC_V2 — '
          + 'a finite positive freshness window; the receipt signs measured_at and no expires_at.',
        );
      } else if (maxAgeMs > ATOMIC_V2_MAX_AGE_MS_CAP) {
        problems.push(
          `credential_boundary: credentialBoundary.maxAgeMs exceeds the ${ATOMIC_V2_MAX_AGE_MS_CAP}ms `
          + 'cap (24h). A larger window is not a freshness check.',
        );
      }
      // V2 calls the verifier only with both mandatory args present — a call with neither
      // is itself a construction problem (the verifier stays permissive when invoked directly).
      if (deploymentId.length > 0 && maxAgeOk) {
        // The credential-boundary tuple, from the construction input rather than
        // from anywhere this function could invent it. Each is passed ONLY when
        // configured: an absent one reaches the verifier as undefined and comes
        // back named in `not_bound` — the honest record of a boundary this
        // deployment never stated.
        const r = verifyPostureReceipt(cb.postureReceipt, {
          registry: cb.registry,
          pinnedKeyPem: cb.pinnedKeyPem,
          expectedDeploymentId: deploymentId,
          expectedExecutorId: input.executorId,
          expectedAdapterId: input.adapterId,
          expectedTargetUri: input.targetUri,
          expectedPolicyHash: input.policyHash,
          maxAgeMs,
          now: cb.now,
        });
        if (!r.valid) {
          problems.push(
            `credential_boundary: posture receipt not verified — ${r.status} (${r.reason}). `
            + (r.status === 'POSTURE_STALE'
              ? 'This is the caller-supplied freshness window (maxAgeMs), not a receipt-carried '
                + 'expiry: cr.posture.receipt.v1 signs measured_at and no expires_at.'
              : r.status === 'POSTURE_FAIL'
                ? 'The signature verified; the posture did not. A signed FAIL is a drift artifact — '
                  + 'the boundary regressed, the receipt is intact.'
                : 'Supply a posture receipt signed by a key in the registry, bound to this '
                  + 'deployment_id, with verdict PASS.'),
          );
        }
      }
    }
  }

  return problems;
}

export function throwAtomicUnsatisfied(problems: string[]): never {
  const err = new Error(
    `withCodeRifts: ${ATOMIC_PROFILE_UNSATISFIED} — ${problems.length} condition(s):\n`
    + problems.map((p) => `  - ${p}`).join('\n'),
  );
  (err as Error & { code: string }).code = ATOMIC_PROFILE_UNSATISFIED;
  throw err;
}

/**
 * Per-call outcome union. Host-claimed commit never AUTHORIZED_COMMITTED.
 */
export function atomicOutcome(input: {
  receiptVerified: boolean;
  grantV2Valid: boolean;
  executorMatch: boolean;
  targetMatch: boolean;
  nonceFresh: boolean;
  nonceConsumedOnce: boolean;
  casCommitted: boolean;
  readBackOk: boolean;
  executorAttested: boolean;
  mutatorRegistered: boolean;
  authUnavailable?: boolean;
  nonceStoreUnavailable?: boolean;
  readBackUnavailable?: boolean;
  signerUnavailableAfterCommit?: boolean;
}): AtomicOutcome {
  if (input.authUnavailable || input.nonceStoreUnavailable || input.readBackUnavailable) {
    return 'INDETERMINATE';
  }
  if (input.signerUnavailableAfterCommit && input.casCommitted) {
    return 'INDETERMINATE';
  }
  const ok = input.receiptVerified && input.grantV2Valid && input.executorMatch
    && input.targetMatch && input.nonceFresh && input.nonceConsumedOnce
    && input.casCommitted && input.readBackOk && input.executorAttested
    && input.mutatorRegistered;
  if (ok && input.executorAttested) return 'AUTHORIZED_COMMITTED';
  return 'REFUSED';
}
