/**
 * ENFORCING_ATOMIC_V1 — versioned profile (roadmap 1090).
 *
 * STRICT_V1 is frozen and is not edited. ATOMIC is a NEW profile: construction
 * aborts with ATOMIC_PROFILE_UNSATISFIED when the invariant conjunction is not
 * wired. Executor behaviour (nonce consume-once, CAS, read-back, attestation)
 * is still observed per call; construction only demands the wiring.
 */
export const PROFILE_ENFORCING_ATOMIC_V1 = 'ENFORCING_ATOMIC_V1' as const;
export const GUARD_ATOMIC_WIRE_VALUE = 'ENFORCING_ATOMIC' as const;
export type AtomicProfileSpelling = 'ENFORCING_ATOMIC' | 'ENFORCING_ATOMIC_V1';

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

export function isEnforcingAtomic(profile: unknown): boolean {
  return profile === 'ENFORCING_ATOMIC' || profile === PROFILE_ENFORCING_ATOMIC_V1;
}

export type AtomicConstructionInput = {
  executionGrant?: { enabled?: boolean; resolveStateNonce?: unknown; grantVersion?: string } | null;
  executorId?: string;
  adapterId?: string;
  targetUri?: string;
  executorAttestation?: { registry?: unknown } | null;
  mutatorRegister?: MutatorRegister | null;
  casAdapter?: unknown;
  readBack?: unknown;
  credentialBoundary?: unknown;
};

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
