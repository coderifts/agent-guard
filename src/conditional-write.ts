/**
 * Conditional-execution surface (reporting only — this package never writes).
 *
 * ACTIVE + FRESH only proves content matched at measurement time. A host that resolves
 * then writes unconditionally still races; the conditional write itself is the host's job.
 * We define the surface, demand it by policy, and report whether the host said it happened.
 *
 * Host contract (executeIfUnchanged):
 *   The host SHOULD perform writes via executeIfUnchanged(write, expected_token) (or
 *   equivalent: only apply the mutation if the resource still holds expected_token).
 *   After the attempt, the host reports on the call context:
 *     - conditional_write: true  — write was conditioned on a version token
 *     - conditional_write: false — write was unconditional (host admits it)
 *     - conditional_write: 'not_reported' — host did not report (DEFAULT; absence ≠ false)
 *   When true, conditioned_on_token is the opaque token the host conditioned on.
 *   Tokens are host-defined (git blob sha, etag, mtime-hash, …). This package never
 *   interprets them — only carries them and compares for equality (===).
 */

'use strict';

/** Host-defined opaque version token. Compared only by string equality. */
export type VersionToken = string;

/**
 * Host resolution surface: content plus an opaque version token.
 * Returned by host resolvers that support conditional execution.
 */
export type VersionedContent = {
  content: string;
  version_token: VersionToken;
};

/**
 * Host report of whether the write was conditioned on a version token.
 * `not_reported` is the default — absence of a report is not false
 * (absent ≠ 0 ≠ null ≠ unknown).
 */
export type ConditionalWriteReport = true | false | 'not_reported';

/**
 * HOW STRONG the atomicity guarantee was — claim language on the mutation side, worded the way the
 * four claim levels are: each class says what it ASSERTS and what it DOES NOT.
 *
 * SAME_TRANSACTION
 *   ASSERTS: the check and the mutation committed inside ONE transaction of the same system, so no
 *   interleaving is possible — the provider, not us, enforces it.
 *   DOES NOT ASSERT: that the transaction was correct, that it was the right row, or anything about
 *   any resource outside that transaction.
 *
 * CONDITIONAL_EXTERNAL
 *   ASSERTS: a SINGLE conditional claim was made against a provider that supports CAS or
 *   idempotency (if-match, expected-version, expected-old-sha), and the result was read back.
 *   DOES NOT ASSERT: atomicity across the check and the mutation. Two systems were involved and the
 *   provider's own compare-and-set is what closed the window — a Redis SETNX followed by a separate
 *   HTTP call is NOT this class and is NOT a transaction, because the claim and the mutation are two
 *   claims against two systems.
 *
 * NON_ATOMIC
 *   ASSERTS: the mutation was applied.
 *   DOES NOT ASSERT: that anything guarded it. The provider lacked the capability, or no
 *   authorization-time token was available, so the write was unconditional. This is the honest
 *   class for "we wrote it and cannot say more", and it must never be reported as either of the
 *   two above.
 */
export type ConditionalWriteGuarantee =
  | 'SAME_TRANSACTION'
  | 'CONDITIONAL_EXTERNAL'
  | 'NON_ATOMIC';

/**
 * Why an outcome is INDETERMINATE. The claim is strictly "we do not know", never "it failed".
 */
export type IndeterminateReason =
  | 'response_lost'          // request sent, no response observed (timeout / socket death)
  | 'ambiguous_provider_reply'
  | 'observation_failed';    // the write may have landed; we could not read back to find out

/**
 * Per-call forensic basis for conditional write (on every GuardOutcome).
 * Survives replay unchanged when recorded.
 */
export type ConditionalWriteBasis = {
  conditional_write: ConditionalWriteReport;
  /**
   * When conditional_write === true, the token the host says it conditioned on.
   * Omitted when not_reported / false / not supplied.
   */
  conditioned_on_token?: VersionToken | null;
  /** Config requireConditionalWrite for this call (policy). */
  require_conditional_write: boolean;
  /** Whether this call was treated as write-style (freshness classification; reporting only). */
  write_style: boolean;
  /**
   * Whether this call was treated as a MUTATION — the fact the policy actually gates on.
   * Independent of artifacts[]: carrying both sides of a change does not make the commit atomic.
   */
  mutating: boolean;
  /**
   * HOW STRONG the guarantee was, when the host reported one. Absent when conditional_write is
   * not_reported — "we were not told" is not a guarantee class. `conditional_write: true` with
   * guarantee NON_ATOMIC is a coherent and important combination: the host conditioned nothing.
   */
  guarantee?: ConditionalWriteGuarantee;
};

/**
 * Values the RUNNER collected / host reported before the pure guard path.
 * Default when omitted: conditional_write 'not_reported'.
 */
export type ConditionalWriteCallContext = {
  conditional_write?: ConditionalWriteReport;
  conditioned_on_token?: VersionToken | null;
  /** Optional versioned content for token carry (equality only). */
  versioned_content?: VersionedContent | null;
  /** Host-reported strength of the guarantee. Carried, never inferred. */
  guarantee?: ConditionalWriteGuarantee;
};

/** Equality compare only — never semantic interpretation of the token. */
export function tokensEqual(
  a: VersionToken | null | undefined,
  b: VersionToken | null | undefined,
): boolean {
  if (a == null || b == null) return false;
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  return a === b;
}

function normalizeReport(raw: unknown): ConditionalWriteReport {
  if (raw === true) return true;
  if (raw === false) return false;
  if (raw === 'not_reported') return 'not_reported';
  return 'not_reported';
}

/**
 * Build per-call conditional-write basis + optional enforce block.
 * Pure once the host report is a value (no I/O).
 *
 * Policy: when requireConditionalWrite is true and the call MUTATES, conditional_write must be
 * true for enforced execution to be eligible. false and not_reported both refuse (distinct from
 * "host said false" vs "host silent" only on the basis field — both block under policy).
 *
 * The gate is `mutating`, NOT `writeStyle`. It once mirrored requireFreshness's write-style
 * predicate; that predicate means "the caller supplied no both-sides snapshot", which is the right
 * question for freshness and the wrong one for atomicity. Under the old gate an ordinary Edit
 * carrying artifacts[] with non-empty before AND after classified as not-write-style and the
 * policy never fired — the demand for an atomic commit was suppressed by evidence about content.
 *
 * `mutating` is optional and defaults to `writeStyle` so a direct caller of this pure export keeps
 * its previous behaviour; guardToolCall always supplies it.
 */
export function buildConditionalWriteBasis(input: {
  writeStyle: boolean;
  /** Artifact-independent mutation classification (isMutatingCall). Defaults to writeStyle. */
  mutating?: boolean;
  requireConditionalWrite: boolean;
  ctx?: ConditionalWriteCallContext | null;
}): {
  basis: ConditionalWriteBasis;
  /** If set, enforced execution must not proceed. */
  blockCause?: 'CONDITIONAL_WRITE_REQUIRED';
} {
  const require_conditional_write = input.requireConditionalWrite === true;
  const write_style = input.writeStyle === true;
  // Absent `mutating` = legacy call site: fall back to write_style, never widen silently.
  const mutating = input.mutating === undefined ? write_style : input.mutating === true;
  const ctx = input.ctx && typeof input.ctx === 'object' ? input.ctx : {};
  const conditional_write = normalizeReport(ctx.conditional_write);

  const basis: ConditionalWriteBasis = {
    conditional_write,
    require_conditional_write,
    write_style,
    mutating,
  };

  // Guarantee carry: reported only, never inferred from the report being true.
  if (ctx.guarantee === 'SAME_TRANSACTION'
    || ctx.guarantee === 'CONDITIONAL_EXTERNAL'
    || ctx.guarantee === 'NON_ATOMIC') {
    basis.guarantee = ctx.guarantee;
  }

  // Token carry: prefer explicit conditioned_on_token, else versioned_content.version_token.
  if (conditional_write === true) {
    if (typeof ctx.conditioned_on_token === 'string') {
      basis.conditioned_on_token = ctx.conditioned_on_token;
    } else if (
      ctx.versioned_content
      && typeof ctx.versioned_content === 'object'
      && typeof ctx.versioned_content.version_token === 'string'
    ) {
      basis.conditioned_on_token = ctx.versioned_content.version_token;
    } else if (ctx.conditioned_on_token === null) {
      basis.conditioned_on_token = null;
    }
  }

  // Policy on mutation: only conditional_write:true is eligible for enforced:true.
  if (mutating && require_conditional_write && conditional_write !== true) {
    return { basis, blockCause: 'CONDITIONAL_WRITE_REQUIRED' };
  }
  return { basis };
}

/** Residual name when policy requires conditional write but host did not report true. */
export const RESIDUAL_UNCONDITIONAL_WRITE = 'composition_unconditional_write_under_policy';

/**
 * Coverage residual when requireConditionalWrite is on and the host report is not true.
 * inescapable_runtime must stay false — we report what the host told us, never claim compliance.
 */
export function conditionalWriteResidual(input: {
  /** Artifact-independent mutation classification. Defaults to writeStyle when omitted. */
  mutating?: boolean;
  requireConditionalWrite: boolean;
  writeStyle: boolean;
  conditionalWrite: ConditionalWriteReport;
}): string | null {
  if (input.requireConditionalWrite !== true) return null;
  const mutating = input.mutating === undefined ? input.writeStyle === true : input.mutating === true;
  if (!mutating) return null;
  if (input.conditionalWrite === true) return null;
  return RESIDUAL_UNCONDITIONAL_WRITE;
}

// ── Host helper: executeIfUnchanged (CAS surface) ─────────────────────────────────────────────
// Documented at top of file; implemented as pure orchestration. I/O lives in adapters
// (e.g. cas-adapters/fs) that supply current_token + write. Core never invents tokens.

/**
 * Outcome of a conditional write attempt.
 * - committed: write ran under the expected token; post-check (if any) agreed
 * - refused / stale_version_token: resource token moved BEFORE write; write did NOT run
 * - committed_stale_detected / stale_during_commit: write DID run, but a post-commit
 *   re-check found the resource no longer matches the write's expected post-state
 *   (detection only — not a rollback)
 */
export type ExecuteIfUnchangedOutcome<T> =
  | { status: 'committed'; result: T; version_token: VersionToken; observed_token?: VersionToken | null }
  | {
      status: 'refused';
      reason: 'stale_version_token';
      expected_token: VersionToken;
      current_token: VersionToken | null;
    }
  | {
      /**
       * FIRST-CLASS UNKNOWN. The mutation may or may not have been applied — we sent it and could
       * not observe the result. Distinct from 'refused' (we know it did not land) and from
       * 'committed' (we know it did).
       *
       * The rule is strict and is the whole point of the class:
       *   - NEVER blindly retry. A retry of a write that already landed is a second mutation.
       *   - Reconciliation is REQUIRED: read the resource and establish which state holds.
       *   - Downstream MUST block until it is resolved. An indeterminate write is not a pass.
       */
      status: 'indeterminate';
      reason: IndeterminateReason;
      expected_token: VersionToken;
      /** What we managed to observe, if anything. null when observation itself failed. */
      observed_token?: VersionToken | null;
      detail?: string;
    }
  | {
      status: 'committed_stale_detected';
      reason: 'stale_during_commit';
      result: T;
      expected_token: VersionToken;
      post_commit_token: VersionToken | null;
      observed_token?: VersionToken | null;
    };

/**
 * Thrown from write() when the adapter aborts BEFORE applying the mutation
 * (e.g. pre-rename re-check). executeIfUnchanged maps this to status:'refused'.
 * Not a public host API — adapters use it to stay on the single helper path.
 */
export class StaleVersionTokenAbort extends Error {
  readonly current_token: VersionToken | null;
  constructor(current_token: VersionToken | null) {
    super('stale_version_token');
    this.name = 'StaleVersionTokenAbort';
    this.current_token = current_token;
  }
}

export type ExecuteIfUnchangedArgs<T> = {
  /** Token the host measured before deciding to write (opaque string). */
  expected_token: VersionToken;
  /**
   * Re-read the resource's token immediately before commit.
   * Return null when the resource is gone / unreadable (treated as mismatch).
   */
  current_token: () => VersionToken | null | Promise<VersionToken | null>;
  /** Mutation applied ONLY when current_token equals expected_token. */
  write: () => T | Promise<T>;
  /**
   * Opt-in post-commit detection (default false — byte-identical old paths).
   * When true AND expected_after_commit is provided: after write(), re-read
   * current_token and compare to expected_after_commit(result). Mismatch →
   * committed_stale_detected (write already happened; honest report only).
   *
   * NOTE: do NOT compare post-commit to expected_token for content-changing
   * writes — the token is supposed to change. Supply the token of the written state.
   */
  detect_stale_during_commit?: boolean;
  /**
   * Token that should hold after a successful write (the written state's token).
   * Required when detect_stale_during_commit is true; ignored otherwise.
   */
  expected_after_commit?: (
    result: T,
  ) => VersionToken | null | Promise<VersionToken | null>;
};

/**
 * Host contract helper: re-check version token, then write or refuse.
 * Equality via tokensEqual only — never interprets token format.
 * Never throws for stale tokens (returns refused / committed_stale_detected);
 * write/current_token errors (other than StaleVersionTokenAbort) propagate.
 */
export async function executeIfUnchanged<T>(
  args: ExecuteIfUnchangedArgs<T>,
): Promise<ExecuteIfUnchangedOutcome<T>> {
  const expected = args.expected_token;
  if (typeof expected !== 'string' || expected.length === 0) {
    return {
      status: 'refused',
      reason: 'stale_version_token',
      expected_token: typeof expected === 'string' ? expected : '',
      current_token: null,
    };
  }
  const current = await args.current_token();
  if (!tokensEqual(expected, current)) {
    return {
      status: 'refused',
      reason: 'stale_version_token',
      expected_token: expected,
      current_token: current == null ? null : current,
    };
  }

  let result: T;
  try {
    result = await args.write();
  } catch (err) {
    if (err instanceof StaleVersionTokenAbort) {
      return {
        status: 'refused',
        reason: 'stale_version_token',
        expected_token: expected,
        current_token: err.current_token,
      };
    }
    throw err;
  }

  // T3: always re-read current_token after write (same host reader executeIfUnchanged already required).
  // Detection (opt-in) reuses this read — not a second I/O. Observation failure must not fail the write.
  let observed_token: VersionToken | null = null;
  try {
    observed_token = await args.current_token();
  } catch (err) {
    if (args.detect_stale_during_commit === true) throw err;
    observed_token = null;
  }

  // Post-commit detection (best-effort honesty, not prevention).
  if (args.detect_stale_during_commit === true && typeof args.expected_after_commit === 'function') {
    const want = await args.expected_after_commit(result);
    if (!tokensEqual(want, observed_token)) {
      return {
        status: 'committed_stale_detected',
        reason: 'stale_during_commit',
        result,
        expected_token: expected,
        post_commit_token: observed_token,
        observed_token,
      };
    }
  }

  return { status: 'committed', result, version_token: expected, observed_token };
}
