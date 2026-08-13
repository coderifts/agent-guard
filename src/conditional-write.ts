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
  /** Whether this call was treated as write-style. */
  write_style: boolean;
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
 * Policy (mirrors requireFreshness Decision-1): when requireConditionalWrite is true
 * and the call is write-style, conditional_write must be true for enforced execution
 * to be eligible. false and not_reported both refuse (distinct from "host said false"
 * vs "host silent" only on the basis field — both block under policy).
 */
export function buildConditionalWriteBasis(input: {
  writeStyle: boolean;
  requireConditionalWrite: boolean;
  ctx?: ConditionalWriteCallContext | null;
}): {
  basis: ConditionalWriteBasis;
  /** If set, enforced execution must not proceed. */
  blockCause?: 'CONDITIONAL_WRITE_REQUIRED';
} {
  const require_conditional_write = input.requireConditionalWrite === true;
  const write_style = input.writeStyle === true;
  const ctx = input.ctx && typeof input.ctx === 'object' ? input.ctx : {};
  const conditional_write = normalizeReport(ctx.conditional_write);

  const basis: ConditionalWriteBasis = {
    conditional_write,
    require_conditional_write,
    write_style,
  };

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

  // Policy on write: only conditional_write:true is eligible for enforced:true.
  if (write_style && require_conditional_write && conditional_write !== true) {
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
  requireConditionalWrite: boolean;
  writeStyle: boolean;
  conditionalWrite: ConditionalWriteReport;
}): string | null {
  if (input.requireConditionalWrite !== true) return null;
  if (input.writeStyle !== true) return null;
  if (input.conditionalWrite === true) return null;
  return RESIDUAL_UNCONDITIONAL_WRITE;
}

// ── Host helper: executeIfUnchanged (CAS surface) ─────────────────────────────────────────────
// Documented at top of file; implemented as pure orchestration. I/O lives in adapters
// (e.g. cas-adapters/fs) that supply current_token + write. Core never invents tokens.

/**
 * Outcome of a conditional write attempt.
 * - committed: write ran under the expected token
 * - refused / stale_version_token: resource token moved; write did NOT run
 */
export type ExecuteIfUnchangedOutcome<T> =
  | { status: 'committed'; result: T; version_token: VersionToken }
  | {
      status: 'refused';
      reason: 'stale_version_token';
      expected_token: VersionToken;
      current_token: VersionToken | null;
    };

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
};

/**
 * Host contract helper: re-check version token, then write or refuse.
 * Equality via tokensEqual only — never interprets token format.
 * Never throws for stale tokens (returns refused); write/current_token errors propagate.
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
  const result = await args.write();
  return { status: 'committed', result, version_token: expected };
}
