/**
 * Freshness-safe prior content — PURE comparison core (TOCTOU close for the fresh-snapshot conjunct).
 *
 * Settled decisions (do not relitigate):
 *   1. Freshness is CONTENT IDENTITY, not time. No TTL. Byte identity of `before` vs gate-time resolve.
 *   2. The caller NAMES (artifact id); the gate RESOLVES prior content. A caller-supplied `before`
 *      is a claim, not a measurement — no fallback ladder that relabels a guess as measured.
 *   3. Four outcomes, never collapsed: TARGET_MUTATED | STALE_CONTEXT | TAMPERED | UNKNOWN_FRESHNESS.
 *   4. STALE_CONTEXT fails closed by default; policy may opt out deliberately.
 *   5. Tree hash is OPTIONAL in the binding. Without it, STALE_CONTEXT is skipped, TARGET_MUTATED
 *      still runs, and the result SAYS the reduced level (never silently pretends full check ran).
 *
 * Merge-gate pattern generalized: recompute from current inputs; compare to what preflight bound;
 * do not trust a claim about itself. Tree hash stays OUT of verdict_fingerprint and input_fingerprint
 * (those preimages are frozen — their frozenness is what makes recompute meaningful).
 *
 * PURE: no I/O, no network, no Date.now(). Host supplies resolved content as inputs.
 */

import { createHash } from 'node:crypto';

// ── outcomes ─────────────────────────────────────────────────────────────────────────────────────

/**
 * Four outcomes. Callers distinguish them by the `outcome` field (never by message text alone).
 *
 *   TARGET_MUTATED     — the contract `before` bytes moved (field removal, type change, …)
 *   STALE_CONTEXT      — repository path-set tree moved, contract `before` identical (e.g. format-only
 *                        neighbouring files, or raw blob change with same contract content). Message
 *                        MUST state this is not tampering.
 *   TAMPERED           — contract moved AND tree moved (both axes disagree)
 *   UNKNOWN_FRESHNESS  — a candidate was named, but current state is not measurable (missing resolve)
 *
 * Plus FRESH when both applicable axes match.
 */
export type FreshnessOutcome =
  | 'FRESH'
  | 'TARGET_MUTATED'
  | 'STALE_CONTEXT'
  | 'TAMPERED'
  | 'UNKNOWN_FRESHNESS';

/**
 * Which axes were eligible to run.
 *   full           — tree hash was bound; contract + tree both evaluated
 *   contract_only  — no tree hash on the binding; only TARGET_MUTATED axis ran (reported, not silent)
 */
export type FreshnessCheckLevel = 'full' | 'contract_only';

export type FreshnessAssessInput = {
  /**
   * Contract `before` that entered preflight (and thus digests / the decision). Bound measurement —
   * not a host claim at execute time.
   */
  preflightBefore: string;
  /**
   * Gate-resolved prior content for the same artifact id NOW.
   * null/undefined = current state not measurable → UNKNOWN_FRESHNESS.
   * The gate (or host adapter feeding the gate) supplies this by resolving the caller's artifact id;
   * a caller-supplied `before` string must NOT be passed here as if measured.
   */
  resolvedBeforeNow: string | null | undefined;
  /**
   * Optional tree commitment bound at preflight (additive; NOT in input_fingerprint / verdict_fp).
   * Absent/empty → level is contract_only; STALE_CONTEXT axis is skipped.
   */
  preflightTreeHash?: string | null;
  /**
   * Tree commitment recomputed at gate time from the same path set + current blobs.
   * Only consulted when preflightTreeHash is present.
   * null/undefined when tree was bound but cannot be re-measured → UNKNOWN_FRESHNESS.
   */
  resolvedTreeHashNow?: string | null | undefined;
  /**
   * Policy opt-out for STALE_CONTEXT only (default false = fail closed).
   * TARGET_MUTATED / TAMPERED / UNKNOWN_FRESHNESS are never opted out by this flag.
   * Same shape as an explicit team choice (approver allowlist): say so deliberately.
   */
  allowStaleContext?: boolean;
};

export type FreshnessAssessResult = {
  outcome: FreshnessOutcome;
  /** Which axes ran. Always set — even on FRESH — so a reduced check cannot look like a full one. */
  level: FreshnessCheckLevel;
  /** True when the gate must refuse enforced execution. */
  failClosed: boolean;
  /** Contract before bytes match (only meaningful when resolvedBeforeNow was measurable). */
  contractMatch: boolean | null;
  /** Tree match; null when tree axis skipped or unmeasurable. */
  treeMatch: boolean | null;
  /**
   * Human message. For STALE_CONTEXT always includes that this is not tampering.
   * Machine consumers should branch on `outcome`, not parse the message.
   */
  message: string;
};

// ── write-style input (gateable?) ────────────────────────────────────────────────────────────────

/**
 * Write-style call: path + new content only is the shape the composition residual names.
 * Gateable requires an artifact identifier the gate can resolve — not a caller-supplied before.
 */
export type WriteStylePriorInput = {
  /** Artifact id from a prior preflight artifacts[] entry (caller names; gate resolves). */
  artifactId?: string | null;
  path?: string | null;
  /** New content (the write payload). */
  after?: string | null;
  /**
   * If present, this is a CLAIM. It is never treated as a measurement and never substitutes
   * for artifactId. Recorded only so tests can assert there is no "use claimed before" ladder.
   */
  claimedBefore?: string | null;
};

export type WriteStylePriorResult = {
  gateable: boolean;
  reason:
    | 'ok'
    | 'MISSING_ARTIFACT_ID'
    | 'CLAIMED_BEFORE_NOT_MEASUREMENT';
  message: string;
  /** Always false — claimedBefore is never elevated to a measurement. */
  claimedBeforeAcceptedAsMeasurement: false;
};

// ── pure digests (tree hash OUT of frozen fingerprint preimages) ─────────────────────────────────

function sha256hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Byte identity of two content strings (freshness definition: not time, not TTL). */
export function contentByteIdentical(a: string, b: string): boolean {
  return a === b;
}

/**
 * Optional path-set tree commitment. Additive only — never fold into input_fingerprint or
 * verdict_fingerprint. Preimage: sorted path + sha256(content), then outer sha256.
 * Missing content for a path is the caller's problem: pass only complete pairs.
 */
export function computePathSetTreeHash(
  entries: ReadonlyArray<{ path: string; content: string }>,
): string {
  const parts = entries
    .slice()
    .map((e) => ({ path: String(e.path), content: String(e.content) }))
    .sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0))
    .map((e) => `${e.path}\x1f${sha256hex(e.content)}`);
  return `sha256:${sha256hex(parts.join('\x1e'))}`;
}

// ── assess ───────────────────────────────────────────────────────────────────────────────────────

const MSG = {
  FRESH_FULL:
    'Prior content is fresh: gate-resolved before matches preflight (byte identity); tree commitment matches.',
  FRESH_CONTRACT_ONLY:
    'Prior content is fresh at contract level (byte identity of before). '
    + 'Tree-hash check was not bound on this receipt — level is contract_only, not full.',
  TARGET_MUTATED:
    'TARGET_MUTATED: gate-resolved contract before differs from preflight (byte identity failed). '
    + 'The contract itself changed under the bound artifact; re-preflight.',
  STALE_CONTEXT:
    'STALE_CONTEXT: repository path-set tree moved, but the contract before is byte-identical. '
    + 'This is NOT tampering — neighbouring or formatting-only material changed while the analyzed '
    + 'contract content did not. Default policy fails closed; set allowStaleContext to accept deliberately.',
  TAMPERED:
    'TAMPERED: contract before moved AND tree commitment moved. Both axes disagree with the preflight binding.',
  UNKNOWN_BEFORE:
    'UNKNOWN_FRESHNESS: artifact was named but current prior content is not measurable '
    + '(gate could not resolve before at execution time). Not the same as a measured mismatch.',
  UNKNOWN_TREE:
    'UNKNOWN_FRESHNESS: tree hash was bound on the preflight, but current tree commitment is not measurable. '
    + 'Not the same as STALE_CONTEXT (which requires a measured tree that differs).',
} as const;

/**
 * Assess freshness of prior content by recompute-and-compare (merge-gate pattern generalized).
 *
 * Pure. Does not read the filesystem; the host/adapter resolves artifact id → content and passes
 * `resolvedBeforeNow` / optional tree hashes as inputs.
 */
export function assessFreshness(input: FreshnessAssessInput): FreshnessAssessResult {
  const hasTreeBinding =
    typeof input.preflightTreeHash === 'string' && input.preflightTreeHash.length > 0;
  const level: FreshnessCheckLevel = hasTreeBinding ? 'full' : 'contract_only';

  // Current prior must be measurable.
  if (input.resolvedBeforeNow === null || input.resolvedBeforeNow === undefined) {
    return {
      outcome: 'UNKNOWN_FRESHNESS',
      level,
      failClosed: true,
      contractMatch: null,
      treeMatch: hasTreeBinding ? null : null,
      message: MSG.UNKNOWN_BEFORE,
    };
  }

  const contractMatch = contentByteIdentical(
    String(input.preflightBefore),
    String(input.resolvedBeforeNow),
  );

  // Tree axis: only when bound (Decision 5).
  let treeMatch: boolean | null = null;
  if (hasTreeBinding) {
    if (input.resolvedTreeHashNow === null || input.resolvedTreeHashNow === undefined) {
      return {
        outcome: 'UNKNOWN_FRESHNESS',
        level: 'full',
        failClosed: true,
        contractMatch,
        treeMatch: null,
        message: MSG.UNKNOWN_TREE,
      };
    }
    treeMatch = contentByteIdentical(
      String(input.preflightTreeHash),
      String(input.resolvedTreeHashNow),
    );
  }

  // Four outcomes from the two axes (tree may be skipped).
  if (!contractMatch && treeMatch === false) {
    return {
      outcome: 'TAMPERED',
      level,
      failClosed: true,
      contractMatch,
      treeMatch,
      message: MSG.TAMPERED,
    };
  }
  if (!contractMatch) {
    return {
      outcome: 'TARGET_MUTATED',
      level,
      failClosed: true,
      contractMatch,
      treeMatch,
      message: MSG.TARGET_MUTATED,
    };
  }
  if (contractMatch && treeMatch === false) {
    const allow = input.allowStaleContext === true;
    return {
      outcome: 'STALE_CONTEXT',
      level,
      // Default closed; policy opt-out only for this outcome (Decision 4).
      failClosed: !allow,
      contractMatch,
      treeMatch,
      message: MSG.STALE_CONTEXT,
    };
  }

  // contractMatch && (treeMatch === true || treeMatch === null)
  return {
    outcome: 'FRESH',
    level,
    failClosed: false,
    contractMatch,
    treeMatch,
    message: level === 'full' ? MSG.FRESH_FULL : MSG.FRESH_CONTRACT_ONLY,
  };
}

/**
 * Write-style prior requirements (Decision 2).
 * Caller must supply artifactId. claimedBefore is never accepted as measurement.
 */
export function assessWriteStylePrior(input: WriteStylePriorInput): WriteStylePriorResult {
  const id = input.artifactId;
  if (typeof id !== 'string' || id.trim().length === 0) {
    // If they only offered a claimed before, still missing the identifier — and do not climb a ladder.
    const claimed = typeof input.claimedBefore === 'string' && input.claimedBefore.length > 0;
    return {
      gateable: false,
      reason: claimed ? 'CLAIMED_BEFORE_NOT_MEASUREMENT' : 'MISSING_ARTIFACT_ID',
      claimedBeforeAcceptedAsMeasurement: false,
      message: claimed
        ? 'Write-style call supplied claimed before content without an artifact id. '
          + 'A caller-supplied before is a claim, not a measurement. '
          + 'Pass the artifact id from the preflight artifacts[] entry; the gate resolves prior content.'
        : 'Write-style call is missing an artifact identifier. '
          + 'Pass the id from a prior preflight artifacts[] entry (path + new content alone is not gateable). '
          + 'The gate resolves prior content; do not invent a before.',
    };
  }
  return {
    gateable: true,
    reason: 'ok',
    claimedBeforeAcceptedAsMeasurement: false,
    message: 'Artifact id present; gate may resolve prior content for freshness recompute.',
  };
}

/**
 * Convenience: whether enforced execution is allowed for this freshness result.
 * Equivalent to !failClosed: FRESH always; STALE_CONTEXT only when the team opted out;
 * TARGET_MUTATED / TAMPERED / UNKNOWN never.
 */
export function freshnessAllowsEnforce(result: FreshnessAssessResult): boolean {
  return result.failClosed === false;
}
