/**
 * repo-merge-gate (#7) — the PURE gate decision (repo-merge-gate-SPEC §1). Placement B: the repo-side
 * required-status-check logic that answers "may THIS PR head merge, given the finished receipt and the
 * observed branch-protection state?"
 *
 * This is a PURE function — it performs NO I/O and makes NO GitHub call (branch protection is an
 * INPUT, observed by the host and passed in). It does NOT re-decide: it reads only the finished
 * receipt fields (decision / lifecycle authz / binding) — the deterministic verdict stays the
 * server's (M5). Same inputs → same output (M8).
 *
 * Scope honesty is the whole point (§4): `inescapable_merge` is true ONLY in the fully-enforcing,
 * non-bypassable case. For absent / advisory / unknown protection, or when an admin can bypass the
 * required check, the check may still be `success` for visibility but `inescapable_merge` is FALSE
 * with the residual named. It never claims more than the platform actually enforces.
 *
 * Public source (ships in the npm package): it references only receipt/protection fields and generic
 * merge-gate concepts — no scoring logic, weights, thresholds, pattern names, endpoints, or secrets.
 */

export type GateStatusState = 'success' | 'failure' | 'pending';

/** Gate reason codes (§1.1 + honesty residuals). Success uses allow_current_head;
 *  protection_* / admin_bypass_open / required_check_app_* / change_set_not_rebound name honesty
 *  residuals on an otherwise-green check; fingerprint_mismatch is a hard failure (not a residual);
 *  server_unreachable is a host-supplied fail-closed policy input. */
export type GateReason =
  | 'allow_current_head'
  | 'no_receipt'
  | 'receipt_not_authorized'
  | 'stale_head'
  | 'fingerprint_mismatch'
  | 'operation_mismatch'
  | 'target_mismatch'
  | 'decision_not_allow'
  | 'body_hash_mismatch'
  | 'protection_not_configured'
  | 'protection_advisory_only'
  | 'admin_bypass_open'
  | 'inputs_incomplete'
  | 'server_unreachable'
  /** Host did not report whether the required check is app-bound (field absent). Not the same as not bound. */
  | 'required_check_app_binding_unknown'
  /** Host reported the required check is not bound to a GitHub App (name-only / spoofable). */
  | 'required_check_app_not_bound'
  /**
   * Host did not supply expected_fingerprint — the optional change-set re-bind was skipped.
   * Residual only (does not flip merge_allowed / inescapable_merge). Distinct from
   * fingerprint_mismatch, which is the hard failure when a re-bind WAS requested and disagreed.
   */
  | 'change_set_not_rebound';

export type EnforcementState = 'ENFORCING' | 'ADVISORY' | 'UNKNOWN' | 'ABSENT';

/** A view of the finished receipt (fields already produced by the server + lifecycle evaluation).
 *  Reuses the shipped field names — the gate never re-derives any of them. */
export type ReceiptView = {
  /** Lifecycle authorization result (NOT signature validity alone). */
  currently_authorized: boolean;
  authz_reason?: string;
  decision: 'ALLOW' | 'WARN' | 'REQUIRE_APPROVAL' | 'BLOCK' | string;
  execution_action?: 'CONTINUE' | 'CONTINUE_WITH_MONITORING' | 'REQUEST_APPROVAL' | 'STOP' | string;
  /** The PR head commit this receipt was issued for (required for a non-null receipt). */
  bound_head_sha: string;
  verdict_fingerprint?: string;
  body_hash?: string;
  operation?: 'merge' | 'deploy' | 'tool_call' | 'publish' | string;
  target_id?: string;
  environment?: string;
  /** Structural signature ok — NOT sufficient alone (currently_authorized is the gate). */
  signature_valid?: boolean;
};

/** Branch-protection observation (from the host's GitHub read — the pure gate consumes it as input). */
export type ProtectionState = {
  enforcement: EnforcementState;
  admin_bypass_possible: boolean;
  required_context_name?: string;
  /**
   * Whether the required status check is bound to a specific GitHub App (`app_id` set on the
   * protection rule). OPTIONAL: omit when the host has not observed this — absence means
   * **unknown**, not "not bound". `true` = app-bound (not name-spoofable); `false` = known
   * unbound (context name only; write access can satisfy the check).
   */
  required_check_app_bound?: boolean;
};

export type RequiredContext = {
  operation?: string;
  repository?: string;
  expected_fingerprint?: string;
  expected_body_hash?: string;
  protection: ProtectionState;
  // Policy flags (also accepted at the top level of GateDecisionInput).
  allowWarnMerge?: boolean;
  allowPrefixCompare?: boolean;
  allowPending?: boolean;
};

export type GateDecisionInput = {
  prHeadSha: string;
  receipt: ReceiptView | null;
  requiredContext: RequiredContext;
  /** Incomplete/no-receipt → pending when true, else failure (default false). */
  allowPending?: boolean;
  /** Green the gate on WARN as well as ALLOW (default false). */
  allowWarnMerge?: boolean;
  /** Compare head SHAs by prefix instead of full 40-char equality (default false). */
  allowPrefixCompare?: boolean;
};

export type GateDecision = {
  merge_allowed: boolean;
  state: GateStatusState;
  reason: GateReason;
  enforcement_state: EnforcementState;
  inescapable_merge: boolean;
  /**
   * Named honesty residual on an otherwise-green check (§4.2). Usually present when
   * inescapable_merge is false; may also name an app-binding gap while inescapable_merge
   * remains true (published callers cannot supply that fact yet — residual only, no flip).
   */
  residual?: GateReason;
  detail: { prHeadSha: string; bound_head_sha: string | null; decision: string | null };
};

// ── helpers (pure) ────────────────────────────────────────────────────────────────────────────────
function normSha(s: string | null | undefined): string {
  return String(s == null ? '' : s).trim().toLowerCase();
}

/** Normalize an operation label for comparison (mirrors the deploy-gate): trim + lowercase, so a
 *  canonical 'merge' in any notation ('Merge', 'MERGE') is valid, while an absent/other op fails. */
function normOp(o: string | null | undefined): string {
  return String(o == null ? '' : o).trim().toLowerCase();
}

/** §1.2 — full lowercase SHA equality by default; prefix comparison is opt-in. */
function sameHead(a: string, b: string, allowPrefix: boolean): boolean {
  const na = normSha(a);
  const nb = normSha(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  if (allowPrefix && na.length >= 7 && nb.length >= 7 && (na.startsWith(nb) || nb.startsWith(na))) return true;
  return false;
}

/** §1.3 — allow-class for the merge gate: ALLOW (or WARN only when opted in) + a continue-class action. */
function isAllowClass(receipt: ReceiptView, allowWarnMerge: boolean): boolean {
  const dec = receipt.decision;
  const decisionOk = dec === 'ALLOW' || (dec === 'WARN' && allowWarnMerge === true);
  if (!decisionOk) return false;
  const ea = receipt.execution_action;
  if (ea === undefined || ea === null || ea === '') return true; // decision already allow-class, no action to contradict it
  return ea === 'CONTINUE' || ea === 'CONTINUE_WITH_MONITORING';
}

/** Target/repo binding: the receipt's target must name this repository (exact or `repo:`/path/colon suffix). */
function targetMatches(targetId: string, repository: string): boolean {
  const t = String(targetId).toLowerCase();
  const r = String(repository).toLowerCase();
  return t === r || t === `repo:${r}` || t.endsWith(`:${r}`) || t.endsWith(`/${r}`);
}

/**
 * §1.4 — the normative, first-match-wins gate decision. Pure; no I/O; deterministic.
 */
export function gateDecision(input: GateDecisionInput): GateDecision {
  const rc: RequiredContext = input.requiredContext || ({} as RequiredContext);
  const protection: ProtectionState = rc.protection || { enforcement: 'UNKNOWN', admin_bypass_possible: true };
  const enforcement_state = protection.enforcement;

  const allowPending = input.allowPending ?? rc.allowPending ?? false;
  const allowWarnMerge = input.allowWarnMerge ?? rc.allowWarnMerge ?? false;
  const allowPrefix = input.allowPrefixCompare ?? rc.allowPrefixCompare ?? false;
  const receipt = input.receipt;

  const detail = {
    prHeadSha: normSha(input.prHeadSha),
    bound_head_sha: receipt ? normSha(receipt.bound_head_sha) : null,
    decision: receipt ? String(receipt.decision) : null,
  };
  const fail = (state: GateStatusState, reason: GateReason): GateDecision => ({
    merge_allowed: false, state, reason, enforcement_state, inescapable_merge: false, detail,
  });

  // 1) incomplete head → pending/failure (fail-closed on missing evaluation input).
  if (!input.prHeadSha || String(input.prHeadSha).trim() === '') {
    return fail(allowPending ? 'pending' : 'failure', 'inputs_incomplete');
  }
  // 2) no receipt → fail-closed (M2).
  if (receipt === null || receipt === undefined) {
    return fail(allowPending ? 'pending' : 'failure', 'no_receipt');
  }
  // 3) lifecycle authorization — a valid signature alone is NOT sufficient (M3).
  if (receipt.currently_authorized !== true) {
    return fail('failure', 'receipt_not_authorized');
  }
  // 4) operation binding (RT-P-01 / RT-P-05) — a receipt for a different operation does not authorize
  //    this gate, and a MISSING operation also fails closed (mirrors the deploy-gate T7). Compared via
  //    normOp so casing is notation, not an attack: 'Merge' is a valid merge; only a real other op fails.
  const op = rc.operation ?? 'merge';
  if (receipt.operation == null || normOp(receipt.operation) !== normOp(op)) {
    return fail('failure', 'operation_mismatch');
  }
  // 5) STALE HEAD — the central invariant: a receipt bound to an old head never greens a new one (M1).
  if (!sameHead(receipt.bound_head_sha, input.prHeadSha, allowPrefix)) {
    return fail('failure', 'stale_head');
  }
  // 6) optional re-bind to the current change set.
  if (rc.expected_fingerprint != null && receipt.verdict_fingerprint !== rc.expected_fingerprint) {
    return fail('failure', 'fingerprint_mismatch');
  }
  if (rc.expected_body_hash != null && receipt.body_hash !== rc.expected_body_hash) {
    return fail('failure', 'body_hash_mismatch');
  }
  // 7) target / repository binding (only when both sides are present).
  if (rc.repository && receipt.target_id && !targetMatches(receipt.target_id, rc.repository)) {
    return fail('failure', 'target_mismatch');
  }
  // 8) decision class — only an allow-class verdict greens the merge gate (M4).
  if (!isAllowClass(receipt, allowWarnMerge)) {
    return fail('failure', 'decision_not_allow');
  }

  // 9) success for the CHECK — green for visibility regardless of protection strength.
  // 10) inescapable_merge claim (STRICT, §1.4 step 10 / M6): only when the platform actually enforces
  //     the required check AND no admin can bypass it. Never true otherwise.
  //     App binding is NOT a third conjunct here: flipping the claim when the optional field is
  //     absent would break every published caller who cannot yet supply it. Honesty for that
  //     axis is residual-only (below).
  const inescapable_merge = enforcement_state === 'ENFORCING' && protection.admin_bypass_possible === false;

  let residual: GateReason | undefined;
  if (!inescapable_merge) {
    if (enforcement_state === 'ENFORCING') residual = 'admin_bypass_open';          // required, but admins can override
    else if (enforcement_state === 'ADVISORY') residual = 'protection_advisory_only'; // posted but not required
    else residual = 'protection_not_configured';                                     // ABSENT or UNKNOWN — cannot attest
  } else {
    // Claim is still true (existing contract). Residual names app-binding honesty only when
    // the host has not confirmed a non-spoofable required check.
    if (protection.required_check_app_bound === true) {
      // confirmed app-bound — no residual
    } else if (protection.required_check_app_bound === false) {
      residual = 'required_check_app_not_bound';
    } else {
      residual = 'required_check_app_binding_unknown'; // field absent: unknown ≠ not bound
    }
  }

  // Optional change-set re-bind skipped: record the gap, do not flip the claim (same residual-only
  // shape as required_check_app_*). Only fills when no residual is already named. Distinct from
  // fingerprint_mismatch (hard fail when a re-bind was requested and disagreed).
  if (rc.expected_fingerprint == null && residual === undefined) {
    residual = 'change_set_not_rebound';
  }

  return {
    merge_allowed: true,
    state: 'success',
    reason: 'allow_current_head',
    enforcement_state,
    inescapable_merge,
    ...(residual ? { residual } : {}),
    detail,
  };
}
