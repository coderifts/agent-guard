/**
 * deploy-gate (#8) — the PURE deploy authorization decision (deploy-gate-SPEC §1). The DEPLOY sibling
 * of the merge gate: it answers "may THIS artifact deploy to THIS environment, given the finished
 * receipt and the observed pipeline-enforcement state?"
 *
 * Same shape as the merge gate, different operation. It is a PURE function — NO I/O, NO CD-API call
 * (pipeline enforcement is an INPUT, observed by the host and passed in). It does NOT re-decide: it
 * reads only the finished receipt fields — the deterministic verdict stays the server's (D7). Same
 * inputs → same output (D9).
 *
 * The three deploy-specific binds are the whole point: T7 (a MERGE — or operation-less — receipt can
 * never deploy), environment binding (a staging ALLOW never authorizes production), and artifact
 * binding (an old artifact's ALLOW never deploys a newer one). Scope honesty mirrors the merge gate:
 * `inescapable_deploy` is true ONLY in the fully-enforcing, non-bypassable case; otherwise the check
 * may be `success` for visibility but the claim is false with the residual named.
 *
 * Public source (ships in the npm package): references only receipt/target/enforcement fields and
 * generic deploy-gate concepts — no scoring logic, weights, thresholds, pattern names, endpoints, or
 * secrets.
 */

import type { GateStatusState, EnforcementState } from './merge-gate.js';

export type { GateStatusState, EnforcementState } from './merge-gate.js';

/** The 14 deploy-gate reason codes (§1.1 + change-set residual). Success uses allow_current_deploy;
 *  enforcement_not_configured / bypass_open / change_set_not_rebound name honesty residuals on an
 *  otherwise-green check; fingerprint_mismatch is a hard failure (not a residual). */
export type DeployGateReason =
  | 'allow_current_deploy'
  | 'no_receipt'
  | 'receipt_not_authorized'
  | 'operation_mismatch'
  | 'env_mismatch'
  | 'stale_artifact'
  | 'fingerprint_mismatch'
  | 'body_hash_mismatch'
  | 'target_mismatch'
  | 'decision_not_allow'
  | 'inputs_incomplete'
  | 'enforcement_not_configured'
  | 'bypass_open'
  /**
   * Host did not supply expected_fingerprint — the change-set re-bind was skipped.
   * Residual names the gap; inescapable_deploy is false (fail-closed). Distinct from
   * fingerprint_mismatch (hard failure when a re-bind WAS requested and disagreed).
   * deploy_allowed may stay true.
   */
  | 'change_set_not_rebound';

/** What is being deployed — all fields are INPUTS (the pure function performs no discovery). */
export type DeployTarget = {
  environment: string;
  /** Immutable artifact identity: content digest, or a commit SHA when that is the deploy unit. */
  artifact_id: string;
  service?: string;
  pipeline_run_id?: string;
};

/** A view of the finished receipt. Reuses the shipped field names + the deploy analogs of bound_head_sha. */
export type DeployReceiptView = {
  currently_authorized: boolean;
  authz_reason?: string;
  decision: 'ALLOW' | 'WARN' | 'REQUIRE_APPROVAL' | 'BLOCK' | string;
  execution_action?: 'CONTINUE' | 'CONTINUE_WITH_MONITORING' | 'REQUEST_APPROVAL' | 'STOP' | string;
  /** MUST be 'deploy' for success (T7). */
  operation?: 'merge' | 'deploy' | 'tool_call' | 'publish' | string;
  /** The environment this receipt authorizes (deploy analog of bound_head_sha). */
  bound_environment?: string | null;
  /** The artifact/commit this receipt was issued for (deploy analog of bound_head_sha). */
  bound_artifact_id?: string | null;
  verdict_fingerprint?: string;
  body_hash?: string;
  target_id?: string;
  signature_valid?: boolean;
};

/** Pipeline-enforcement observation (from the host's CD-config read — the pure gate consumes it). */
export type DeployEnforcementState = {
  enforcement: EnforcementState;
  bypass_possible: boolean;
  required_step_name?: string;
};

export type DeployRequiredContext = {
  operation?: 'deploy' | string;
  repository?: string;
  service?: string;
  expected_fingerprint?: string;
  expected_body_hash?: string;
  enforcement: DeployEnforcementState;
  /** Default true: a missing bound_environment on the receipt → env_mismatch. */
  require_bound_environment?: boolean;
  /** Default true: a missing bound_artifact_id → stale_artifact. */
  require_bound_artifact?: boolean;
  // Policy flags (also accepted at the top level of DeployGateInput).
  allowWarnDeploy?: boolean;
  allowPrefixCompare?: boolean;
  allowPending?: boolean;
};

export type DeployGateInput = {
  deployTarget: DeployTarget;
  receipt: DeployReceiptView | null;
  requiredContext: DeployRequiredContext;
  /** Incomplete/no-receipt → pending when true, else failure (default false). */
  allowPending?: boolean;
  /** Green the gate on WARN as well as ALLOW (default false; stricter for prod-shaped envs). */
  allowWarnDeploy?: boolean;
  /** Compare env/artifact by prefix instead of full equality (default false). */
  allowPrefixCompare?: boolean;
};

export type DeployGateDecision = {
  deploy_allowed: boolean;
  state: GateStatusState;
  reason: DeployGateReason;
  enforcement_state: EnforcementState;
  inescapable_deploy: boolean;
  /**
   * Named residual when the check is green but NOT inescapable (honesty channel, §3.2).
   * Compat: FIRST residual in evaluation order (same priority as pre-array single-slot).
   * Prefer `residuals` when co-occurrence matters.
   */
  residual?: DeployGateReason;
  /**
   * ALL applicable honesty residuals in evaluation order (no duplicates).
   * Empty array when none. Additive — singular `residual` remains for published callers.
   */
  residuals: DeployGateReason[];
  detail: {
    environment: string;
    artifact_id: string;
    bound_environment: string | null;
    bound_artifact_id: string | null;
    operation: string | null;
  };
};

// ── helpers (pure) ────────────────────────────────────────────────────────────────────────────────
function norm(s: string | null | undefined): string {
  return String(s == null ? '' : s).trim().toLowerCase();
}

/** §1.2 — full lowercase equality by default (env exact; artifact digest/sha); prefix opt-in. */
function sameNorm(a: string | null | undefined, b: string | null | undefined, allowPrefix: boolean): boolean {
  const na = norm(a);
  const nb = norm(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  if (allowPrefix && na.length >= 7 && nb.length >= 7 && (na.startsWith(nb) || nb.startsWith(na))) return true;
  return false;
}

/** §1.3 — allow-class for deploy: ALLOW (or WARN only when opted in) + a continue-class action. */
function isAllowClass(receipt: DeployReceiptView, allowWarnDeploy: boolean): boolean {
  const dec = receipt.decision;
  const decisionOk = dec === 'ALLOW' || (dec === 'WARN' && allowWarnDeploy === true);
  if (!decisionOk) return false;
  const ea = receipt.execution_action;
  if (ea === undefined || ea === null || ea === '') return true;
  return ea === 'CONTINUE' || ea === 'CONTINUE_WITH_MONITORING';
}

/** target_id must name this service/repository (exact or `svc:`/`repo:`/path/colon suffix). */
function idMatchesName(targetId: string, name: string): boolean {
  const t = norm(targetId);
  const r = norm(name);
  return t === r || t === `svc:${r}` || t === `repo:${r}` || t.endsWith(`:${r}`) || t.endsWith(`/${r}`);
}

/**
 * §1.4 — the normative, first-match-wins deploy decision. Pure; no I/O; deterministic.
 */
export function deployGate(input: DeployGateInput): DeployGateDecision {
  const target: DeployTarget = input.deployTarget || ({} as DeployTarget);
  const rc: DeployRequiredContext = input.requiredContext || ({} as DeployRequiredContext);
  const enf: DeployEnforcementState = rc.enforcement || { enforcement: 'UNKNOWN', bypass_possible: true };
  const enforcement_state = enf.enforcement;

  const opRequired = rc.operation ?? 'deploy';
  // Soft switches may disable binding checks under ADVISORY / UNKNOWN / ABSENT.
  // Under ENFORCING they are forced true: claiming inescapability while switching
  // off a binding check is a contradiction (RT-P-11 / RT-P-12). Keyed off
  // enforcement_state above (enf.enforcement), which is the value already used
  // for inescapable_deploy.
  const requireEnv = enforcement_state === 'ENFORCING' || rc.require_bound_environment !== false; // default true; forced under ENFORCING
  const requireArt = enforcement_state === 'ENFORCING' || rc.require_bound_artifact !== false;    // default true; forced under ENFORCING
  const allowPending = input.allowPending ?? rc.allowPending ?? false;
  const allowWarnDeploy = input.allowWarnDeploy ?? rc.allowWarnDeploy ?? false;
  const allowPrefix = input.allowPrefixCompare ?? rc.allowPrefixCompare ?? false;
  const receipt = input.receipt;

  const detail = {
    environment: norm(target.environment),
    artifact_id: norm(target.artifact_id),
    bound_environment: receipt && receipt.bound_environment != null ? norm(receipt.bound_environment) : null,
    bound_artifact_id: receipt && receipt.bound_artifact_id != null ? norm(receipt.bound_artifact_id) : null,
    operation: receipt && receipt.operation != null ? String(receipt.operation) : null,
  };
  const deny = (state: GateStatusState, reason: DeployGateReason): DeployGateDecision => ({
    deploy_allowed: false, state, reason, enforcement_state, inescapable_deploy: false,
    residuals: [],
    detail,
  });

  // 0) incomplete target → pending/failure (fail-closed on missing evaluation input).
  if (!target.environment || String(target.environment).trim() === ''
    || !target.artifact_id || String(target.artifact_id).trim() === '') {
    return deny(allowPending ? 'pending' : 'failure', 'inputs_incomplete');
  }
  // 1) no receipt → fail-closed (D4).
  if (receipt === null || receipt === undefined) {
    return deny(allowPending ? 'pending' : 'failure', 'no_receipt');
  }
  // 2) lifecycle authorization — a valid signature alone is NOT sufficient (D5).
  if (receipt.currently_authorized !== true) {
    return deny('failure', 'receipt_not_authorized');
  }
  // 3) T7 — operation MUST be deploy. A merge (or any other) receipt cannot deploy, and a MISSING
  //    operation also fails closed (stricter than the merge gate — deploy is higher-risk) (D1).
  if (receipt.operation == null || norm(receipt.operation) !== norm(opRequired)) {
    return deny('failure', 'operation_mismatch');
  }
  // 4) ENVIRONMENT binding — a staging ALLOW never authorizes production (D2).
  if (requireEnv) {
    if (!receipt.bound_environment || !sameNorm(receipt.bound_environment, target.environment, allowPrefix)) {
      return deny('failure', 'env_mismatch');
    }
  } else if (receipt.bound_environment && !sameNorm(receipt.bound_environment, target.environment, allowPrefix)) {
    return deny('failure', 'env_mismatch');
  }
  // 5) ARTIFACT binding — an old artifact's ALLOW never deploys a newer one (D3, the stale analog).
  if (requireArt) {
    if (!receipt.bound_artifact_id || !sameNorm(receipt.bound_artifact_id, target.artifact_id, allowPrefix)) {
      return deny('failure', 'stale_artifact');
    }
  } else if (receipt.bound_artifact_id && !sameNorm(receipt.bound_artifact_id, target.artifact_id, allowPrefix)) {
    return deny('failure', 'stale_artifact');
  }
  // 6) optional re-bind to the current change set.
  if (rc.expected_fingerprint != null && receipt.verdict_fingerprint !== rc.expected_fingerprint) {
    return deny('failure', 'fingerprint_mismatch');
  }
  if (rc.expected_body_hash != null && receipt.body_hash !== rc.expected_body_hash) {
    return deny('failure', 'body_hash_mismatch');
  }
  // 7) optional service / repository target binding.
  if (rc.service && receipt.target_id) {
    if (!idMatchesName(receipt.target_id, rc.service)) return deny('failure', 'target_mismatch');
  } else if (rc.repository && receipt.target_id) {
    if (!idMatchesName(receipt.target_id, rc.repository)) return deny('failure', 'target_mismatch');
  }
  // 8) decision class — only an allow-class verdict greens the deploy gate (D6).
  if (!isAllowClass(receipt, allowWarnDeploy)) {
    return deny('failure', 'decision_not_allow');
  }

  // 9) success for the CHECK / pipeline step — green for visibility regardless of enforcement strength.
  // 10) inescapable_deploy (fail-closed): true ONLY when ENFORCING ∧ ¬bypass ∧ fingerprint rebound.
  //     Unbound change set → false (cannot assert), never residual-true.
  const enforcementOk = enforcement_state === 'ENFORCING' && enf.bypass_possible === false;
  const rebound = rc.expected_fingerprint != null && String(rc.expected_fingerprint).length > 0;
  const inescapable_deploy = enforcementOk && rebound;

  // Residuals key off the FACT that failed (not the collapsed flag).
  const residuals: DeployGateReason[] = [];
  if (!enforcementOk) {
    if (enforcement_state === 'ENFORCING') residuals.push('bypass_open');
    else residuals.push('enforcement_not_configured');
  }

  if (!rebound) {
    residuals.push('change_set_not_rebound');
  }

  const residual = residuals.length > 0 ? residuals[0] : undefined;

  return {
    deploy_allowed: true,
    state: 'success',
    reason: 'allow_current_deploy',
    enforcement_state,
    inescapable_deploy,
    residuals,
    ...(residual ? { residual } : {}),
    detail,
  };
}
