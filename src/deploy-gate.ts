/**
 * deploy-gate (#8) — the PURE deploy authorization decision (deploy-gate-SPEC §1). The DEPLOY sibling
 * of the merge gate: it answers "may THIS artifact deploy to THIS environment, given the finished
 * receipt and the observed pipeline-enforcement state?"
 *
 * Same shape as the merge gate, different operation. It is a PURE function — NO I/O, NO CD-API call
 * (pipeline enforcement is an INPUT, observed by the host and passed in). TOKEN mode verifies a
 * chain-receipt locally (Ed25519 + registry/pinned PEM; no HTTP). VERIFIED-VIEW mode accepts a
 * host-attributed view ONLY with the guard-defined provenance marker. A bare
 * `currently_authorized: true` is not proof (P0 / external audit 2026-08-24). Same
 * inputs → same output (D9). Observation `verification.{mode,verify_status}` is recorded on the
 * outcome; it does not enter any fingerprint preimage.
 *
 * The three deploy-specific binds are the whole point: T7 (a MERGE — or operation-less — receipt can
 * never deploy), environment binding (a staging ALLOW never authorizes production), and artifact
 * binding (an old artifact's ALLOW never deploys a newer one). Scope honesty follows the merge gate's
 * SHAPE (a conjunction, fail-closed on any gap) but NOT its conjuncts — see below.
 *
 * `inescapable_deploy` is true ONLY when every conjunct holds: ENFORCING ∧ ¬bypass_possible ∧
 * fingerprint rebound. Missing any conjunct → FALSE (fail-closed); the check may still be `success`
 * for visibility, with the residual named.
 *
 * WHAT THAT DOES NOT SAY, stated because the field name is stronger than the fact. The first two
 * conjuncts are the HOST's observation of its own CD config (`DeployRequiredContext.enforcement`),
 * consumed by this pure gate, not verified by it — so `inescapable_deploy: true` reports that the
 * host said its pipeline enforces and cannot be bypassed, plus a fingerprint we did rebind. Note
 * also that this gate carries NO issuer-binding conjunct at all, unlike `inescapable_merge`: where a
 * provider check supplies the enforcing signal, binding it to an App id proves the check came from
 * that provider's Actions app, NOT that CodeRifts produced it — anyone who can edit the workflow
 * definition can post under the same issuer. Closing that needs workflow-SHA pinning.
 *
 * Public source (ships in the npm package): references only receipt/target/enforcement fields and
 * generic deploy-gate concepts — no scoring logic, weights, thresholds, pattern names, endpoints, or
 * secrets.
 */

import type { GateStatusState, EnforcementState } from './merge-gate.js';
import {
  verifyDeployReceiptToken,
  type DeployTokenReceipt,
} from './deploy-receipt-token.js';

export type { GateStatusState, EnforcementState } from './merge-gate.js';
export type { DeployTokenReceipt } from './deploy-receipt-token.js';

/**
 * Guard-defined VERIFIED-VIEW provenance marker (same idiom as `proof_spec` /
 * `attestation_spec`). A host that already verified (CLI, etc.) MUST set this —
 * `currently_authorized: true` alone is untrusted input.
 */
export const DEPLOY_RECEIPT_VIEW_SPEC = 'deploy-receipt-view.v1' as const;

/** Deploy-gate reason codes (§1.1 + change-set residual + 9.0.0 verification). Success uses allow_current_deploy;
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
  | 'change_set_not_rebound'
  /**
   * Caller handed a receipt view with currently_authorized (or bounds) but no TOKEN and no
   * guard-defined view_spec provenance. Distinct from receipt_not_authorized: "you didn't prove
   * it" ≠ "verification says no".
   */
  | 'unverified_receipt_view'
  | 'invalid_signature'
  | 'expired'
  | 'unknown_key'
  | 'retired_key'
  /**
   * The registry has withdrawn this key: status `revoked`, or a `revoked_at`
   * timestamp on the entry. Distinct from retired_key, which is a planned
   * rotation whose pre-rotation receipts stay meaningful. NOT repairable by
   * re-requesting a receipt — the same key would sign it.
   */
  | 'revoked_key'
  /**
   * The registry carries a key status this verifier does not understand. Fails
   * closed rather than reading it as healthy: an unrecognised status is more
   * likely a withdrawal we cannot parse than a permission we should grant.
   */
  | 'unknown_key_status';

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
  /**
   * VERIFIED-VIEW provenance. Must equal DEPLOY_RECEIPT_VIEW_SPEC together with
   * `verified: true` or the gate denies unverified_receipt_view.
   */
  view_spec?: string;
  verified?: boolean;
  verify_status?: string;
};

/** VERIFIED-VIEW: host-attributed, guard-defined marker required. */
export type VerifiedDeployReceiptView = DeployReceiptView & {
  view_spec: typeof DEPLOY_RECEIPT_VIEW_SPEC;
  verified: true;
  verify_status: string;
};

export type DeployVerificationMode = 'token' | 'verified_view' | 'unverified' | 'none';

export type DeployVerificationObservation = {
  mode: DeployVerificationMode;
  verify_status: string | null;
};

/** Stamp a computed view so deployGate will accept it as VERIFIED-VIEW (not TOKEN). */
export function asVerifiedDeployReceiptView(
  view: DeployReceiptView,
  verify_status = 'VERIFIED_CURRENT',
): VerifiedDeployReceiptView {
  return {
    ...view,
    view_spec: DEPLOY_RECEIPT_VIEW_SPEC,
    verified: true,
    verify_status,
  };
}

export function isVerifiedDeployReceiptView(r: DeployReceiptView | null | undefined): r is VerifiedDeployReceiptView {
  return !!r
    && r.view_spec === DEPLOY_RECEIPT_VIEW_SPEC
    && r.verified === true;
}

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
  /**
   * VERIFIED-VIEW (or null). A bare currently_authorized boolean is untrusted.
   * TOKEN mode uses `token` instead (recommended).
   */
  receipt?: DeployReceiptView | VerifiedDeployReceiptView | null;
  /** TOKEN mode: signed chain_receipt + registry | pinnedKeyPem. Guard verifies locally. */
  token?: DeployTokenReceipt;
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
  /**
   * Observation: which input mode ran and the verify_status. Not a preimage field.
   */
  verification: DeployVerificationObservation;
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

  let verification: DeployVerificationObservation = { mode: 'none', verify_status: null };
  let receipt: DeployReceiptView | null | undefined = input.receipt;

  const detailOf = (r: DeployReceiptView | null | undefined) => ({
    environment: norm(target.environment),
    artifact_id: norm(target.artifact_id),
    bound_environment: r && r.bound_environment != null ? norm(r.bound_environment) : null,
    bound_artifact_id: r && r.bound_artifact_id != null ? norm(r.bound_artifact_id) : null,
    operation: r && r.operation != null ? String(r.operation) : null,
  });
  const deny = (state: GateStatusState, reason: DeployGateReason): DeployGateDecision => ({
    deploy_allowed: false, state, reason, enforcement_state, inescapable_deploy: false,
    residuals: [],
    detail: detailOf(receipt),
    verification,
  });

  // 0) incomplete target → pending/failure (fail-closed on missing evaluation input).
  if (!target.environment || String(target.environment).trim() === ''
    || !target.artifact_id || String(target.artifact_id).trim() === '') {
    return deny(allowPending ? 'pending' : 'failure', 'inputs_incomplete');
  }

  // TOKEN mode (recommended): guard verifies locally. Wins over a sibling receipt view.
  const tokenInput = input.token;
  if (tokenInput && typeof tokenInput.token === 'string' && tokenInput.token.length > 0) {
    const tv = verifyDeployReceiptToken(tokenInput, {
      operation: opRequired,
      environment: target.environment,
      artifact_id: target.artifact_id,
    });
    verification = { mode: 'token', verify_status: tv.status };
    if (tv.denyReason) {
      receipt = tv.view;
      return deny('failure', tv.denyReason as DeployGateReason);
    }
    receipt = tv.view;
  } else if (receipt === null || receipt === undefined) {
    // 1) no receipt and no token → fail-closed (D4).
    return deny(allowPending ? 'pending' : 'failure', 'no_receipt');
  } else if (isVerifiedDeployReceiptView(receipt)) {
    verification = {
      mode: 'verified_view',
      verify_status: typeof receipt.verify_status === 'string' ? receipt.verify_status : null,
    };
  } else {
    // Bare currently_authorized (or any view without the guard-defined marker).
    verification = { mode: 'unverified', verify_status: null };
    return deny('failure', 'unverified_receipt_view');
  }

  if (receipt === null || receipt === undefined) {
    return deny(allowPending ? 'pending' : 'failure', 'no_receipt');
  }

  // 2) lifecycle authorization — a valid signature alone is NOT sufficient (D5).
  //    In TOKEN mode currently_authorized was COMPUTED; in VERIFIED-VIEW it is host-attributed
  //    behind view_spec (not a sneaked boolean).
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
    detail: detailOf(receipt),
    verification,
  };
}
