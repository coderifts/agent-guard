/**
 * bindDeploy — pure deploy-TIME composition over deployGate (#8).
 *
 * Why this exists: deployGate is the pure decision; nothing in this package used to
 * invoke it at the moment of deploying. The merge gate has the same shape
 * (gateDecision is pure; GitHub enforces via required checks the package does not
 * control). Deploy generalises that pattern with two differences:
 *   1. There is no pull request / required status check to hang on — the host must
 *      call this from the CD step itself.
 *   2. The environment name is a HOST ASSERTION. The receipt's bound_environment is
 *      signed evidence; the deploy target's environment string is not verified by us.
 *      A host can claim "staging" while deploying to production. The output says so.
 *
 * TOKEN mode: bindDeploy forwards `token` to deployGate, which verifies locally
 * (no HTTP). VERIFIED-VIEW must carry the guard-defined view_spec. pipeline_action
 * is always 'not_observed'. inescapable_deploy still comes only from deployGate.
 *
 * External note: coderifts-app CLI `deploy-gate` historically inlined a similar bind
 * (deployBind). That is a consumer; this is the package-local pure entry hosts should
 * call so the decision logic has a first-class caller in-repo.
 */

import {
  deployGate,
  type DeployEnforcementState,
  type DeployGateDecision,
  type DeployGateReason,
  type DeployReceiptView,
  type DeployTarget,
  type GateStatusState,
  type DeployTokenReceipt,
} from './deploy-gate.js';

/** Reasons a fresh re-preflight for this { env, artifact } can repair. */
const REPAIRABLE: ReadonlySet<DeployGateReason> = new Set([
  'env_mismatch',
  'stale_artifact',
  'operation_mismatch',
  'receipt_not_authorized',
  'fingerprint_mismatch',
  'body_hash_mismatch',
  'no_receipt',
  'inputs_incomplete',
  'unverified_receipt_view',
  'invalid_signature',
  'expired',
  'unknown_key',
  'retired_key',
]);

/**
 * Environment as supplied by the host at deploy time.
 *
 * provenance is ALWAYS 'host_asserted'. The package cannot observe the real CD
 * target; treating this as verified would be the honesty failure this project keeps
 * finding. Signed evidence lives on the receipt (bound_environment), not here.
 */
export type HostAssertedEnvironment = {
  name: string;
  /** Fixed literal — never 'verified'. */
  provenance: 'host_asserted';
};

export type BindDeployInput = {
  /**
   * Host-asserted deploy environment. Pass a string (wrapped as host_asserted) or
   * an explicit HostAssertedEnvironment. Never reported as package-verified.
   */
  environment: string | HostAssertedEnvironment;
  /** Artifact / digest being deployed (host-supplied identity for this moment). */
  artifact_id: string;
  service?: string;
  pipeline_run_id?: string;
  /**
   * VERIFIED-VIEW (must carry view_spec) or null. TOKEN mode: pass `token` instead.
   * A bare currently_authorized boolean is denied as unverified_receipt_view.
   */
  receipt?: DeployReceiptView | null;
  /** TOKEN mode: signed chain_receipt + registry | pinnedKeyPem. Guard verifies. */
  token?: DeployTokenReceipt;
  /**
   * Host-observed pipeline enforcement (CD config / step policy). Same role as
   * ProtectionState for merge — an input, not a package discovery.
   */
  pipeline_enforcement: DeployEnforcementState;
  /** Operation the receipt must match (default 'deploy'). */
  operation?: string;
  expected_fingerprint?: string;
  expected_body_hash?: string;
  allowPending?: boolean;
  allowWarnDeploy?: boolean;
  allowPrefixCompare?: boolean;
};

/**
 * Result of a deploy-time bind. Distinguish carefully:
 *   - gate / decision_allows_deploy — pure decision from deployGate
 *   - pipeline_action — always 'not_observed' (we never block or run a deploy)
 *   - environment.provenance — always 'host_asserted' (we never verified the target)
 */
export type BindDeployResult = {
  /** Full pure gate decision (includes inescapable_deploy, residual, detail). */
  gate: DeployGateDecision;
  /**
   * Whether the pure decision allows deploy. Naming avoids "deploy was blocked"
   * (that would claim pipeline enforcement). Same bit as gate.deploy_allowed.
   */
  decision_allows_deploy: boolean;
  /** Mirror of gate.state for check-run / step status UIs. */
  deploy_check_status: GateStatusState;
  /** Gate reason code (or no_receipt when receipt was null). */
  reason: DeployGateReason;
  /** Whether re-preflighting this target can repair a deny. */
  must_re_preflight: boolean;
  /**
   * Environment as accepted into the gate. provenance is always host_asserted —
   * never verified, never measured by this package.
   */
  environment: HostAssertedEnvironment;
  artifact_id: string;
  /**
   * Always 'not_observed'. The package does not run, block, or skip a pipeline
   * step. Whether the host CD job exits non-zero on decision_allows_deploy:false
   * is entirely the pipeline's business.
   */
  pipeline_action: 'not_observed';
  /**
   * Convenience: inescapable_deploy from the gate only (never a host flag).
   * True only when pipeline_enforcement is ENFORCING and bypass_possible is false
   * AND the gate would allow — same honesty as deployGate.
   */
  inescapable_deploy: boolean;
};

function asHostAssertedEnvironment(env: string | HostAssertedEnvironment): HostAssertedEnvironment {
  if (typeof env === 'string') {
    return { name: env, provenance: 'host_asserted' };
  }
  const name = env && typeof env.name === 'string' ? env.name : '';
  // Force provenance — a host cannot pass provenance: 'verified' through this API.
  return { name, provenance: 'host_asserted' };
}

/**
 * Pure deploy-time entry: bind host claims + finished receipt view into deployGate.
 *
 * @example
 * ```ts
 * const r = bindDeploy({
 *   environment: { name: 'production', provenance: 'host_asserted' },
 *   artifact_id: digest,
 *   receipt: receiptView,
 *   pipeline_enforcement: { enforcement: 'ENFORCING', bypass_possible: false },
 * });
 * // r.decision_allows_deploy — decision only
 * // r.pipeline_action === 'not_observed' — we did not enforce
 * // r.environment.provenance === 'host_asserted' — we did not verify the target name
 * if (!r.decision_allows_deploy) process.exit(1); // host pipeline chooses to honour
 * ```
 */
export function bindDeploy(input: BindDeployInput): BindDeployResult {
  const environment = asHostAssertedEnvironment(input.environment);
  const artifact_id = input.artifact_id == null ? '' : String(input.artifact_id);
  const operation = input.operation ?? 'deploy';

  const deployTarget: DeployTarget = {
    environment: environment.name,
    artifact_id,
    ...(input.service != null ? { service: input.service } : {}),
    ...(input.pipeline_run_id != null ? { pipeline_run_id: input.pipeline_run_id } : {}),
  };

  const requiredContext = {
    operation,
    enforcement: input.pipeline_enforcement || { enforcement: 'UNKNOWN' as const, bypass_possible: true },
    ...(input.service != null ? { service: input.service } : {}),
    ...(input.expected_fingerprint != null
      ? { expected_fingerprint: input.expected_fingerprint }
      : {}),
    ...(input.expected_body_hash != null
      ? { expected_body_hash: input.expected_body_hash }
      : {}),
    ...(input.allowPending != null ? { allowPending: input.allowPending } : {}),
    ...(input.allowWarnDeploy != null ? { allowWarnDeploy: input.allowWarnDeploy } : {}),
    ...(input.allowPrefixCompare != null
      ? { allowPrefixCompare: input.allowPrefixCompare }
      : {}),
  };

  const gate = deployGate({
    deployTarget,
    receipt: input.receipt,
    token: input.token,
    requiredContext,
    ...(input.allowPending != null ? { allowPending: input.allowPending } : {}),
    ...(input.allowWarnDeploy != null ? { allowWarnDeploy: input.allowWarnDeploy } : {}),
    ...(input.allowPrefixCompare != null
      ? { allowPrefixCompare: input.allowPrefixCompare }
      : {}),
  });

  return {
    gate,
    decision_allows_deploy: gate.deploy_allowed === true,
    deploy_check_status: gate.state,
    reason: gate.reason,
    must_re_preflight: REPAIRABLE.has(gate.reason),
    environment, // always provenance: 'host_asserted'
    artifact_id,
    pipeline_action: 'not_observed',
    inescapable_deploy: gate.inescapable_deploy === true,
  };
}

export { REPAIRABLE as DEPLOY_REPAIRABLE_REASONS };
