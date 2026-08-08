/**
 * enforcement-coverage report (#9) — the PURE tetrad aggregator (enforcement-coverage-SPEC §1–5).
 * The capstone of scope honesty: it composes the four primitives' ALREADY-COMPUTED states into ONE
 * honest picture — where is the system actually inescapable, and where isn't it?
 *
 * Thesis: complete ≠ enforced. A primitive installed or green for one commit is not the same as
 * ENFORCING for that placement.
 *
 * PURE aggregator — NO I/O; it NEVER re-decides and NEVER re-runs a gate / resolver / registry (C7).
 * It reads only the input structs the primitives already emit (registry report.coverage +
 * inescapable_runtime; merge/deploy enforcement_state + inescapable_*; resolver report.coverage).
 * Same input → same report (C9; residuals sorted). Fail-closed: the weakest applicable placement caps
 * the overall, and a missing/unobservable applicable state is UNKNOWN — never treated as "fine".
 *
 * Applicability-aware: a placement that is not in scope for this target is EXCLUDED and NEVER
 * contributes a residual or a cap (C4/C5). Scope honesty is paramount: every residual is named, and
 * even FULLY_ENFORCED does not claim "nothing can ever bypass" — an infra residual always exists.
 *
 * Public source (ships in the npm package): reads only placement state fields — no scoring logic,
 * weights, thresholds, pattern names, endpoints, or secrets.
 */

import type { EnforcementState } from './merge-gate.js';

export type PlacementId = 'runtime' | 'merge' | 'deploy' | 'content';

export type Applicability = { runtime: boolean; merge: boolean; deploy: boolean; content: boolean };

export type RuntimePlacementInput = {
  coverage: 'COMPLETE' | 'PARTIAL' | 'BYPASSED' | 'UNKNOWN' | string;
  inescapable_runtime: boolean;
  residuals?: string[];
};
export type MergePlacementInput = {
  enforcement_state: EnforcementState | string;
  inescapable_merge: boolean;
  residuals?: string[];
};
export type DeployPlacementInput = {
  enforcement_state: EnforcementState | string;
  inescapable_deploy: boolean;
  residuals?: string[];
};
export type ContentPlacementInput = {
  coverage: 'COMPLETE' | 'PARTIAL' | 'UNRESOLVED' | 'EMPTY' | 'UNKNOWN' | string;
  artifacts_ready?: boolean;
  residuals?: string[];
};

export type CoverageReportInput = {
  applicability: Applicability;
  /**
   * Host attestation that the `applicability` map is complete and intentional (RT-P-16).
   *
   * **Absence semantics (not_reported discipline):** missing or any value other than
   * strictly `true` is false-equivalent for claims. Unattested applicability can never
   * support `FULLY_ENFORCED` (downgraded to `PARTIALLY_ENFORCED` when placements would
   * otherwise all be ENFORCING) and always names residual `applicability_unattested`
   * when at least one placement is applicable. Absence is not attestation.
   */
  applicability_attested?: boolean;
  runtime?: RuntimePlacementInput | null;
  merge?: MergePlacementInput | null;
  deploy?: DeployPlacementInput | null;
  content?: ContentPlacementInput | null;
};

export type PlacementStrength = 'ENFORCING' | 'WEAK' | 'UNKNOWN' | 'EXCLUDED';

export type OverallCoverage =
  | 'FULLY_ENFORCED' | 'PARTIALLY_ENFORCED' | 'ADVISORY_ONLY'
  | 'CONTENT_BLOCKED' | 'UNKNOWN' | 'NOT_APPLICABLE';

export type HonestClaimKey =
  | 'claim_fully_enforced' | 'claim_partially_enforced' | 'claim_advisory_only'
  | 'claim_content_blocked' | 'claim_unknown' | 'claim_not_applicable';

export type PerPlacementRow = {
  placement: PlacementId;
  applicable: boolean;
  strength: PlacementStrength;
  summary: { enforcement_or_coverage: string; inescapable_flag?: boolean | null };
  residuals: string[];
};

export type CoverageReport = {
  overall_coverage: OverallCoverage;
  per_placement: PerPlacementRow[];
  residuals: string[];
  honest_claim_key: HonestClaimKey;
  honest_claim_language: string;
  flags: {
    may_claim_inescapable_runtime: boolean;
    may_claim_inescapable_merge: boolean;
    may_claim_inescapable_deploy: boolean;
    may_claim_full_tetrad: boolean;
  };
};

// deterministic honest-language templates (§4.4) — no over-claim; FULLY never says "nothing can bypass".
const TEMPLATES: Record<HonestClaimKey, string> = {
  claim_fully_enforced:
    'All applicable CodeRifts placements are enforcing and non-bypassable for this target. '
    + 'Residuals outside tetrad (e.g. infra break-glass) may still exist.',
  claim_partially_enforced:
    'Partial enforcement: some applicable placements enforce; open gaps: {residuals}.',
  claim_advisory_only:
    'CodeRifts is present but no applicable placement is fully enforcing. Gaps: {residuals}.',
  claim_content_blocked:
    'Contract artifact content is not fully resolved; enforcement of preflight content is incomplete. Gaps: {residuals}.',
  claim_unknown:
    'One or more applicable placements cannot be observed. Cannot attest full enforcement. Gaps: {residuals}.',
  claim_not_applicable:
    'No CodeRifts placements are in scope for this target.',
};

const OVERALL_TO_KEY: Record<OverallCoverage, HonestClaimKey> = {
  FULLY_ENFORCED: 'claim_fully_enforced',
  PARTIALLY_ENFORCED: 'claim_partially_enforced',
  ADVISORY_ONLY: 'claim_advisory_only',
  CONTENT_BLOCKED: 'claim_content_blocked',
  UNKNOWN: 'claim_unknown',
  NOT_APPLICABLE: 'claim_not_applicable',
};

type Computed = { strength: PlacementStrength; residuals: string[]; summary: PerPlacementRow['summary'] };

function computeRuntime(applicable: boolean, input: RuntimePlacementInput | null | undefined): Computed {
  if (!applicable) return { strength: 'EXCLUDED', residuals: [], summary: { enforcement_or_coverage: input?.coverage ?? 'N/A', inescapable_flag: input?.inescapable_runtime ?? null } };
  if (input == null) return { strength: 'UNKNOWN', residuals: ['runtime_state_missing'], summary: { enforcement_or_coverage: 'MISSING', inescapable_flag: null } };
  const residuals = [...(input.residuals ?? [])];
  let strength: PlacementStrength;
  if (input.coverage === 'COMPLETE' && input.inescapable_runtime === true) strength = 'ENFORCING';
  else if (input.coverage === 'UNKNOWN') strength = 'UNKNOWN';
  else strength = 'WEAK';
  if (input.coverage === 'BYPASSED') residuals.push('runtime_bypassed');
  return { strength, residuals, summary: { enforcement_or_coverage: input.coverage, inescapable_flag: input.inescapable_runtime } };
}

function computeMerge(applicable: boolean, input: MergePlacementInput | null | undefined): Computed {
  if (!applicable) return { strength: 'EXCLUDED', residuals: [], summary: { enforcement_or_coverage: input?.enforcement_state ?? 'N/A', inescapable_flag: input?.inescapable_merge ?? null } };
  if (input == null) return { strength: 'UNKNOWN', residuals: ['merge_state_missing'], summary: { enforcement_or_coverage: 'MISSING', inescapable_flag: null } };
  const residuals = [...(input.residuals ?? [])];
  let strength: PlacementStrength;
  // RT-P-13: ENFORCING requires the flag AND a consistent enforcement_state — never trust the flag
  // alone. A caller claiming inescapable_merge:true while enforcement_state is not ENFORCING is an
  // inconsistent (adversarial) state → treat as WEAK and name it, never a false FULLY_ENFORCED.
  if (input.inescapable_merge === true && input.enforcement_state === 'ENFORCING') strength = 'ENFORCING';
  else if (input.inescapable_merge === true) { strength = 'WEAK'; residuals.push('inescapable_flag_inconsistent'); }
  else if (input.enforcement_state === 'UNKNOWN') strength = 'UNKNOWN';
  else strength = 'WEAK';
  if (strength === 'WEAK') {
    if (input.enforcement_state === 'ENFORCING' && input.inescapable_merge === false) residuals.push('admin_bypass_open');
    else if (input.enforcement_state === 'ABSENT') residuals.push('merge_gate_not_configured');
    else if (input.enforcement_state === 'ADVISORY') residuals.push('merge_gate_advisory');
  }
  return { strength, residuals, summary: { enforcement_or_coverage: input.enforcement_state, inescapable_flag: input.inescapable_merge } };
}

function computeDeploy(applicable: boolean, input: DeployPlacementInput | null | undefined): Computed {
  if (!applicable) return { strength: 'EXCLUDED', residuals: [], summary: { enforcement_or_coverage: input?.enforcement_state ?? 'N/A', inescapable_flag: input?.inescapable_deploy ?? null } };
  if (input == null) return { strength: 'UNKNOWN', residuals: ['deploy_state_missing'], summary: { enforcement_or_coverage: 'MISSING', inescapable_flag: null } };
  const residuals = [...(input.residuals ?? [])];
  let strength: PlacementStrength;
  // RT-P-13 (deploy analog): ENFORCING requires the flag AND a consistent enforcement_state.
  if (input.inescapable_deploy === true && input.enforcement_state === 'ENFORCING') strength = 'ENFORCING';
  else if (input.inescapable_deploy === true) { strength = 'WEAK'; residuals.push('inescapable_flag_inconsistent'); }
  else if (input.enforcement_state === 'UNKNOWN') strength = 'UNKNOWN';
  else strength = 'WEAK';
  if (strength === 'WEAK') {
    if (input.enforcement_state === 'ENFORCING' && input.inescapable_deploy === false) residuals.push('bypass_open');
    else if (input.enforcement_state === 'ABSENT') residuals.push('deploy_path_ungated');
    else if (input.enforcement_state === 'ADVISORY') residuals.push('deploy_gate_advisory');
  }
  return { strength, residuals, summary: { enforcement_or_coverage: input.enforcement_state, inescapable_flag: input.inescapable_deploy } };
}

function computeContent(applicable: boolean, input: ContentPlacementInput | null | undefined): Computed {
  if (!applicable) return { strength: 'EXCLUDED', residuals: [], summary: { enforcement_or_coverage: input?.coverage ?? 'N/A', inescapable_flag: input?.artifacts_ready ?? null } };
  if (input == null) return { strength: 'UNKNOWN', residuals: ['content_state_missing'], summary: { enforcement_or_coverage: 'MISSING', inescapable_flag: null } };
  const residuals = [...(input.residuals ?? [])];
  let strength: PlacementStrength;
  if (input.coverage === 'COMPLETE' || input.coverage === 'EMPTY') strength = 'ENFORCING';   // EMPTY is vacuously ready, not a gap
  else if (input.coverage === 'UNRESOLVED') { strength = 'WEAK'; residuals.push('content_unresolved'); }
  else if (input.coverage === 'PARTIAL') { strength = 'WEAK'; residuals.push('content_partial'); }
  else strength = 'UNKNOWN'; // 'UNKNOWN' or anything unexpected → fail-closed observation
  return { strength, residuals, summary: { enforcement_or_coverage: input.coverage, inescapable_flag: input.artifacts_ready ?? null } };
}

/**
 * §1–5 — the pure tetrad aggregator. Deterministic; no I/O; reads only the primitives' emitted states.
 */
export function coverageReport(input: CoverageReportInput): CoverageReport {
  const applicability: Applicability = input.applicability || { runtime: false, merge: false, deploy: false, content: false };

  const computed: Record<PlacementId, Computed> = {
    runtime: computeRuntime(applicability.runtime === true, input.runtime),
    merge: computeMerge(applicability.merge === true, input.merge),
    deploy: computeDeploy(applicability.deploy === true, input.deploy),
    content: computeContent(applicability.content === true, input.content),
  };
  const order: PlacementId[] = ['runtime', 'merge', 'deploy', 'content'];

  const isApplicable = (p: PlacementId) => applicability[p] === true;
  const applicableStrengths = order.filter(isApplicable).map((p) => computed[p].strength);
  const contentApplicable = isApplicable('content');
  const contentUnresolved = contentApplicable && input.content != null && input.content.coverage === 'UNRESOLVED';
  const weakPlacements = order.filter((p) => isApplicable(p) && computed[p].strength === 'WEAK');

  // §4.2 — mechanical overall aggregation (weakest applicable caps; fail-closed).
  let overall: OverallCoverage;
  if (applicableStrengths.length === 0) {
    overall = 'NOT_APPLICABLE';
  } else if (applicableStrengths.every((s) => s === 'ENFORCING')) {
    overall = 'FULLY_ENFORCED';
  } else if (applicableStrengths.some((s) => s === 'WEAK') && applicableStrengths.some((s) => s === 'ENFORCING')) {
    overall = contentUnresolved ? 'CONTENT_BLOCKED' : 'PARTIALLY_ENFORCED';
  } else if (applicableStrengths.some((s) => s === 'WEAK')) { // no ENFORCING
    overall = (contentUnresolved && weakPlacements.every((p) => p === 'content')) ? 'CONTENT_BLOCKED' : 'ADVISORY_ONLY';
  } else { // no WEAK, not all ENFORCING → some UNKNOWN
    overall = 'UNKNOWN';
  }

  // RT-P-16: applicability attestation (not_reported). Only strict true is attestation.
  // Absence / false can never support FULLY — a green tetrad with unattested scope is PARTIAL.
  const applicabilityAttested = input.applicability_attested === true;
  if (!applicabilityAttested && overall === 'FULLY_ENFORCED') {
    overall = 'PARTIALLY_ENFORCED';
  }

  // §4.3 — residuals: union of applicable placements only, sorted unique (EXCLUDED contribute none).
  const residualSet = new Set<string>();
  for (const p of order) if (isApplicable(p)) for (const r of computed[p].residuals) residualSet.add(r);
  // RT-P-16 residual: named whenever applicability is not attested and something is in scope.
  if (!applicabilityAttested && applicableStrengths.length > 0) {
    residualSet.add('applicability_unattested');
  }
  const residuals = [...residualSet].sort();

  // §4.4 — claim key + deterministic honest language.
  const honest_claim_key = OVERALL_TO_KEY[overall];
  const honest_claim_language = TEMPLATES[honest_claim_key].replace('{residuals}', residuals.length ? residuals.join(', ') : 'none');

  // §4.5 — flags (must not disagree with overall). RT-P-13: a per-placement inescapable claim tracks
  // the COMPUTED strength (flag ∧ consistent enforcement), never the raw flag alone — so an
  // inconsistent inescapable_* claim cannot leak into a may_claim_* true.
  // may_claim_full_tetrad tracks overall only (which already requires attestation for FULLY).
  const flags = {
    may_claim_inescapable_runtime: isApplicable('runtime') && computed.runtime.strength === 'ENFORCING',
    may_claim_inescapable_merge: isApplicable('merge') && computed.merge.strength === 'ENFORCING',
    may_claim_inescapable_deploy: isApplicable('deploy') && computed.deploy.strength === 'ENFORCING',
    may_claim_full_tetrad: overall === 'FULLY_ENFORCED',
  };

  const per_placement: PerPlacementRow[] = order.map((p) => ({
    placement: p,
    applicable: isApplicable(p),
    strength: computed[p].strength,
    summary: computed[p].summary,
    residuals: isApplicable(p) ? [...new Set(computed[p].residuals)].sort() : [],
  }));

  return { overall_coverage: overall, per_placement, residuals, honest_claim_key, honest_claim_language, flags };
}
