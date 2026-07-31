/**
 * withCodeRifts — additive orchestration layer above the frozen security core (slices S1 + S2).
 *
 * S1 DELIVERS: a single entry point that wraps the frozen `guardToolRegistry` with a MANDATORY
 * `operation` and returns, side by side, (a) the registry's own untouched coverage report and (b) a
 * separately-computed, deliberately-narrower composition-level assurance. It performs NO IO — every
 * input is host-supplied, exactly like the primitives it composes.
 *
 * S2 ADDS startup honesty: it refuses to return a result that would LOOK protected while protection is
 * incomplete. Concretely S2 adds — (1) an explicit `unknownToolPolicy` default of 'mutating' when the
 * caller did not specify one, so an unclassified tool is never silently downgraded to readonly;
 * (2) an optional `requireCoverage` that aborts construction when the registry's coverage is weaker
 * than required, by an EXPLICIT strength ordering; (3) weakening-override residuals recorded onto
 * `composition_assurance` so the trace survives into any later coverageReport consumer. S2 adds NO
 * call-time behaviour.
 *
 * S2 does NOT re-guard what the registry already fails closed on. A `forceReadonly`/`classify`
 * downgrade of a heuristic mutator is, under the registry's default `failOnUnguardedMutator:true`,
 * already a thrown `FORCE_READONLY_MUTATOR` (no report exists); when the caller passes
 * `failOnUnguardedMutator:false` it is already registry coverage 'BYPASSED', which fails any
 * `requireCoverage` above BYPASSED by the ordering alone. So there is deliberately NO second
 * composition-level abort for weakening overrides — that would create two places that must agree. The
 * composition merely RECORDS the residual (composition_forced_readonly_on_heuristic_mutator /
 * composition_unknown_treated_as_readonly) so the reason the composition is narrower than it looks is
 * preserved on the assurance object. Registry-thrown errors propagate UNCHANGED (never wrapped or
 * swallowed).
 *
 * How the weakening residuals are derived, and their KNOWN LIMITATION (a frozen-registry property, not
 * a composition property): both residuals are read SOLELY from `registry_report.warnings` — the
 * composition never recomputes classification. The registry emits `force_readonly_on_mutator_heuristic`
 * ONLY for the downgrade of a HEURISTIC-classified mutator (a tool with no `classify` entry and no
 * `mutationClass`, whose NAME heuristic is mutating), reached via `forceReadonly` OR a `classify`
 * entry. Crucially, `forceReadonly` has NO effect on a tool the caller declared with an explicit
 * `mutationClass`: `resolveClass` (tool-registry.ts:154-165) returns on `tool.mutationClass` at :157,
 * BEFORE `forceReadonly` is consulted at :158 — so such a tool resolves `mutating`, stays guarded,
 * yields coverage 'COMPLETE', and emits NO warning. The composition therefore produces NO residual in
 * that case and CANNOT detect it: the caller's `forceReadonly` was silently ignored by the frozen
 * registry. This is a limitation of the frozen registry surface, recorded (not worked around) here and
 * pinned by a "documented limitation" test. The residual is named
 * `composition_forced_readonly_on_heuristic_mutator` so it does not promise coverage of the case it
 * cannot see.
 *
 * STILL DELIBERATELY OUT OF SCOPE (later slices; not stubbed, not implied here): call-time policy,
 * automatic binders, receipt carry-forward, WARN monitoring, framework adapters, artifact resolution.
 *
 * THE TWO-SCOPE RULE (never merged):
 *   - `registry_report` is EXACTLY what `guardToolRegistry` returned, passed through untouched. It may
 *     legitimately state coverage 'COMPLETE' and claim.inescapable_runtime true — that is the runtime
 *     tool-boundary's own honest truth (Placement A).
 *   - `composition_assurance` is the narrower PRODUCT-level statement — what withCodeRifts as a whole
 *     is willing to claim today. It is computed SEPARATELY and never rewrites the registry's verdict.
 *     Its S1 semantics are UNCHANGED in S2: coverage stays 'PARTIAL', inescapable_runtime stays false
 *     via the same COMPOSITION_CALL_POLICY_COMPLETE conjunction. S2 only appends residuals.
 * The two truths coexist; neither is derived by mutating the other.
 *
 * `requireCoverage` scope (read this before trusting a green construction): it constrains the
 * REGISTRY-level coverage ONLY. It CANNOT be used to demand composition-level runtime inescapability,
 * because S1's invariant makes that unreachable until S3 (binders) and S5 (receipt carry-forward)
 * land. A caller passing `requireCoverage:'COMPLETE'` is asserting an expectation about the registry
 * tool-boundary surface — NOT a product-level guarantee. The abort text and this doc say so explicitly
 * so nobody reads a green construction as product-level enforcement.
 *
 * Operation semantics (accurate scope): `operationForClass` (tool-registry.ts) already derives a
 * per-tool operation from the tool's mutation class, OVERRIDING the guard config for specialised
 * classes (deploy→'deploy', publish→'publish', vcs-merge→'merge', …). The mandatory `operation` here
 * therefore governs generic mutating tools and acts as the session-level default; it does NOT override
 * a deploy-class tool's 'deploy'. It is mandatory because receipts bind to an operation and
 * merge != deploy: a silent default would risk evaluating a deploy under merge semantics.
 *
 * Abort discipline: pre-registry input problems (missing/empty operation, missing client, an invalid
 * requireCoverage value) are collected and thrown as ONE error listing ALL of them. The
 * requireCoverage-vs-actual check is necessarily sequenced AFTER the registry call (it needs the
 * registry's coverage), so it is its own abort; it cannot be batched with the pre-registry problems
 * because a valid operation+client are required even to reach the registry.
 */

import { guardToolRegistry } from './tool-registry.js';
import type {
  RawTool,
  ProtectedTool,
  EnforcementCoverage,
  RegistryCoverageReport,
  GuardToolRegistryConfig,
  ToolBinder,
  ToolMutationClass,
} from './tool-registry.js';
import type { GuardConfig } from './types.js';

/** Registry config fields callers may forward untouched (S1/S2 do not re-declare them). */
export type WithCodeRiftsRegistryConfig = {
  unknownToolPolicy?: 'mutating' | 'readonly' | 'reject';
  classify?: Record<string, ToolMutationClass>;
  binders?: Record<string, ToolBinder>;
  forceReadonly?: string[];
  failOnUnguardedMutator?: boolean;
};

export type WithCodeRiftsInput = {
  /** Raw tool list handed to the frozen guardToolRegistry (required). */
  tools: RawTool[];
  /** The CodeRifts client guardToolRegistry's config.guard.client expects (required; checked at construction). */
  client: GuardConfig['client'];
  /**
   * REQUIRED session-level operation — no default. Receipts bind to an operation and merge != deploy,
   * so a silent default would risk evaluating a deploy under merge semantics. Governs generic mutating
   * tools; specialised classes keep their operationForClass-derived operation.
   */
  operation: string;
  /** Optional; carried through untouched. Artifact resolution is a later slice — S1 invents no use for it. */
  repository?: string;
  /**
   * Optional (S2). Minimum REGISTRY-level coverage required at construction. If the registry's actual
   * coverage is weaker than this (by the COVERAGE_STRENGTH ordering), construction ABORTS. It does NOT
   * demand composition-level inescapability (unreachable until S3/S5) — a green construction here is
   * NOT a product-level runtime-enforcement guarantee.
   */
  requireCoverage?: EnforcementCoverage;
  /** Optional passthrough of existing GuardToolRegistryConfig fields (forwarded as given). */
  registry?: WithCodeRiftsRegistryConfig;
};

/** The narrower product-level statement, computed separately from the registry's own report. */
export type CompositionAssurance = {
  coverage: EnforcementCoverage;
  inescapable_runtime: boolean;
  residuals: string[];
};

export type WithCodeRiftsResult = {
  tools: ProtectedTool[];
  /** Untouched RegistryCoverageReport — the registry's own truth (may be COMPLETE / inescapable). */
  registry_report: RegistryCoverageReport;
  /** Product-level assurance — deliberately narrower than the registry. */
  composition_assurance: CompositionAssurance;
  /** Carried through untouched from input when present (no resolution behaviour in S1/S2). */
  repository?: string;
};

/**
 * Whether the composition's call-time policy is complete. FALSE in S1/S2: automatic binders (S3) and
 * receipt carry-forward (S5) are not yet delivered, so the composition cannot claim runtime
 * inescapability. Later slices AND additional conjuncts into the composition invariant below rather
 * than replacing this one. UNCHANGED by S2.
 */
const COMPOSITION_CALL_POLICY_COMPLETE = false; // becomes true only once S3 (binders) + S5 (receipt carry-forward) land

const RESIDUAL_CALL_POLICY_INCOMPLETE = 'composition_call_policy_incomplete';
// S2 weakening-override residuals — derived SOLELY from registry report.warnings (never recomputed).
// The name says "heuristic_mutator" on purpose: the registry only emits the underlying warning for a
// downgrade of a HEURISTIC-classified mutator (see the header limitation), so the residual must not
// promise coverage of a downgrade it cannot see (an explicit-mutationClass tool).
const RESIDUAL_FORCED_READONLY = 'composition_forced_readonly_on_heuristic_mutator';
const RESIDUAL_UNKNOWN_READONLY = 'composition_unknown_treated_as_readonly';

/**
 * Coverage strength ordering, strongest → weakest. `requireCoverage` aborts when the registry's ACTUAL
 * coverage ranks strictly BELOW the required one. COMPLETE is the strongest; BYPASSED and UNKNOWN are
 * the weakest and are unacceptable for any requirement above them. UNKNOWN is the absolute floor
 * (fail-closed: an unobservable coverage never satisfies a requirement above it). Written explicitly
 * so the ordering is not implicit in comparison operators elsewhere.
 */
const COVERAGE_STRENGTH: Record<EnforcementCoverage, number> = {
  COMPLETE: 3,
  PARTIAL: 2,
  BYPASSED: 1,
  UNKNOWN: 0,
};

/** Rank of a coverage string, or undefined for an unrecognised value (fail-closed: caller treats as floor). */
function coverageRank(coverage: string): number | undefined {
  return Object.prototype.hasOwnProperty.call(COVERAGE_STRENGTH, coverage)
    ? COVERAGE_STRENGTH[coverage as EnforcementCoverage]
    : undefined;
}

/**
 * Wrap guardToolRegistry with a mandatory operation and a separately-computed composition assurance.
 * Fails at CONSTRUCTION (never at first tool call) for a missing client, a missing/empty operation, an
 * invalid requireCoverage value, or (S2) an unmet requireCoverage. Registry-thrown construction errors
 * propagate UNCHANGED.
 */
export function withCodeRifts(input: WithCodeRiftsInput): WithCodeRiftsResult {
  if (!input || typeof input !== 'object') {
    throw new Error('withCodeRifts: input object is required');
  }

  // Pre-registry input validation — collect ALL problems, throw once (a valid operation + client are
  // required even to reach the registry, so these cannot be batched with the post-registry check).
  const problems: string[] = [];
  if (typeof input.operation !== 'string' || input.operation.trim() === '') {
    problems.push('`operation` is required and must be a non-empty string (receipts bind to an operation; merge != deploy, so there is no safe default)');
  }
  if (input.client == null) {
    problems.push('`client` is required at construction (guardToolRegistry needs config.guard.client to wrap any mutating tool)');
  }
  if (input.requireCoverage !== undefined && coverageRank(input.requireCoverage) === undefined) {
    problems.push(`\`requireCoverage\` must be one of COMPLETE | PARTIAL | BYPASSED | UNKNOWN (got ${JSON.stringify(input.requireCoverage)})`);
  }
  if (problems.length > 0) {
    throw new Error(
      `withCodeRifts: construction aborted — ${problems.length} condition(s):\n`
      + problems.map((p) => `  - ${p}`).join('\n'),
    );
  }

  const reg = input.registry ?? {};
  // Defaults, applied ONLY when the caller did not specify them:
  //  - unknownToolPolicy → 'mutating': an unclassified tool must never SILENTLY become readonly (that
  //    would hide a raw mutating capability behind a green result). The caller may still explicitly pass
  //    'readonly'/'reject'; an explicit 'readonly' that downgrades an unknown tool is surfaced as the
  //    composition_unknown_treated_as_readonly residual below.
  //  - failOnUnguardedMutator: NOT defaulted here — the registry owns its own default (true). Forward
  //    the caller's value if given so there is a single source of truth for it.
  const config: GuardToolRegistryConfig = {
    guard: { client: input.client, operation: input.operation },
    unknownToolPolicy: reg.unknownToolPolicy ?? 'mutating',
    classify: reg.classify,
    binders: reg.binders,
    forceReadonly: reg.forceReadonly,
    failOnUnguardedMutator: reg.failOnUnguardedMutator,
  };

  // Registry-thrown construction errors (INVALID_TOOL, DUPLICATE_TOOL_NAME, UNKNOWN_TOOL,
  // FORCE_READONLY_MUTATOR, GUARD_CONFIG_INVALID) propagate UNCHANGED — never caught, wrapped, or
  // swallowed. That is the real contract: the composition does not re-guard what the registry
  // already fails closed on.
  const { tools, report } = guardToolRegistry(input.tools, config);

  // S2 requireCoverage — abort if the REGISTRY-level coverage is weaker than required. This is not a
  // weakening-specific rule: BYPASSED (from a forced downgrade under failOnUnguardedMutator:false) is
  // simply weaker than COMPLETE by the ordering, so it fails here for the same reason PARTIAL does.
  if (input.requireCoverage !== undefined) {
    const requiredRank = coverageRank(input.requireCoverage); // validated non-undefined pre-registry
    const actualRank = coverageRank(report.coverage) ?? -1;   // fail-closed: unknown coverage = below any floor
    if (requiredRank !== undefined && actualRank < requiredRank) {
      throw new Error(
        `withCodeRifts: requireCoverage not met — registry coverage '${report.coverage}' is weaker than required '${input.requireCoverage}' `
        + `(strength ordering COMPLETE > PARTIAL > BYPASSED > UNKNOWN). requireCoverage constrains the REGISTRY tool-boundary surface ONLY; `
        + `a green construction here is NOT a product-level runtime-inescapability guarantee — composition_assurance.inescapable_runtime stays false until S3/S5.`,
      );
    }
  }

  // Composition invariant — a conjunction later slices EXTEND (add conjuncts), never replace. Because
  // COMPOSITION_CALL_POLICY_COMPLETE is false, the result is deterministically false regardless of the
  // registry's own (possibly true) inescapable_runtime. UNCHANGED by S2.
  const compositionInescapableRuntime =
    report.claim.inescapable_runtime && COMPOSITION_CALL_POLICY_COMPLETE;

  // S2 residuals — DERIVED from the registry's own report.warnings, never recomputed. The registry
  // conflates forceReadonly and classify downgrades into one warning string, so this maps to two
  // causes (forced-readonly, unknown→readonly), not three (see recon item c).
  const residuals = [RESIDUAL_CALL_POLICY_INCOMPLETE];
  if (report.warnings.some((w) => w.startsWith('force_readonly_on_mutator_heuristic:'))) {
    residuals.push(RESIDUAL_FORCED_READONLY);
  }
  if (report.warnings.includes('unknown_treated_as_readonly')) {
    residuals.push(RESIDUAL_UNKNOWN_READONLY);
  }

  // 'PARTIAL' from the existing EnforcementCoverage union — never 'COMPLETE' while inescapable_runtime
  // is false (that combination would contradict the registry's own formula). UNCHANGED by S2.
  const composition_assurance: CompositionAssurance = {
    coverage: 'PARTIAL',
    inescapable_runtime: compositionInescapableRuntime,
    residuals,
  };

  const result: WithCodeRiftsResult = {
    tools,
    registry_report: report,
    composition_assurance,
  };
  if (input.repository !== undefined) result.repository = input.repository;
  return result;
}
