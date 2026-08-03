/**
 * withCodeRifts — additive orchestration layer above the frozen security core (slices S1 + S2 +
 * composition observation).
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
 * enforcement at call time.
 *
 * COMPOSITION OBSERVATION (this slice): optional `onEvent` is forwarded UNCHANGED onto the guard
 * config the composition builds (the same surface guardToolRegistry already spreads into
 * guardToolCall). Optional `onOutcome` is a composition-level hook: after each GUARDED tool's
 * execute returns a GuardOutcome, the composition invokes onOutcome then returns that outcome to the
 * host byte-identical. Observation is NOT enforcement — it does not change COMPOSITION_CALL_POLICY_COMPLETE,
 * coverage, residuals, or whether any tool runs.
 *
 * TELEMETRY GAPS (honest boundaries — read before claiming "every mutation was checked"):
 *   - onEvent does NOT emit a dedicated event for BLOCK or REQUIRE_APPROVAL; after preflight_result
 *     those paths return blocked with no further emit. Those outcomes ARE visible via onOutcome
 *     (outcome.executed === false, outcome.verdict.kind === 'BLOCK' | 'APPROVAL'), not via onEvent.
 *   - The GuardEvent payload carries no envelope, receipt, or fingerprint — only optional decisionId
 *     (and action/cause/signals/…). onOutcome carries the full GuardOutcome, including
 *     outcome.verdict.envelope where the frozen path attached one (BLOCK / APPROVAL / ALLOW / MONITOR).
 *   - onOutcome fires ONLY for guarded tools (_coderifts.guarded === true). Readonly passthrough
 *     tools never enter guardToolCall and produce no GuardOutcome; they are not wrapped and never
 *     fire onOutcome.
 *   - onEvent is partial even for other branches (e.g. closed-availability stops may emit only
 *     preflight_start; the declared type 'execution_skipped' is never emitted by the frozen core).
 *   - Neither hook alone is a complete substrate for receipt carry-forward: onEvent lacks the
 *     envelope/receipt; onOutcome exposes them when present but does not retain or re-inject them
 *     across calls (that is a later slice).
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
 * COMPOSITION_CALL_POLICY_COMPLETE (when the composition may claim product-level runtime
 * inescapability) requires ALL of the following — do not flip the constant when only a subset lands:
 *   (1) Automatic binders for call shapes that ALREADY carry both sides of the change (old_string/
 *       new_string, edits[]) — DONE (commit 582504a / defaultBinder lift). Not the same as covering
 *       every real agent edit shape.
 *   (2) Receipt carry-forward (S5) — host-threaded chaining is POSSIBLE (optional previousReceipt +
 *       verifyReceiptChainLinkage; commit 588a376). NOT met for this constant: the composition holds
 *       no cursor (decision, not omission — 3/5 design reviews against a package-held prior).
 *   (3) A freshness-safe source of prior content for write-style calls (path + new content only),
 *       where the host never supplied `before` — NOT done. The package performs no IO, so a prior it
 *       was not given cannot be obtained; inventing one (including empty-string before) would send a
 *       fabricated artifact to the oracle. That needs a host/guard freshness protocol, not another
 *       binder rename. Flipping this constant on (1)+(2) alone is incorrect.
 *
 * STILL DELIBERATELY OUT OF SCOPE (later slices; not stubbed, not implied here): receipt carry-forward;
 * freshness-safe prior content for write-style calls; call-time STOP re-implementation (already
 * complete in the frozen guardToolCall path); WARN monitoring policy beyond the frozen sink gate;
 * framework adapters. (Both-sides edit-side lifting in defaultBinder is landed — see (1) above.)
 *
 * THE TWO-SCOPE RULE (never merged):
 *   - `registry_report` is EXACTLY what `guardToolRegistry` returned, passed through untouched. It may
 *     legitimately state coverage 'COMPLETE' and claim.inescapable_runtime true — that is the runtime
 *     tool-boundary's own honest truth (Placement A).
 *   - `composition_assurance` is the narrower PRODUCT-level statement — what withCodeRifts as a whole
 *     is willing to claim today. It is computed SEPARATELY and never rewrites the registry's verdict.
 *     Its S1 semantics are UNCHANGED in S2 and under observation: coverage stays 'PARTIAL',
 *     inescapable_runtime stays false via the same COMPOSITION_CALL_POLICY_COMPLETE conjunction.
 * The two truths coexist; neither is derived by mutating the other.
 *
 * `requireCoverage` scope (read this before trusting a green construction): it constrains the
 * REGISTRY-level coverage ONLY. It CANNOT be used to demand composition-level runtime inescapability —
 * that remains unreachable while COMPOSITION_CALL_POLICY_COMPLETE is false (see the three conditions
 * above, not merely "binders + receipts"). A caller passing `requireCoverage:'COMPLETE'` is asserting
 * an expectation about the registry tool-boundary surface — NOT a product-level guarantee. The abort
 * text and this doc say so explicitly so nobody reads a green construction as product-level
 * enforcement.
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
import type { GuardConfig, GuardEvent, GuardOutcome } from './types.js';

/** Registry config fields callers may forward untouched (S1/S2 do not re-declare them). */
export type WithCodeRiftsRegistryConfig = {
  unknownToolPolicy?: 'mutating' | 'readonly' | 'reject';
  classify?: Record<string, ToolMutationClass>;
  binders?: Record<string, ToolBinder>;
  forceReadonly?: string[];
  failOnUnguardedMutator?: boolean;
};

/**
 * Composition-level observation of one guarded-tool return. Carries the tool name and the
 * GuardOutcome EXACTLY as returned by the frozen path — no summary, no extracted convenience fields.
 * Consumers that need the envelope read `outcome.verdict.envelope` (when present on that arm).
 */
export type ObservedOutcome = {
  toolName: string;
  outcome: GuardOutcome<unknown>;
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
   * demand composition-level inescapability (unreachable while COMPOSITION_CALL_POLICY_COMPLETE is
   * false — binders-for-both-sides alone do not suffice; see file header) — a green construction here
   * is NOT a product-level runtime-enforcement guarantee.
   */
  requireCoverage?: EnforcementCoverage;
  /** Optional passthrough of existing GuardToolRegistryConfig fields (forwarded as given). */
  registry?: WithCodeRiftsRegistryConfig;
  /**
   * Optional. Forwarded UNCHANGED onto the guard config (config.guard.onEvent) so the frozen
   * guardToolCall emit path can reach it. Not wrapped, not filtered, no extra events added.
   * See header TELEMETRY GAPS: partial; does not carry envelope/receipt/fingerprint.
   */
  onEvent?: (e: GuardEvent) => void;
  /**
   * Optional. Invoked by the composition after each GUARDED tool execute returns, with toolName + the
   * unmodified GuardOutcome. Does not fire for readonly passthrough. Throws and rejected promises are
   * swallowed so observation never changes host-visible execution. See header TELEMETRY GAPS.
   */
  onOutcome?: (o: ObservedOutcome) => void | PromiseLike<void>;
  /**
   * Optional prior chain-receipt token (or getter) forwarded onto GuardConfig.previousReceipt.
   * Host-owned; the composition does not retain or advance it between calls.
   */
  previousReceipt?: string | (() => string | undefined | null);
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
 * Whether the composition's call-time / content policy is complete enough to claim product-level
 * runtime inescapability. Stays FALSE until EVERY condition below is delivered — later slices ADD
 * conjuncts to the invariant that uses this flag; they must not replace a narrower false narrative.
 *
 * Conditions (all required; do NOT flip this constant because a subset landed):
 *   (1) DONE — automatic binders for shapes that already carry both edit sides (old_string/new_string,
 *       edits[] → artifacts). Commit 582504a. Does NOT cover write-style path+new-content-only calls.
 *   (2) NOT DONE — receipt carry-forward (S5).
 *   (3) NOT DONE — freshness-safe prior content for write-style calls. The package does no IO, so a
 *       `before` the host never supplied cannot be obtained; inventing one (including empty string)
 *       fabricates an oracle input. Needs a host/guard freshness protocol, not binder renaming.
 *
 * Historically this comment named only (1) and (2). That wording is narrower than reality: after (1)
 * shipped, a reader could think "binders + S5" was enough and flip the flag incorrectly. Do not.
 *
 * UNCHANGED by S2 / composition observation (observing ≠ enforcing). Value stays false until all three.
 */
const COMPOSITION_CALL_POLICY_COMPLETE = false;

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
 * Invoke onOutcome without affecting the host call. Swallows synchronous throws AND rejected
 * promises (unlike the frozen emit hook, which only try/catches sync throws and ignores returned
 * promises — that host-side footgun is deliberately not reproduced here).
 */
async function safeOnOutcome(
  onOutcome: (o: ObservedOutcome) => void | PromiseLike<void>,
  payload: ObservedOutcome,
): Promise<void> {
  try {
    await Promise.resolve(onOutcome(payload));
  } catch {
    /* observation never changes execution */
  }
}

/**
 * Build a NEW ProtectedTool shell around a frozen guarded tool so we can replace execute without
 * mutating the frozen registry object. name / description / inputSchema / meta / _coderifts are
 * copied by reference (the _coderifts bag is already frozen by the registry). The new shell is
 * frozen for parity with registry tools.
 */
function wrapGuardedForObservation(
  tool: ProtectedTool,
  onOutcome: (o: ObservedOutcome) => void | PromiseLike<void>,
): ProtectedTool {
  const innerExecute = tool.execute;
  const toolName = tool.name;
  const shell: ProtectedTool = {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    meta: tool.meta,
    _coderifts: tool._coderifts,
    execute: async (args: unknown) => {
      // If the inner execute rejects, do NOT invent an outcome — propagate the rejection unchanged.
      const outcome = await innerExecute(args);
      await safeOnOutcome(onOutcome, {
        toolName,
        // Guarded execute always returns a GuardOutcome from guardToolCall; assert the type for callers.
        outcome: outcome as GuardOutcome<unknown>,
      });
      // Host must receive the same object the unwrapped tool returned (reference-identical).
      return outcome;
    },
  };
  // Match registry freeze discipline: freeze _coderifts if not already, freeze the shell.
  if (!Object.isFrozen(shell._coderifts)) Object.freeze(shell._coderifts);
  return Object.freeze(shell);
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
  // Guard config: client + operation always; onEvent forwarded UNCHANGED when provided (no second
  // try/catch layer — frozen emit already swallows sync throws).
  const guard: GuardConfig = { client: input.client, operation: input.operation };
  if (input.onEvent !== undefined) {
    guard.onEvent = input.onEvent;
  }
  if (input.previousReceipt !== undefined) {
    guard.previousReceipt = input.previousReceipt;
  }
  const config: GuardToolRegistryConfig = {
    guard,
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
        + `a green construction here is NOT a product-level runtime-inescapability guarantee — composition_assurance.inescapable_runtime stays false until receipt carry-forward and a freshness-safe prior for write-style calls land.`,
      );
    }
  }

  // Composition invariant — a conjunction later slices EXTEND (add conjuncts), never replace. Because
  // COMPOSITION_CALL_POLICY_COMPLETE is false, the result is deterministically false regardless of the
  // registry's own (possibly true) inescapable_runtime. UNCHANGED by S2. UNCHANGED by observation.
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
  // is false (that combination would contradict the registry's own formula). UNCHANGED by S2 / observation.
  const composition_assurance: CompositionAssurance = {
    coverage: 'PARTIAL',
    inescapable_runtime: compositionInescapableRuntime,
    residuals,
  };

  // Outcome observation: registry returns FROZEN ProtectedTool objects (and a frozen tools array).
  // We cannot reassign execute on a frozen tool, so we build NEW shells for guarded tools only when
  // onOutcome is provided. Readonly tools are left as the same object references (no GuardOutcome).
  // The tools ARRAY is also frozen by the registry — always return a fresh array when we wrap.
  let toolsOut: ProtectedTool[] = tools as ProtectedTool[];
  if (input.onOutcome) {
    const onOutcome = input.onOutcome;
    toolsOut = Object.freeze(
      tools.map((t) => (t._coderifts.guarded ? wrapGuardedForObservation(t, onOutcome) : t)),
    ) as ProtectedTool[];
  }

  const result: WithCodeRiftsResult = {
    tools: toolsOut,
    registry_report: report,
    composition_assurance,
  };
  if (input.repository !== undefined) result.repository = input.repository;
  return result;
}
