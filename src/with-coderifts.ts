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
 * COMPOSITION OBSERVATION: optional `onEvent` is forwarded UNCHANGED onto the guard config.
 * Optional `onSettledCall` is a composition-level hook: it fires EXACTLY ONCE for every SETTLED
 * call through the RETURNED tool table (GUARDED | PASSTHROUGH | BYPASSED × RETURNED | THREW).
 * Discriminant is an EXPLICIT TAG (`kind: 'settled_call'` plus route/terminal), never the absence of
 * a field. On the GUARDED+RETURNED arm, `outcome` is non-optional. Observation is NOT enforcement —
 * it does not change COMPOSITION_CALL_POLICY_COMPLETE, coverage, residuals, or whether any tool runs.
 * The package holds NO counters and computes NO ratios at runtime; pure fold helpers are optional
 * host-side tools (see foldTableSettledCalls / guardedFractionAmongRoutes).
 *
 * TELEMETRY GAPS (honest boundaries — read before claiming "every mutation was checked"):
 *   - onEvent does NOT emit a dedicated event for BLOCK or REQUIRE_APPROVAL; after preflight_result
 *     those paths return blocked with no further emit. Those outcomes ARE visible via onSettledCall
 *     on the GUARDED arm (outcome.executed === false, outcome.verdict.kind === 'BLOCK' | 'APPROVAL').
 *   - The GuardEvent payload carries no envelope, receipt, or fingerprint — only optional decisionId
 *     (and action/cause/signals/…). GUARDED+RETURNED onSettledCall carries the full GuardOutcome,
 *     including outcome.verdict.envelope where the frozen path attached one.
 *   - onSettledCall sees ONLY calls through the table withCodeRifts returned. Host-invoked raw tools
 *     outside that table are invisible. Never treat observation as "total operations" or "100%
 *     enforcement coverage".
 *   - onEvent is partial even for other branches (e.g. closed-availability stops may emit only
 *     preflight_start; the declared type 'execution_skipped' is never emitted by the frozen core).
 *   - Neither hook alone is a complete substrate for receipt carry-forward: onEvent lacks the
 *     envelope/receipt; onSettledCall exposes them when present on the GUARDED+RETURNED arm but does
 *     not retain or re-inject them across calls (that is a later slice).
 *
 * S2 does NOT re-guard what the registry already fails closed on. A `forceReadonly`/`classify`
 * downgrade of a heuristic mutator is, under the registry's default `failOnUnguardedMutator:true`,
 * already a thrown `FORCE_READONLY_MUTATOR` (no report exists); when the caller passes
 * `failOnUnguardedMutator:false` it is already registry coverage 'BYPASSED', which fails any
 * `requireCoverage` above BYPASSED by the ordering alone. The composition RECORDS residuals from
 * registry warnings. When forceReadonly lists a tool that declared explicit mutationClass, the
 * registry emits `force_readonly_ignored_explicit_mutation_class:<name>` (break-glass ignored).
 *
 * COMPOSITION_CALL_POLICY_COMPLETE (when the composition may claim product-level runtime
 * inescapability) requires ALL of the following — do not flip the constant when only a subset lands:
 *   (1) Automatic binders for call shapes that ALREADY carry both sides of the change (old_string/
 *       new_string, edits[]) — DONE. Not the same as covering every real agent edit shape.
 *   (2) Receipt carry-forward (S5) — host-threaded chaining is POSSIBLE (optional previousReceipt +
 *       verifyReceiptChainLinkage). NOT met for this constant: the composition holds no cursor.
 *   (3) A freshness-safe source of prior content for write-style calls (path + new content only) —
 *       PURE CORE shipped (`assessFreshness` / `assessWriteStylePrior` in freshness.ts): content-
 *       identity recompute, four outcomes, write-style requires artifact id. NOT DONE: wiring into
 *       guardToolCall enforce path, host resolve adapter, receipt-bound optional tree hash, or
 *       flipping COMPOSITION_CALL_POLICY_COMPLETE.
 *
 * THE TWO-SCOPE RULE (never merged):
 *   - `registry_report` is EXACTLY what `guardToolRegistry` returned, passed through untouched.
 *   - `composition_assurance` is the narrower PRODUCT-level statement, computed SEPARATELY.
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

/** Route of a settled call through the returned table. Explicit tag values — never inferred by field absence. */
export type CallRoute = 'GUARDED' | 'PASSTHROUGH' | 'BYPASSED';

/** How a settled call finished. Explicit tag values. */
export type CallTerminal = 'RETURNED' | 'THREW';

/**
 * One settled call through the tool table withCodeRifts returned.
 *
 * Discriminant is the EXPLICIT `kind: 'settled_call'` plus `route` and `terminal` tags — never
 * "outcome present vs missing". On GUARDED+RETURNED, `outcome` is required (non-optional).
 *
 * Replaces the former `ObservedOutcome` (`{ toolName, outcome }` only for guarded returns). The old
 * name implied every observation carried a GuardOutcome and that only guarded tools were visible;
 * both were false once passthrough/threw routes ship, so the name is retired rather than overloaded.
 */
export type SettledCallObservation =
  | {
      kind: 'settled_call';
      route: 'GUARDED';
      terminal: 'RETURNED';
      toolName: string;
      outcome: GuardOutcome<unknown>;
    }
  | {
      kind: 'settled_call';
      route: 'GUARDED';
      terminal: 'THREW';
      toolName: string;
      error: unknown;
    }
  | {
      kind: 'settled_call';
      route: 'PASSTHROUGH';
      terminal: 'RETURNED';
      toolName: string;
      result: unknown;
    }
  | {
      kind: 'settled_call';
      route: 'PASSTHROUGH';
      terminal: 'THREW';
      toolName: string;
      error: unknown;
    }
  | {
      kind: 'settled_call';
      route: 'BYPASSED';
      terminal: 'RETURNED';
      toolName: string;
      result: unknown;
    }
  | {
      kind: 'settled_call';
      route: 'BYPASSED';
      terminal: 'THREW';
      toolName: string;
      error: unknown;
    };

/**
 * Counts of settled-call routes from a host-collected event list.
 * Names are route tags only — not "total operations" or "enforcement coverage".
 */
export type TableSettledCallRouteCounts = {
  GUARDED: number;
  PASSTHROUGH: number;
  BYPASSED: number;
};

/**
 * Pure fold: count routes in a host-owned list of settled-call observations.
 * The package never accumulates these at runtime.
 */
export function foldTableSettledCalls(
  events: readonly SettledCallObservation[],
): TableSettledCallRouteCounts {
  const counts: TableSettledCallRouteCounts = { GUARDED: 0, PASSTHROUGH: 0, BYPASSED: 0 };
  for (const e of events) {
    if (e.kind !== 'settled_call') continue;
    counts[e.route] += 1;
  }
  return counts;
}

/**
 * Fraction of GUARDED among observed routes, or ABSENT when a ratio would be misleading.
 *
 * Returns `kind: 'absent'` (not zero) when:
 *   - no settled calls were observed, or
 *   - only a single route tag has a non-zero count (one-sided observation).
 *
 * Never returns a number that could be read as "0% enforcement" or "100% coverage" from partial data.
 * The package does not call this automatically.
 */
export function guardedFractionAmongRoutes(
  counts: TableSettledCallRouteCounts,
):
  | { kind: 'absent'; why: 'no_settled_calls' | 'one_route_only' }
  | { kind: 'present'; fraction: number } {
  const routesWithCalls = (['GUARDED', 'PASSTHROUGH', 'BYPASSED'] as const)
    .filter((r) => counts[r] > 0);
  if (routesWithCalls.length === 0) {
    return { kind: 'absent', why: 'no_settled_calls' };
  }
  if (routesWithCalls.length === 1) {
    return { kind: 'absent', why: 'one_route_only' };
  }
  const sum = counts.GUARDED + counts.PASSTHROUGH + counts.BYPASSED;
  return { kind: 'present', fraction: counts.GUARDED / sum };
}

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
   * Alone does NOT unlock WARN/MONITOR — also set monitoringSinkWired: true (host assertion).
   */
  onEvent?: (e: GuardEvent) => void;
  /**
   * Optional. Host assertion that a monitoring sink is intentionally wired. Forwarded onto
   * GuardConfig.monitoringSinkWired. Must agree with onEvent for CONTINUE_WITH_MONITORING.
   * See GuardConfig.monitoringSinkWired docs: claim, not delivery proof.
   */
  monitoringSinkWired?: boolean;
  /**
   * Optional. Invoked once per SETTLED call through the returned tool table (every route and both
   * terminals). Discriminated union — see SettledCallObservation. Throws and rejected promises are
   * swallowed so observation never changes host-visible execution. Replaces the former `onOutcome`
   * (guarded-only) hook.
   */
  onSettledCall?: (o: SettledCallObservation) => void | PromiseLike<void>;
  /**
   * Optional prior chain-receipt token (or getter) forwarded onto GuardConfig.previousReceipt.
   * Host-owned; the composition does not retain or advance it between calls.
   */
  previousReceipt?: string | (() => string | undefined | null);
  /**
   * Optional freshness prior resolver (opt-in). Forwarded onto GuardConfig.resolvePriorContent.
   * When absent: composition residual composition_freshness_not_configured; per-call basis
   * NOT_CONFIGURED. When present: host commitment — failures are DEGRADED, not silent opt-out.
   */
  resolvePriorContent?: GuardConfig['resolvePriorContent'];
  /** Policy: write-style without ACTIVE freshness does not proceed. Default false (API opt-in). */
  requireFreshness?: boolean;
  /** STALE_CONTEXT policy opt-out forwarded onto GuardConfig.allowStaleContext. */
  allowStaleContext?: boolean;
};

/** The narrower product-level statement, computed separately from the registry's own report. */
export type CompositionAssurance = {
  coverage: EnforcementCoverage;
  inescapable_runtime: boolean;
  residuals: string[];
  /**
   * Whether the host supplied resolvePriorContent (composition-level claim).
   * Does NOT mean any given call was fresh — that is outcome.freshness per call.
   * Never implies inescapable_runtime.
   */
  freshness_resolver_wired: boolean;
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
 *       edits[] → artifacts). Does NOT cover write-style path+new-content-only calls.
 *   (2) NOT DONE — receipt carry-forward (S5).
 *   (3) NOT DONE for product claim — pure core + opt-in wiring exist (resolvePriorContent +
 *       per-call basis). COMPOSITION_CALL_POLICY_COMPLETE stays false until freshness is ACTIVE
 *       by default for writes AND remaining conjuncts land. Host may still omit the resolver.
 *
 * UNCHANGED by S2 / composition observation (observing ≠ enforcing). Value stays false until all three.
 */
const COMPOSITION_CALL_POLICY_COMPLETE = false;

const RESIDUAL_CALL_POLICY_INCOMPLETE = 'composition_call_policy_incomplete';
/** Composition residual: host did not supply resolvePriorContent (NOT the same as DEGRADED). */
const RESIDUAL_FRESHNESS_NOT_CONFIGURED = 'composition_freshness_not_configured';
// S2 weakening-override residuals — derived SOLELY from registry report.warnings (never recomputed).
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
 * Invoke onSettledCall without affecting the host call. Swallows synchronous throws AND rejected
 * promises (unlike the frozen emit hook, which only try/catches sync throws and ignores returned
 * promises — that host-side footgun is deliberately not reproduced here).
 */
async function safeOnSettledCall(
  onSettledCall: (o: SettledCallObservation) => void | PromiseLike<void>,
  payload: SettledCallObservation,
): Promise<void> {
  try {
    await Promise.resolve(onSettledCall(payload));
  } catch {
    /* observation never changes execution */
  }
}

/**
 * Build a NEW ProtectedTool shell so we can observe settle without mutating the frozen registry object.
 * name / description / inputSchema / meta / _coderifts are copied by reference.
 */
function wrapForSettledCallObservation(
  tool: ProtectedTool,
  route: CallRoute,
  onSettledCall: (o: SettledCallObservation) => void | PromiseLike<void>,
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
      try {
        const result = await innerExecute(args);
        if (route === 'GUARDED') {
          await safeOnSettledCall(onSettledCall, {
            kind: 'settled_call',
            route: 'GUARDED',
            terminal: 'RETURNED',
            toolName,
            // Guarded execute always returns a GuardOutcome from guardToolCall.
            outcome: result as GuardOutcome<unknown>,
          });
        } else {
          await safeOnSettledCall(onSettledCall, {
            kind: 'settled_call',
            route,
            terminal: 'RETURNED',
            toolName,
            result,
          });
        }
        // Host must receive the same object/value the unwrapped tool returned (reference-identical for objects).
        return result;
      } catch (error) {
        await safeOnSettledCall(onSettledCall, {
          kind: 'settled_call',
          route,
          terminal: 'THREW',
          toolName,
          error,
        });
        throw error;
      }
    },
  };
  if (!Object.isFrozen(shell._coderifts)) Object.freeze(shell._coderifts);
  return Object.freeze(shell);
}

/** Tools forced to readonly via heuristic break-glass — observed as BYPASSED, not true PASSTHROUGH. */
function bypassedToolNames(report: RegistryCoverageReport): Set<string> {
  const names = new Set<string>();
  for (const w of report.warnings) {
    const prefix = 'force_readonly_on_mutator_heuristic:';
    if (w.startsWith(prefix)) names.add(w.slice(prefix.length));
  }
  return names;
}

function routeForTool(tool: ProtectedTool, bypassed: Set<string>): CallRoute {
  if (tool._coderifts.guarded) return 'GUARDED';
  if (bypassed.has(tool.name)) return 'BYPASSED';
  return 'PASSTHROUGH';
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
  // Guard config: client + operation always; onEvent + monitoringSinkWired forwarded UNCHANGED when
  // provided (no second try/catch layer — frozen emit already swallows sync throws).
  const guard: GuardConfig = { client: input.client, operation: input.operation };
  if (input.onEvent !== undefined) {
    guard.onEvent = input.onEvent;
  }
  if (input.monitoringSinkWired !== undefined) {
    guard.monitoringSinkWired = input.monitoringSinkWired;
  }
  if (input.previousReceipt !== undefined) {
    guard.previousReceipt = input.previousReceipt;
  }
  if (input.resolvePriorContent !== undefined) {
    guard.resolvePriorContent = input.resolvePriorContent;
  }
  if (input.requireFreshness !== undefined) {
    guard.requireFreshness = input.requireFreshness;
  }
  if (input.allowStaleContext !== undefined) {
    guard.allowStaleContext = input.allowStaleContext;
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
  // Freshness resolver: composition-level visibility. Absence is residual NOT_CONFIGURED;
  // presence is a host claim (freshness_resolver_wired), not proof every call was measured.
  // Does NOT flip COMPOSITION_CALL_POLICY_COMPLETE or inescapable_runtime.
  const freshness_resolver_wired = typeof input.resolvePriorContent === 'function';
  if (!freshness_resolver_wired) {
    residuals.push(RESIDUAL_FRESHNESS_NOT_CONFIGURED);
  }

  // 'PARTIAL' from the existing EnforcementCoverage union — never 'COMPLETE' while inescapable_runtime
  // is false (that combination would contradict the registry's own formula). UNCHANGED by S2 / observation.
  const composition_assurance: CompositionAssurance = {
    coverage: 'PARTIAL',
    inescapable_runtime: compositionInescapableRuntime,
    residuals,
    freshness_resolver_wired,
  };

  // Settled-call observation: registry returns FROZEN ProtectedTool objects (and a frozen tools array).
  // We cannot reassign execute on a frozen tool, so we build NEW shells for EVERY tool in the table
  // when onSettledCall is provided — including passthrough and forced-bypass (readonly) tools.
  let toolsOut: ProtectedTool[] = tools as ProtectedTool[];
  if (input.onSettledCall) {
    const onSettledCall = input.onSettledCall;
    const bypassed = bypassedToolNames(report);
    toolsOut = Object.freeze(
      tools.map((t) => wrapForSettledCallObservation(t, routeForTool(t, bypassed), onSettledCall)),
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
