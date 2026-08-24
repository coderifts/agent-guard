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
 * Settled-call observation holds NO ratios at runtime; pure fold helpers remain optional
 * host-side tools (see foldTableSettledCalls / guardedFractionAmongRoutes). Dispatch counts live
 * on `coverage_observed` (Half A always; Half B only when the host reports).
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
 *   - onEvent still lacks envelope/receipt. onSettledCall exposes them on GUARDED+RETURNED when present.
 *     S5: when threadReceipts is enabled (default), the composition ALSO retains the last enforced
 *     receipt token and re-injects it as previous_receipt on the next preflight — host previousReceipt
 *     always wins over the cursor. This is carry-forward of a token, not chain authenticity.
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
 *   (2) Receipt carry-forward (S5) — composition cursor EXISTS (threadReceipts default on; host
 *       previousReceipt overrides; advance only on enforced + receipt token; refuse under overlap).
 *       NOT sufficient alone to flip this constant: package never self-attests chain authenticity
 *       (consumer re-runs verifyReceiptChainLinkage), and concurrent overlap refuses to advance.
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
import { createCoverageObserver } from './coverage-observed.js';
import type { CoverageObserver } from './coverage-observed.js';

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

/** Opt-in fail-closed lock. Only value today: ENFORCING_STRICT. Absent = today's per-flag defaults. */
export type WithCodeRiftsProfile = 'ENFORCING_STRICT';

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
  /**
   * Opt-in profile. `ENFORCING_STRICT` locks the fail-closed conjunction (requireCoverage COMPLETE,
   * requireFreshness, requireExecutionStateMatch true, requireConditionalWrite, requireCommitObservation,
   * failOnUnguardedMutator, unknownToolPolicy mutating) and ABORTS construction on any conflicting opt-down.
   * Absent: today's defaults (freshness/conditional-write remain opt-in). Not weakenable when set.
   */
  profile?: WithCodeRiftsProfile;
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
   * Optional dedicated CWM delivery sink (callback or HTTP). Forwarded onto GuardConfig.
   * Distinct from onEvent. See monitoring_delivery on the CWM outcome.
   */
  monitoringSink?: GuardConfig['monitoringSink'];
  monitoringSinkTimeoutMs?: GuardConfig['monitoringSinkTimeoutMs'];
  ackHmacKey?: GuardConfig['ackHmacKey'];
  /**
   * Optional. Invoked once per SETTLED call through the returned tool table (every route and both
   * terminals). Discriminated union — see SettledCallObservation. Throws and rejected promises are
   * swallowed so observation never changes host-visible execution. Replaces the former `onOutcome`
   * (guarded-only) hook.
   */
  onSettledCall?: (o: SettledCallObservation) => void | PromiseLike<void>;
  /**
   * Optional prior chain-receipt token (or getter). When set, ALWAYS wins over the composition
   * cursor for the preflight `previous_receipt` field — the host may know a prior the composition
   * does not. String or zero-arg getter (same shape as GuardConfig.previousReceipt).
   */
  previousReceipt?: string | (() => string | undefined | null);
  /**
   * Automatic receipt carry-forward for this composition instance (default true).
   * When enabled, each enforced+receipt-verified guarded call advances a per-composition cursor
   * that is supplied as previous_receipt on the next preflight unless the host overrides.
   *
   * Default ON (opt-out) — unlike freshness, which is opt-in because it needs a host resolver:
   * threading only reuses a token the composition already observed. Set false for independent
   * root receipts every call. Does not verify or re-sign; does not claim chain authenticity.
   */
  threadReceipts?: boolean;
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
  /**
   * Policy: write-style without host conditional_write:true does not enforce.
   * Default false (API opt-in). Forwarded onto GuardConfig.requireConditionalWrite.
   * Host residual when policy is on without host report: composition_unconditional_write_under_policy.
   */
  requireConditionalWrite?: boolean;
  /**
   * Policy (ID842): T2 execution-time fingerprint recheck. Forwarded UNCHANGED onto
   * GuardConfig.requireExecutionStateMatch. Absent inherits guard@8 default true
   * (fail-closed). Explicit opt-down: false | 'warn'.
   */
  requireExecutionStateMatch?: GuardConfig['requireExecutionStateMatch'];
  /**
   * Policy (ID781 T3): post-commit observation. Forwarded onto GuardConfig.requireCommitObservation.
   * Absent inherits default true. Explicit opt-out: false (emits commit_observation_check_disabled;
   * does not change enforced). Under `profile: 'ENFORCING_STRICT'`, false aborts construction
   * (`requireCommitObservation conflicts`) and the lock forces true.
   */
  requireCommitObservation?: GuardConfig['requireCommitObservation'];
  /**
   * S6 auto-recheck. Default OFF. `{ maxAttempts: 1|2|3, applyFix }` — the HOST applies
   * the fix (guard never writes artifacts). Hard cap 3 re-preflights.
   */
  autoRecheck?: GuardConfig['autoRecheck'];
  /**
   * S1 auto-derive. Default OFF. `true` or `{ readers?: { fs, api, db, registry } }`.
   * Fills before/after when the host did not supply args.artifacts. Flip-to-default
   * is a later, evidence-gated decision.
   */
  autoDerive?: GuardConfig['autoDerive'];
  /**
   * S2-F2a R3. Customer-pinned executor registry `{ registry }`. Forwarded onto GuardConfig.
   * Default absent — no verification attempted, CAS evidence stays host_claimed (no penalty).
   */
  executorAttestation?: GuardConfig['executorAttestation'];
  /**
   * Opt-in CWM monitoring attestation. Forwarded onto GuardConfig.
   * `{ kid, signer }` — host sign(bytes), never a raw key. Absent = today's CWM (no token).
   */
  monitoringAttestation?: GuardConfig['monitoringAttestation'];
  /**
   * Optional host system-prompt / instruction text. Forwarded onto GuardConfig.
   * Observation only (policy_presence). Absent = field omitted on the outcome.
   */
  systemPrompt?: string;
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
  /**
   * Live classification of observed tool traffic vs the returned table.
   * UNKNOWN_OUTSIDE_SCOPE until the host reports dispatches (Half B).
   * Not COMPLETE — COMPLETE on registry_report is table-truth, not agent-truth.
   */
  readonly observed_class: import('./coverage-observed.js').CoverageObservedClass;
};

export type WithCodeRiftsResult = {
  tools: ProtectedTool[];
  /** Untouched RegistryCoverageReport — the registry's own truth (may be COMPLETE / inescapable). */
  registry_report: RegistryCoverageReport;
  /** Product-level assurance — deliberately narrower than the registry. */
  composition_assurance: CompositionAssurance;
  /**
   * Per-composition receipt cursor handle (always present). When enabled is false the getters
   * stay empty / skip as disabled. NOT product-truth chain evidence.
   */
  receipt_thread: ReceiptThreadHandle;
  /**
   * Observed coverage for THIS withCodeRifts instance (the run). Half A always;
   * Half B via reportToolDispatch. Not a process-wide session.
   */
  coverage_observed: import('./coverage-observed.js').CoverageObservedHandle;
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
 *   (2) PARTIAL — composition receipt cursor (S5) ships; still not product-level chain authenticity
 *       and refuses under concurrent overlap (honest non-order, not a guessed order).
 *   (3) NOT DONE for product claim — pure core + opt-in wiring exist (resolvePriorContent +
 *       per-call basis). COMPOSITION_CALL_POLICY_COMPLETE stays false until freshness is ACTIVE
 *       by default for writes AND remaining conjuncts land. Host may still omit the resolver.
 *
 * UNCHANGED by S2 / composition observation (observing ≠ enforcing). Value stays false until all three.
 */
const COMPOSITION_CALL_POLICY_COMPLETE = false;

/**
 * Why the composition receipt cursor did not advance after a settled guarded call.
 * Concurrent overlap is a first-class reason: a last-write-wins cursor under parallelism would
 * produce a chain that LOOKS ordered and is not — refuse and report rather than guess.
 */
export type ReceiptCursorSkipReason =
  | 'concurrent_overlap'
  | 'not_enforced'
  | 'no_receipt_token'
  | 'threw_before_outcome';

/**
 * Composition-held receipt carry-forward diagnostics.
 *
 * This is a TOKEN cursor only: it does not verify signatures, linkage, or authorization.
 * Consumers that need product truth re-run verifyReceiptChainLinkage (and signature verify)
 * on an export they hold — the package never reports its own chain as authentic.
 */
export type ReceiptThreadHandle = {
  /** Automatic carry-forward enabled for this composition instance. */
  enabled: boolean;
  /** Last token advanced into the cursor (undefined if never advanced). */
  lastToken: () => string | undefined;
  /**
   * Why the most recent settled guarded call did not advance the cursor.
   * null means the last considered call advanced (or no call has settled yet).
   */
  lastSkipReason: () => ReceiptCursorSkipReason | null;
};

const RESIDUAL_CALL_POLICY_INCOMPLETE = 'composition_call_policy_incomplete';
/** Composition residual: host did not supply resolvePriorContent (NOT the same as DEGRADED). */
const RESIDUAL_FRESHNESS_NOT_CONFIGURED = 'composition_freshness_not_configured';
/**
 * Honesty residual: host-invoked raw tools outside the returned table are invisible.
 * Always named under ENFORCING_STRICT — never a claim of total inescapability (ID781).
 */
const RESIDUAL_CALLS_OUTSIDE_GUARDED_PATH = 'calls_outside_guarded_path_invisible';
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

function isEnforcingStrict(input: WithCodeRiftsInput): boolean {
  return input.profile === 'ENFORCING_STRICT';
}

/**
 * Explicit opt-downs that contradict ENFORCING_STRICT. Empty = no conflict.
 * `unknownToolPolicy: 'reject'` is stricter than 'mutating' (unclassified throws) — not a weaken.
 * `'readonly'` hides a possible mutator → conflict.
 */
function enforcingStrictWeakenFlags(input: WithCodeRiftsInput): string[] {
  const flags: string[] = [];
  if (input.requireCoverage !== undefined) {
    const rank = coverageRank(input.requireCoverage);
    if (rank !== undefined && rank < COVERAGE_STRENGTH.COMPLETE) flags.push('requireCoverage');
  }
  if (input.requireFreshness === false) flags.push('requireFreshness');
  if (input.requireExecutionStateMatch === false || input.requireExecutionStateMatch === 'warn') {
    flags.push('requireExecutionStateMatch');
  }
  if (input.requireConditionalWrite === false) flags.push('requireConditionalWrite');
  if (input.requireCommitObservation === false) flags.push('requireCommitObservation');
  const reg = input.registry ?? {};
  if (reg.failOnUnguardedMutator === false) flags.push('failOnUnguardedMutator');
  if (reg.unknownToolPolicy === 'readonly') flags.push('unknownToolPolicy');
  return flags;
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

/** Resolve host previousReceipt the same way the frozen guard does (string or getter). */
function resolveHostPreviousReceipt(
  pr: string | (() => string | undefined | null),
): string | undefined {
  let raw: unknown;
  if (typeof pr === 'function') {
    try { raw = pr(); } catch { return undefined; }
  } else {
    raw = pr;
  }
  if (typeof raw !== 'string') return undefined;
  const s = raw.trim();
  return s.length > 0 ? s : undefined;
}

/**
 * Per-composition receipt cursor. Scope is this withCodeRifts instance only (not process/session).
 *
 * Concurrency: if a second guarded call starts while another is in flight, overlapDirty is set and
 * NO completion advances the cursor until inFlight returns to 0. Last-write-wins under parallelism
 * would invent an order the package did not observe — refuse and report concurrent_overlap instead.
 *
 * Advance only when: threading enabled, no overlap, outcome.enforced === true, and a non-empty
 * receipt token is present on the verified envelope. BLOCK / unenforced / throw-before-outcome do not.
 */
type ReceiptCursorState = {
  enabled: boolean;
  token: string | undefined;
  inFlight: number;
  overlapDirty: boolean;
  lastSkip: ReceiptCursorSkipReason | null;
  begin: () => void;
  end: () => void;
  considerOutcome: (outcome: GuardOutcome<unknown>) => void;
  considerThrow: () => void;
  handle: ReceiptThreadHandle;
};

function createReceiptCursor(enabled: boolean): ReceiptCursorState {
  const state: ReceiptCursorState = {
    enabled,
    token: undefined,
    inFlight: 0,
    overlapDirty: false,
    lastSkip: null,
    begin() {
      if (!enabled) return;
      if (state.inFlight > 0) state.overlapDirty = true;
      state.inFlight += 1;
    },
    end() {
      if (!enabled) return;
      state.inFlight -= 1;
      if (state.inFlight <= 0) {
        state.inFlight = 0;
        state.overlapDirty = false;
      }
    },
    considerOutcome(outcome: GuardOutcome<unknown>) {
      if (!enabled) return;
      if (state.overlapDirty) {
        state.lastSkip = 'concurrent_overlap';
        return;
      }
      if (!outcome || typeof outcome !== 'object' || outcome.enforced !== true) {
        state.lastSkip = 'not_enforced';
        return;
      }
      const token = (outcome.verdict as { envelope?: { receipt?: { token?: unknown } } } | undefined)
        ?.envelope?.receipt?.token;
      if (typeof token !== 'string' || token.trim().length === 0) {
        state.lastSkip = 'no_receipt_token';
        return;
      }
      state.token = token.trim();
      state.lastSkip = null;
    },
    considerThrow() {
      if (!enabled) return;
      if (state.overlapDirty) {
        state.lastSkip = 'concurrent_overlap';
        return;
      }
      state.lastSkip = 'threw_before_outcome';
    },
    handle: {
      enabled,
      lastToken: () => state.token,
      lastSkipReason: () => state.lastSkip,
    },
  };
  return state;
}

/**
 * Outermost wrap: count every execute() through the returned table (Half A).
 * Records before inner execute so BLOCK/throw still count as dispatched.
 * Observation only — does not change the inner result.
 */
function wrapForCoverageObserved(tool: ProtectedTool, observer: CoverageObserver): ProtectedTool {
  const innerExecute = tool.execute;
  const shell: ProtectedTool = {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    meta: tool.meta,
    _coderifts: tool._coderifts,
    execute: async (args: unknown) => {
      observer.recordGoverned(tool.name);
      return innerExecute(args);
    },
  };
  if (!Object.isFrozen(shell._coderifts)) Object.freeze(shell._coderifts);
  return Object.freeze(shell);
}

/**
 * Wrap a GUARDED tool so the composition can begin/end the cursor around the call and advance
 * from the GuardOutcome the frozen path returns. Does not change guardToolCall's signature.
 */
function wrapForReceiptCursor(tool: ProtectedTool, cursor: ReceiptCursorState): ProtectedTool {
  if (!tool._coderifts.guarded || !cursor.enabled) return tool;
  const innerExecute = tool.execute;
  const shell: ProtectedTool = {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    meta: tool.meta,
    _coderifts: tool._coderifts,
    execute: async (args: unknown) => {
      cursor.begin();
      try {
        const result = await innerExecute(args);
        // Guarded execute returns GuardOutcome (does not throw on BLOCK).
        cursor.considerOutcome(result as GuardOutcome<unknown>);
        return result;
      } catch (error) {
        cursor.considerThrow();
        throw error;
      } finally {
        cursor.end();
      }
    },
  };
  if (!Object.isFrozen(shell._coderifts)) Object.freeze(shell._coderifts);
  return Object.freeze(shell);
}

/**
 * Wrap guardToolRegistry with a mandatory operation and a separately-computed composition assurance.
 * Fails at CONSTRUCTION (never at first tool call) for a missing client, a missing/empty operation, an
 * invalid requireCoverage value, (S2) an unmet requireCoverage, or `profile: 'ENFORCING_STRICT'` plus a
 * conflicting opt-down / missing resolvePriorContent. Registry-thrown construction errors
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
  if (input.profile !== undefined && input.profile !== 'ENFORCING_STRICT') {
    problems.push(`\`profile\` must be 'ENFORCING_STRICT' when set (got ${JSON.stringify(input.profile)})`);
  }
  if (isEnforcingStrict(input)) {
    const weaken = enforcingStrictWeakenFlags(input);
    if (weaken.length > 0) {
      problems.push(`ENFORCING_STRICT cannot be weakened: ${weaken.join(', ')} conflicts`);
    }
    // requireFreshness=true is construction-detectable without a resolver → abort (not call-time FRESHNESS_REQUIRED).
    if (typeof input.resolvePriorContent !== 'function') {
      problems.push('ENFORCING_STRICT cannot be weakened: resolvePriorContent conflicts');
    }
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
  // Receipt cursor: per composition instance. Default ON (opt-out via threadReceipts:false).
  // Host previousReceipt always wins over the cursor at resolve time.
  const threadReceipts = input.threadReceipts !== false;
  const receiptCursor = createReceiptCursor(threadReceipts);
  const hostPreviousReceipt = input.previousReceipt;

  // Guard config: client + operation always; onEvent + monitoringSinkWired forwarded UNCHANGED when
  // provided (no second try/catch layer — frozen emit already swallows sync throws).
  const coverageObserver = createCoverageObserver();
  const guard: GuardConfig = { client: input.client, operation: input.operation, coverageObserver };
  if (input.onEvent !== undefined) {
    guard.onEvent = input.onEvent;
  }
  if (input.monitoringSinkWired !== undefined) {
    guard.monitoringSinkWired = input.monitoringSinkWired;
  }
  if (input.monitoringSink !== undefined) {
    guard.monitoringSink = input.monitoringSink;
  }
  if (input.monitoringSinkTimeoutMs !== undefined) {
    guard.monitoringSinkTimeoutMs = input.monitoringSinkTimeoutMs;
  }
  if (input.ackHmacKey !== undefined) {
    guard.ackHmacKey = input.ackHmacKey;
  }
  if (input.profile === 'ENFORCING_STRICT') {
    guard.profile = 'ENFORCING_STRICT';
  }
  // previousReceipt getter: host override > composition cursor > undefined.
  // Always install a getter when threading is on OR the host supplied an override, so the frozen
  // path reads current values per call without a guardToolCall signature change.
  if (hostPreviousReceipt !== undefined || threadReceipts) {
    guard.previousReceipt = () => {
      if (hostPreviousReceipt !== undefined) {
        return resolveHostPreviousReceipt(hostPreviousReceipt);
      }
      return receiptCursor.token;
    };
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
  if (input.requireConditionalWrite !== undefined) {
    guard.requireConditionalWrite = input.requireConditionalWrite;
  }
  if (input.requireExecutionStateMatch !== undefined) {
    guard.requireExecutionStateMatch = input.requireExecutionStateMatch;
  }
  if (input.requireCommitObservation !== undefined) {
    guard.requireCommitObservation = input.requireCommitObservation;
  }
  if (input.autoRecheck !== undefined) {
    guard.autoRecheck = input.autoRecheck;
  }
  if (input.autoDerive !== undefined) {
    guard.autoDerive = input.autoDerive;
  }
  if (input.executorAttestation !== undefined) {
    guard.executorAttestation = input.executorAttestation;
  }
  if (input.monitoringAttestation !== undefined) {
    guard.monitoringAttestation = input.monitoringAttestation;
  }
  if (input.systemPrompt !== undefined) {
    guard.systemPrompt = input.systemPrompt;
  }
  const strict = isEnforcingStrict(input);
  if (strict) {
    // Lock the fail-closed conjunction. Conflicts already aborted above — these are the STRICT values.
    guard.requireFreshness = true;
    guard.requireConditionalWrite = true;
    guard.requireExecutionStateMatch = true;
    guard.requireCommitObservation = true;
  }
  const config: GuardToolRegistryConfig = {
    guard,
    unknownToolPolicy: strict ? (reg.unknownToolPolicy === 'reject' ? 'reject' : 'mutating') : (reg.unknownToolPolicy ?? 'mutating'),
    classify: reg.classify,
    binders: reg.binders,
    forceReadonly: reg.forceReadonly,
    failOnUnguardedMutator: strict ? true : reg.failOnUnguardedMutator,
  };
  const requireCoverage = strict ? 'COMPLETE' : input.requireCoverage;

  // Registry-thrown construction errors (INVALID_TOOL, DUPLICATE_TOOL_NAME, UNKNOWN_TOOL,
  // FORCE_READONLY_MUTATOR, GUARD_CONFIG_INVALID) propagate UNCHANGED — never caught, wrapped, or
  // swallowed. That is the real contract: the composition does not re-guard what the registry
  // already fails closed on.
  const { tools, report } = guardToolRegistry(input.tools, config);
  coverageObserver.setTableNames(tools.map((t) => t.name));

  // S2 requireCoverage — abort if the REGISTRY-level coverage is weaker than required. This is not a
  // weakening-specific rule: BYPASSED (from a forced downgrade under failOnUnguardedMutator:false) is
  // simply weaker than COMPLETE by the ordering, so it fails here for the same reason PARTIAL does.
  if (requireCoverage !== undefined) {
    const requiredRank = coverageRank(requireCoverage); // validated non-undefined pre-registry
    const actualRank = coverageRank(report.coverage) ?? -1;   // fail-closed: unknown coverage = below any floor
    if (requiredRank !== undefined && actualRank < requiredRank) {
      throw new Error(
        `withCodeRifts: requireCoverage not met — registry coverage '${report.coverage}' is weaker than required '${requireCoverage}' `
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
  // requireConditionalWrite policy without a host reporting path: residual only (inescapable stays false).
  // Per-call truth is outcome.conditional_write; composition names the policy gap.
  if (input.requireConditionalWrite === true || strict) {
    residuals.push('composition_unconditional_write_under_policy');
  }
  if (strict) {
    residuals.push(RESIDUAL_CALLS_OUTSIDE_GUARDED_PATH);
  }

  // 'PARTIAL' from the existing EnforcementCoverage union — never 'COMPLETE' while inescapable_runtime
  // is false (that combination would contradict the registry's own formula). UNCHANGED by S2 / observation.
  // observed_class is LIVE (Half A/B) — not construction-time COMPLETE. Registry COMPLETE is table-truth.
  const composition_assurance: CompositionAssurance = {
    coverage: 'PARTIAL',
    inescapable_runtime: compositionInescapableRuntime,
    residuals: Object.freeze(residuals.slice()) as string[],
    freshness_resolver_wired,
    get observed_class() {
      return coverageObserver.snapshot().class;
    },
  };
  Object.freeze(composition_assurance);

  // Settled-call observation + receipt cursor: registry returns FROZEN ProtectedTool objects.
  // We build NEW shells (cannot reassign execute). Layering from inside out:
  //   registry guard → receipt cursor (GUARDED only) → onSettledCall observation (all routes)
  // begin() runs before preflight so concurrent overlap is visible to the cursor rule.
  let toolsOut: ProtectedTool[] = tools as ProtectedTool[];
  if (threadReceipts) {
    toolsOut = toolsOut.map((t) => wrapForReceiptCursor(t, receiptCursor));
  }
  if (input.onSettledCall) {
    const onSettledCall = input.onSettledCall;
    const bypassed = bypassedToolNames(report);
    toolsOut = Object.freeze(
      toolsOut.map((t) => wrapForSettledCallObservation(t, routeForTool(t, bypassed), onSettledCall)),
    ) as ProtectedTool[];
  } else if (threadReceipts) {
    toolsOut = Object.freeze(toolsOut) as ProtectedTool[];
  }

  toolsOut = Object.freeze(toolsOut.map((t) => wrapForCoverageObserved(t, coverageObserver))) as ProtectedTool[];

  const result: WithCodeRiftsResult = {
    tools: toolsOut,
    registry_report: report,
    composition_assurance,
    receipt_thread: receiptCursor.handle,
    coverage_observed: coverageObserver.handle,
  };
  if (input.repository !== undefined) result.repository = input.repository;
  return result;
}
