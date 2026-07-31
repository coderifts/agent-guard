/**
 * withCodeRifts — additive orchestration layer above the frozen security core (slice S1).
 *
 * S1 DELIVERS: a single entry point that wraps the frozen `guardToolRegistry` with a MANDATORY
 * `operation` and returns, side by side, (a) the registry's own untouched coverage report and (b) a
 * separately-computed, deliberately-narrower composition-level assurance. It performs NO IO — every
 * input is host-supplied, exactly like the primitives it composes.
 *
 * S1 DELIBERATELY DOES NOT (later slices; not stubbed, not implied here): call-time policy, automatic
 * binders, receipt carry-forward, WARN monitoring, or framework adapters.
 *
 * THE TWO-SCOPE RULE (never merged):
 *   - `registry_report` is EXACTLY what `guardToolRegistry` returned, passed through untouched. It may
 *     legitimately state coverage 'COMPLETE' and claim.inescapable_runtime true — that is the runtime
 *     tool-boundary's own honest truth (Placement A).
 *   - `composition_assurance` is the narrower PRODUCT-level statement — what withCodeRifts as a whole
 *     is willing to claim today. It is computed SEPARATELY and never rewrites the registry's verdict.
 *     In S1 the composition's call-time policy is incomplete, so it reports coverage 'PARTIAL',
 *     inescapable_runtime false, and the residual 'composition_call_policy_incomplete'.
 * The two truths coexist; neither is derived by mutating the other.
 *
 * Operation semantics (accurate scope): `operationForClass` (tool-registry.ts) already derives a
 * per-tool operation from the tool's mutation class, OVERRIDING the guard config for specialised
 * classes (deploy→'deploy', publish→'publish', vcs-merge→'merge', …). The mandatory `operation` here
 * therefore governs generic mutating tools and acts as the session-level default; it does NOT override
 * a deploy-class tool's 'deploy'. It is mandatory because receipts bind to an operation and
 * merge != deploy: a silent default would risk evaluating a deploy under merge semantics.
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

/** Registry config fields callers may forward untouched (S1 does not re-default or re-declare them). */
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
  /** Product-level assurance — deliberately narrower than the registry in S1. */
  composition_assurance: CompositionAssurance;
  /** Carried through untouched from input when present (no resolution behaviour in S1). */
  repository?: string;
};

/**
 * Whether the composition's call-time policy is complete. FALSE in S1: automatic binders (S3) and
 * receipt carry-forward (S5) are not yet delivered, so the composition cannot claim runtime
 * inescapability. Later slices AND additional conjuncts into the composition invariant below rather
 * than replacing this one.
 */
const COMPOSITION_CALL_POLICY_COMPLETE = false; // becomes true only once S3 (binders) + S5 (receipt carry-forward) land

const RESIDUAL_CALL_POLICY_INCOMPLETE = 'composition_call_policy_incomplete';

/**
 * Wrap guardToolRegistry with a mandatory operation and a separately-computed composition assurance.
 * Fails at CONSTRUCTION (never at first tool call) for a missing client or a missing/empty operation.
 */
export function withCodeRifts(input: WithCodeRiftsInput): WithCodeRiftsResult {
  if (!input || typeof input !== 'object') {
    throw new Error('withCodeRifts: input object is required');
  }
  if (typeof input.operation !== 'string' || input.operation.trim() === '') {
    // Mandatory by design: receipts bind to an operation and merge != deploy — a silent default could
    // evaluate a deploy under merge semantics. No default is provided.
    throw new Error('withCodeRifts: `operation` is required and must be a non-empty string (receipts bind to an operation; merge != deploy, so there is no safe default)');
  }
  if (input.client == null) {
    throw new Error('withCodeRifts: `client` is required at construction (guardToolRegistry needs config.guard.client to wrap any mutating tool)');
  }

  const reg = input.registry ?? {};
  // Forward the registry passthrough fields AS GIVEN (no re-defaulting). operation is the session-level
  // default via config.guard.operation; specialised classes still override it in operationForClass.
  const config: GuardToolRegistryConfig = {
    guard: { client: input.client, operation: input.operation },
    unknownToolPolicy: reg.unknownToolPolicy,
    classify: reg.classify,
    binders: reg.binders,
    forceReadonly: reg.forceReadonly,
    failOnUnguardedMutator: reg.failOnUnguardedMutator,
  };

  const { tools, report } = guardToolRegistry(input.tools, config);

  // Composition invariant — a conjunction later slices EXTEND (add conjuncts), never replace. Because
  // COMPOSITION_CALL_POLICY_COMPLETE is false in S1, the result is deterministically false regardless
  // of the registry's own (possibly true) inescapable_runtime.
  const compositionInescapableRuntime =
    report.claim.inescapable_runtime && COMPOSITION_CALL_POLICY_COMPLETE;

  // 'PARTIAL' from the existing EnforcementCoverage union — never 'COMPLETE' while inescapable_runtime
  // is false (that combination would contradict the registry's own formula).
  const composition_assurance: CompositionAssurance = {
    coverage: 'PARTIAL',
    inescapable_runtime: compositionInescapableRuntime,
    residuals: [RESIDUAL_CALL_POLICY_INCOMPLETE],
  };

  const result: WithCodeRiftsResult = {
    tools,
    registry_report: report,
    composition_assurance,
  };
  if (input.repository !== undefined) result.repository = input.repository;
  return result;
}
