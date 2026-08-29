/**
 * Vercel AI SDK tool adapter over withCodeRifts (roadmap 129 / wave-2 —
 * same thin pattern as OpenAI / Anthropic / LangGraph / Gemini).
 *
 * Thin converter. Guard logic stays in withCodeRifts; this module:
 *   1. calls withCodeRifts with the same input shape,
 *   2. maps each ProtectedTool → a dependency-free Vercel `tool()` object,
 *   3. wraps `execute` so the guarded execute runs first, then bindVercelGuardOutcome,
 *   4. returns those tools PLUS the untouched assurance objects.
 *
 * Measured Vercel AI SDK v4 `tool()` (no `ai` package in this repo; types from
 * https://ai-sdk.dev/v4/docs/reference/ai-sdk-core/tool ):
 *
 *   import { tool } from 'ai';
 *   tool({
 *     description?: string,
 *     parameters: Zod Schema | JSON Schema,
 *     execute?: async (parameters: T, options: ToolExecutionOptions) => RESULT,
 *   })
 *   ToolExecutionOptions = { toolCallId: string, messages: CoreMessage[], abortSignal?: AbortSignal }
 *
 * generateText / streamText `tools` is a Record keyed by tool name (not an array).
 * This package does NOT depend on `ai` or `zod`. `parameters` is JSON Schema from
 * ProtectedTool.inputSchema (v4 accepts JSON Schema; hosts may wrap with `tool()` + Zod).
 *
 * Only-protected-tools (6/D at the adapter surface):
 *   - `tools` is derived ONLY from the frozen registry's ProtectedTool list.
 *   - Raw tools never appear in the returned table.
 *
 * Honesty (do not "upgrade" assurance): composition_assurance is passed through
 * EXACTLY as the core reported it.
 */

import { withCodeRifts } from '../with-coderifts.js';
import type {
  WithCodeRiftsInput,
  WithCodeRiftsResult,
  CompositionAssurance,
  ReceiptThreadHandle,
} from '../with-coderifts.js';
import type { CoverageObservedHandle } from '../coverage-observed.js';
import type { ProtectedTool, RegistryCoverageReport } from '../tool-registry.js';
import type { GuardOutcome, GuardVerdict } from '../types.js';
import { buildExecutionProof } from '../execution-proof.js';
import { attachProofToAgentResponse } from '../final-answer-proof.js';
import {
  formatGateRefusalBody,
  formatGuardError,
  verdictKind,
} from '../gate-refusal.js';

/**
 * Second argument of Vercel AI SDK v4 `execute` (ToolExecutionOptions).
 * @see https://ai-sdk.dev/v4/docs/ai-sdk-core/tools-and-tool-calling#tool-execution-options
 */
export type VercelToolExecutionOptions = {
  toolCallId: string;
  messages?: unknown[];
  abortSignal?: AbortSignal;
};

/**
 * Dependency-free Vercel `tool()` object (no `ai` import).
 * Name is the key in the generateText `tools` record, not a field on the object.
 * @see https://ai-sdk.dev/v4/docs/reference/ai-sdk-core/tool
 */
export type VercelTool = {
  description?: string;
  /** JSON Schema — v4 `parameters` accepts Zod Schema | JSON Schema. */
  parameters: Record<string, unknown>;
  /**
   * Guarded execute. Return is the Vercel RESULT (generateText puts it in ToolResultPart.result).
   * Mutators: proof-bound string from bindVercelGuardOutcome (never a nested part, never raw GuardOutcome).
   * Readonly passthrough may return the raw factory value.
   */
  execute: (
    args: unknown,
    options?: VercelToolExecutionOptions,
  ) => Promise<unknown>;
};

/**
 * Result of withCodeRiftsVercel — Vercel tool record + core assurance, unflattened.
 *
 * `tools` is the ONLY bag intended for generateText / streamText. `protected_tools`
 * is the same guarded list (with execute) for host dispatch — never the raw tools.
 */
export type WithCodeRiftsVercelResult = {
  /** generateText `tools` record — only protected/guarded tools, keyed by name. */
  tools: Record<string, VercelTool>;
  /**
   * Guarded ProtectedTool list from withCodeRifts (same tools as `tools`).
   * Host may dispatch through these; never raw tools.
   */
  protected_tools: ProtectedTool[];
  /** Untouched registry report — registry's own truth. */
  registry_report: RegistryCoverageReport;
  /**
   * Product-level assurance — deliberately narrower than the registry.
   * Passed through untouched; may still show inescapable_runtime:false and
   * residual composition_call_policy_incomplete.
   */
  composition_assurance: CompositionAssurance;
  /** Per-composition receipt cursor — NOT product-truth chain evidence. */
  receipt_thread: ReceiptThreadHandle;
  /** Observed coverage for this withCodeRifts run. Half A always; Half B via reportToolDispatch. */
  coverage_observed: CoverageObservedHandle;
  repository?: string;
};

/** Empty JSON Schema object — used when a ProtectedTool has no inputSchema. */
const EMPTY_PARAMETERS: Record<string, unknown> = Object.freeze({
  type: 'object',
  properties: {},
});

/**
 * Local GuardOutcome duck-type. Do not import execute-tool-call (that module
 * imports this binder — a cycle). Same fields as isGuardOutcome.
 */
function looksLikeGuardOutcome(x: unknown): x is GuardOutcome<unknown> {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return (
    typeof o.executed === 'boolean'
    && typeof o.executionAttempted === 'boolean'
    && o.proof != null
    && typeof o.proof === 'object'
    && o.verdict != null
    && typeof o.verdict === 'object'
  );
}

function toolCallIdFromOptions(options?: VercelToolExecutionOptions): string {
  if (options && typeof options.toolCallId === 'string') return options.toolCallId;
  return '';
}

const FRESHNESS_NOT_CONFIGURED = Object.freeze({
  wiring: 'NOT_CONFIGURED' as const,
  write_style: false,
  require_freshness: false,
});

const CW_NOT_REPORTED = Object.freeze({
  conditional_write: 'not_reported' as const,
  require_conditional_write: false,
  write_style: false,
  mutating: false,
});

/**
 * Guarded mutator returned a non-outcome — never forward the raw value to generateText.
 * Same CONFIG_ERROR / UNAVAILABLE arm as execute-tool-call unknownToolOutcome (no cycle).
 */
function guardedNonOutcomeRefusal(toolName: string): GuardOutcome<unknown> {
  const verdict: GuardVerdict = {
    kind: 'UNAVAILABLE',
    cause: 'CONFIG_ERROR',
    failPolicy: 'closed',
    resolution: 'CLOSED',
    action: 'STOP',
    decisionMissing: true,
    unavailableCount: 1,
  };
  const commit_observation = {
    status: 'not_observed' as const,
    observed_at: new Date().toISOString(),
    host_attestation: 'absent' as const,
  };
  const proof = buildExecutionProof({
    preflighted: false,
    executionAttempted: false,
    executed: false,
    enforced: false,
    verdict,
    commitObservation: commit_observation,
  });
  void toolName;
  return {
    executionAttempted: false,
    executed: false,
    enforced: false,
    verdict,
    preflighted: false,
    proof,
    freshness: FRESHNESS_NOT_CONFIGURED,
    conditional_write: CW_NOT_REPORTED,
    commit_observation,
  };
}

/**
 * Map one ProtectedTool → Vercel `tool()` object (description, parameters, execute).
 * Binds guarded execute; mutator GuardOutcome is mapped through bindVercelGuardOutcome.
 * Prefer tool.inputSchema when it is a plain object; otherwise empty object schema.
 */
export function protectedToolToVercel(tool: ProtectedTool): VercelTool {
  const parameters =
    tool.inputSchema != null
    && typeof tool.inputSchema === 'object'
    && !Array.isArray(tool.inputSchema)
      ? (tool.inputSchema as Record<string, unknown>)
      : { ...EMPTY_PARAMETERS };

  const execute = async (
    args: unknown,
    options?: VercelToolExecutionOptions,
  ): Promise<unknown> => {
    const raw = await Promise.resolve().then(() => tool.execute(args));
    const bindArgs = {
      toolCallId: toolCallIdFromOptions(options),
      toolName: tool.name,
    };
    // generateText treats execute's return as RESULT (the `result` field of a
    // tool-result part). Return the bound body, not the part — otherwise the
    // SDK nests { type:'tool-result', result: { type:'tool-result', ... } }.
    if (looksLikeGuardOutcome(raw)) {
      return bindVercelGuardOutcome(raw, bindArgs).result;
    }
    if (tool._coderifts && tool._coderifts.guarded) {
      return bindVercelGuardOutcome(guardedNonOutcomeRefusal(tool.name), bindArgs).result;
    }
    return raw;
  };

  const out: VercelTool = {
    parameters,
    execute,
  };
  if (tool.description != null && tool.description !== '') {
    out.description = tool.description;
  }
  return out;
}

/**
 * Convert a list of ProtectedTool into a Vercel generateText `tools` record.
 * Does NOT call the guard — map over an already-protected list.
 */
export function toVercelTools(
  protectedTools: readonly ProtectedTool[],
): Record<string, VercelTool> {
  const out: Record<string, VercelTool> = {};
  for (const t of protectedTools) {
    out[t.name] = protectedToolToVercel(t);
  }
  return out;
}

/**
 * Build Vercel-ready guarded tools from raw tools + client + operation.
 *
 * Calls withCodeRifts internally (guard logic stays in the core). Returns:
 *   - `tools` — generateText record { [name]: { description?, parameters, execute } }
 *   - `protected_tools` — same guarded tools
 *   - assurance objects from the core, passed through untouched
 *
 * @param input Same shape as withCodeRifts (WithCodeRiftsInput).
 */
export function withCodeRiftsVercel(input: WithCodeRiftsInput): WithCodeRiftsVercelResult {
  const core: WithCodeRiftsResult = withCodeRifts(input);
  return vercelToolAdapter(core);
}

/**
 * Shape adapter over an existing WithCodeRiftsResult (composition style).
 * Prefer withCodeRiftsVercel when starting from raw tools.
 *
 * Does not re-run the guard; does not invent assurance.
 */
export function vercelToolAdapter(result: WithCodeRiftsResult): WithCodeRiftsVercelResult {
  const protected_tools = result.tools;
  const tools = toVercelTools(protected_tools);
  const out: WithCodeRiftsVercelResult = {
    tools,
    protected_tools,
    registry_report: result.registry_report,
    composition_assurance: result.composition_assurance,
    receipt_thread: result.receipt_thread,
    coverage_observed: result.coverage_observed,
  };
  if (result.repository !== undefined) {
    out.repository = result.repository;
  }
  return out;
}

// ── Proof-binding helper (Option B; same arms as bindOpenAIGuardOutcome) ─────

/**
 * Minimal Vercel AI SDK v4 tool-result part. No `ai` dependency.
 * Id field is `toolCallId` (ToolExecutionOptions / ToolResultPart).
 * @see https://ai-sdk.dev/v4/docs/ai-sdk-core/tools-and-tool-calling
 */
export type VercelToolResult = {
  type: 'tool-result';
  toolCallId: string;
  toolName?: string;
  result: string;
};

declare const __proofBoundVercelBrand: unique symbol;
export type ProofBoundVercelToolResult = VercelToolResult & {
  readonly __proofBound: typeof __proofBoundVercelBrand;
};

export type BindVercelGuardOutcomeArgs<T> = {
  /** Vercel toolCallId this tool-result answers. */
  toolCallId: string;
  /** Optional tool name (ToolResultPart.toolName). */
  toolName?: string;
  serialize?: (result: T) => string;
  /**
   * Attach the rendered GuardExecutionProof (S4). Default ON.
   * Pass `false` to opt out.
   */
  attachProof?: boolean;
};

export function defaultSerializeVercelToolResult<T>(result: T): string {
  if (typeof result === 'string') return result;
  if (
    typeof result === 'number'
    || typeof result === 'boolean'
    || typeof result === 'bigint'
    || result === null
    || result === undefined
  ) {
    return String(result);
  }
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

/**
 * Map a full GuardOutcome into a Vercel tool-result part with proof embedded.
 * Same arm mapping as bindOpenAIGuardOutcome; id field is toolCallId.
 */
export function bindVercelGuardOutcome<T>(
  outcome: GuardOutcome<T>,
  args: BindVercelGuardOutcomeArgs<T>,
): ProofBoundVercelToolResult {
  const toolCallId = args.toolCallId;
  const serialize = args.serialize ?? defaultSerializeVercelToolResult;

  let body: string;
  if (outcome.executed === true) {
    body = serialize(outcome.result);
  } else if (outcome.executionAttempted === false) {
    body = formatGateRefusalBody(outcome);
  } else {
    const err = 'error' in outcome ? outcome.error : undefined;
    const kind = verdictKind(outcome);
    body =
      `Tool execution failed after gate decision (verdict: ${kind}): ${formatGuardError(err)}`;
  }

  const result = args.attachProof === false
    ? body
    : attachProofToAgentResponse(body, outcome.proof) as string;
  const part: VercelToolResult = {
    type: 'tool-result',
    toolCallId,
    result,
  };
  if (args.toolName != null && args.toolName !== '') {
    part.toolName = args.toolName;
  }
  return part as ProofBoundVercelToolResult;
}
