/**
 * OpenAI tool-calling adapter over withCodeRifts (ID632 slice 1 — reference adapter).
 *
 * Thin SHAPE converter only. Guard logic stays in withCodeRifts; this module:
 *   1. calls withCodeRifts with the same input shape,
 *   2. maps each ProtectedTool → OpenAI chat.completions tool definition,
 *   3. returns OpenAI-shaped tools PLUS the untouched assurance objects
 *      (registry_report, composition_assurance, receipt_thread).
 *
 * Honesty (do not "upgrade" assurance):
 *   - composition_assurance is passed through EXACTLY as the core reported it
 *     (COMPOSITION_CALL_POLICY_COMPLETE may still be false; inescapable_runtime may be false).
 *   - The adapter converts tool SHAPE for the model API; it does not claim product-level
 *     inescapability the core does not claim.
 *
 * Only-protected-tools (6/D at the adapter surface):
 *   - `tools` is derived ONLY from the frozen registry's ProtectedTool list.
 *   - Raw tools never appear in the returned OpenAI table. The host may still hold a raw
 *     reference outside this table; that boundary stays the host's responsibility.
 *
 * Ergonomics (5–10 lines): pass raw tools + client + operation → OpenAI-ready guarded tools.
 * LangGraph / Anthropic adapters follow the same thin-converter pattern later.
 */

import { withCodeRifts } from '../with-coderifts.js';
import type {
  WithCodeRiftsInput,
  WithCodeRiftsResult,
  CompositionAssurance,
  ReceiptThreadHandle,
} from '../with-coderifts.js';
import type { ProtectedTool, RegistryCoverageReport } from '../tool-registry.js';
import type { GuardOutcome } from '../types.js';
import { attachProofToAgentResponse } from '../final-answer-proof.js';

/**
 * OpenAI chat.completions `tools[]` element (function tool).
 * @see https://platform.openai.com/docs/guides/function-calling
 */
export type OpenAIFunctionTool = {
  type: 'function';
  function: {
    name: string;
    description?: string;
    /** JSON Schema object for the function arguments (OpenAI `parameters`). */
    parameters: Record<string, unknown>;
  };
};

/**
 * Result of withCodeRiftsOpenAI — OpenAI tool definitions + core assurance, unflattened.
 *
 * `tools` is the ONLY list intended for the model/runtime tool table. `protected_tools` is the
 * same guarded list (with execute) for host dispatch after tool_calls — never the raw tools.
 */
export type WithCodeRiftsOpenAIResult = {
  /** OpenAI-shaped tools for chat.completions — only protected/guarded tools. */
  tools: OpenAIFunctionTool[];
  /**
   * Guarded ProtectedTool list from withCodeRifts (same tools as `tools`, with execute).
   * Host dispatches model tool_calls through these only. Never raw tools.
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
  repository?: string;
};

/** Empty JSON Schema object — used when a ProtectedTool has no inputSchema. */
const EMPTY_PARAMETERS: Record<string, unknown> = Object.freeze({
  type: 'object',
  properties: {},
});

/**
 * Map one ProtectedTool → OpenAI function tool definition (shape only; no execute).
 * Prefer tool.inputSchema when it is a plain object; otherwise empty object schema.
 */
export function protectedToolToOpenAI(tool: ProtectedTool): OpenAIFunctionTool {
  const parameters =
    tool.inputSchema != null
    && typeof tool.inputSchema === 'object'
    && !Array.isArray(tool.inputSchema)
      ? (tool.inputSchema as Record<string, unknown>)
      : { ...EMPTY_PARAMETERS };

  const fn: OpenAIFunctionTool['function'] = {
    name: tool.name,
    parameters,
  };
  if (tool.description != null && tool.description !== '') {
    fn.description = tool.description;
  }
  return { type: 'function', function: fn };
}

/**
 * Convert a list of ProtectedTool into OpenAI tool definitions.
 * Does NOT call the guard — pure shape map over an already-protected list.
 */
export function toOpenAITools(protectedTools: readonly ProtectedTool[]): OpenAIFunctionTool[] {
  return protectedTools.map(protectedToolToOpenAI);
}

/**
 * Build OpenAI-ready guarded tools from raw tools + client + operation.
 *
 * Calls withCodeRifts internally (guard logic stays in the core). Returns:
 *   - `tools` — OpenAI chat.completions shape (function tools only)
 *   - `protected_tools` — same guarded tools for host execute dispatch
 *   - assurance objects from the core, passed through untouched
 *
 * @param input Same shape as withCodeRifts (WithCodeRiftsInput).
 */
export function withCodeRiftsOpenAI(input: WithCodeRiftsInput): WithCodeRiftsOpenAIResult {
  const core: WithCodeRiftsResult = withCodeRifts(input);
  return openAIToolAdapter(core);
}

/**
 * Shape-only adapter over an existing WithCodeRiftsResult (composition style).
 * Prefer withCodeRiftsOpenAI when starting from raw tools.
 *
 * Does not re-run the guard; does not invent assurance.
 */
export function openAIToolAdapter(result: WithCodeRiftsResult): WithCodeRiftsOpenAIResult {
  const protected_tools = result.tools;
  const tools = toOpenAITools(protected_tools);
  const out: WithCodeRiftsOpenAIResult = {
    tools,
    protected_tools,
    registry_report: result.registry_report,
    composition_assurance: result.composition_assurance,
    receipt_thread: result.receipt_thread,
  };
  if (result.repository !== undefined) {
    out.repository = result.repository;
  }
  return out;
}

// ── ID827 phase 1 — proof-binding helper (Option B; additive guard@6.1) ─────────────────────────

/**
 * Minimal OpenAI chat tool-message (role tool). No openai SDK dependency.
 * @see https://platform.openai.com/docs/guides/function-calling
 */
export type OpenAIToolMessage = {
  role: 'tool';
  tool_call_id: string;
  content: string;
};

/**
 * Brand for proof-bound OpenAI tool messages (compile-time detection of proof-forgotten paths).
 * Type-level only — same pattern as ReceiptVerifiedEnvelope; not a runtime wire field.
 */
declare const __proofBoundBrand: unique symbol;
export type ProofBoundOpenAIToolMessage = OpenAIToolMessage & {
  readonly __proofBound: typeof __proofBoundBrand;
};

export type BindOpenAIGuardOutcomeArgs<T> = {
  /** OpenAI tool_call_id this message answers. */
  tool_call_id: string;
  /** Override result serialization (default: JSON.stringify objects, String() primitives). */
  serialize?: (result: T) => string;
  /**
   * Attach the rendered GuardExecutionProof to the tool message (S4).
   * Default ON. Pass `false` to opt out — host then owns the proof surface.
   */
  attachProof?: boolean;
};

/**
 * Default result → content body serializer (pure).
 * Objects/arrays → JSON.stringify; strings unchanged; other primitives → String().
 */
export function defaultSerializeOpenAIToolResult<T>(result: T): string {
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
 * Map a full GuardOutcome into an OpenAI tool message with the execution proof embedded.
 *
 * Option B (proof-binding helper): host still calls guardToolCall; this only binds
 * outcome → framework tool-result. Pure and non-mutating. Always embeds outcome.proof
 * (present on every arm) via attachProofToAgentResponse / renderFinalAnswerProof —
 * does not reinvent proof formatting.
 *
 * Arms:
 *  - executed (result): serialized result + rendered proof
 *  - blocked before factory: gate-denied text (no fabricated result) + proof
 *  - factory threw: error indication + proof
 */
export function bindOpenAIGuardOutcome<T>(
  outcome: GuardOutcome<T>,
  args: BindOpenAIGuardOutcomeArgs<T>,
): ProofBoundOpenAIToolMessage {
  const tool_call_id = args.tool_call_id;
  const serialize = args.serialize ?? defaultSerializeOpenAIToolResult;

  let body: string;
  if (outcome.executed === true) {
    // Executed arms (enforced or not): result is present.
    body = serialize(outcome.result);
  } else if (outcome.executionAttempted === false) {
    // Blocked before factory — no result; never fabricate one.
    const kind = outcome.verdict && typeof outcome.verdict === 'object' && 'kind' in outcome.verdict
      ? String((outcome.verdict as { kind: string }).kind)
      : 'UNKNOWN';
    body =
      `CodeRifts gate did not permit execution (verdict: ${kind}). `
      + 'No tool result was produced.';
  } else {
    // executionAttempted && !executed → factory threw; error is present.
    const err = 'error' in outcome ? outcome.error : undefined;
    const errText = formatGuardError(err);
    const kind = outcome.verdict && typeof outcome.verdict === 'object' && 'kind' in outcome.verdict
      ? String((outcome.verdict as { kind: string }).kind)
      : 'UNKNOWN';
    body =
      `Tool execution failed after gate decision (verdict: ${kind}): ${errText}`;
  }

  // Default ON (S4). attachProof:false is the explicit opt-out.
  const content = args.attachProof === false
    ? body
    : attachProofToAgentResponse(body, outcome.proof) as string;

  // Type brand only (no extra wire keys — OpenAI tool messages stay {role, tool_call_id, content}).
  const msg: OpenAIToolMessage = {
    role: 'tool',
    tool_call_id,
    content,
  };
  return msg as ProofBoundOpenAIToolMessage;
}

function formatGuardError(err: unknown): string {
  if (err instanceof Error) return err.message || err.name || 'Error';
  if (typeof err === 'string') return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
