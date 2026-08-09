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
