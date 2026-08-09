/**
 * Anthropic tool_use adapter over withCodeRifts (ID632 slice 2 — same thin pattern as OpenAI).
 *
 * Thin SHAPE converter only. Guard logic stays in withCodeRifts; this module:
 *   1. calls withCodeRifts with the same input shape,
 *   2. maps each ProtectedTool → Anthropic Messages API tool definition,
 *   3. returns Anthropic-shaped tools PLUS the untouched assurance objects
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
 *   - Raw tools never appear in the returned Anthropic table. The host may still hold a raw
 *     reference outside this table; that boundary stays the host's responsibility.
 *
 * Ergonomics (5–10 lines): pass raw tools + client + operation → Anthropic-ready guarded tools.
 * Mirrors src/adapters/openai.ts — only the target tool shape differs.
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
 * Anthropic Messages API `tools[]` element (tool_use definition).
 * @see https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/overview
 */
export type AnthropicTool = {
  name: string;
  description?: string;
  /** JSON Schema object for the tool input (Anthropic `input_schema`). */
  input_schema: Record<string, unknown>;
};

/**
 * Result of withCodeRiftsAnthropic — Anthropic tool definitions + core assurance, unflattened.
 *
 * `tools` is the ONLY list intended for the model/runtime tool table. `protected_tools` is the
 * same guarded list (with execute) for host dispatch after tool_use blocks — never the raw tools.
 */
export type WithCodeRiftsAnthropicResult = {
  /** Anthropic-shaped tools for messages.create — only protected/guarded tools. */
  tools: AnthropicTool[];
  /**
   * Guarded ProtectedTool list from withCodeRifts (same tools as `tools`, with execute).
   * Host dispatches model tool_use through these only. Never raw tools.
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
const EMPTY_INPUT_SCHEMA: Record<string, unknown> = Object.freeze({
  type: 'object',
  properties: {},
});

/**
 * Map one ProtectedTool → Anthropic tool definition (shape only; no execute).
 * Prefer tool.inputSchema when it is a plain object; otherwise empty object schema.
 */
export function protectedToolToAnthropic(tool: ProtectedTool): AnthropicTool {
  const input_schema =
    tool.inputSchema != null
    && typeof tool.inputSchema === 'object'
    && !Array.isArray(tool.inputSchema)
      ? (tool.inputSchema as Record<string, unknown>)
      : { ...EMPTY_INPUT_SCHEMA };

  const out: AnthropicTool = {
    name: tool.name,
    input_schema,
  };
  if (tool.description != null && tool.description !== '') {
    out.description = tool.description;
  }
  return out;
}

/**
 * Convert a list of ProtectedTool into Anthropic tool definitions.
 * Does NOT call the guard — pure shape map over an already-protected list.
 */
export function toAnthropicTools(protectedTools: readonly ProtectedTool[]): AnthropicTool[] {
  return protectedTools.map(protectedToolToAnthropic);
}

/**
 * Build Anthropic-ready guarded tools from raw tools + client + operation.
 *
 * Calls withCodeRifts internally (guard logic stays in the core). Returns:
 *   - `tools` — Anthropic messages API shape ({ name, description?, input_schema })
 *   - `protected_tools` — same guarded tools for host execute dispatch
 *   - assurance objects from the core, passed through untouched
 *
 * @param input Same shape as withCodeRifts (WithCodeRiftsInput).
 */
export function withCodeRiftsAnthropic(input: WithCodeRiftsInput): WithCodeRiftsAnthropicResult {
  const core: WithCodeRiftsResult = withCodeRifts(input);
  return anthropicToolAdapter(core);
}

/**
 * Shape-only adapter over an existing WithCodeRiftsResult (composition style).
 * Prefer withCodeRiftsAnthropic when starting from raw tools.
 *
 * Does not re-run the guard; does not invent assurance.
 */
export function anthropicToolAdapter(result: WithCodeRiftsResult): WithCodeRiftsAnthropicResult {
  const protected_tools = result.tools;
  const tools = toAnthropicTools(protected_tools);
  const out: WithCodeRiftsAnthropicResult = {
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
