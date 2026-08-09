/**
 * Google Gemini function-calling adapter over withCodeRifts (ID632 slice 4 —
 * same thin pattern as OpenAI / Anthropic / LangGraph).
 *
 * Thin SHAPE converter only. Guard logic stays in withCodeRifts; this module:
 *   1. calls withCodeRifts with the same input shape,
 *   2. maps ProtectedTool[] → Gemini generateContent tools shape,
 *   3. returns Gemini-shaped tools PLUS the untouched assurance objects
 *      (registry_report, composition_assurance, receipt_thread).
 *
 * Gemini nesting (differs from OpenAI):
 *   tools: [ { functionDeclarations: [ { name, description?, parameters }, … ] } ]
 * One tools entry wraps ALL declarations in a single functionDeclarations array —
 * not one { type: 'function' } object per tool.
 *
 * Honesty (do not "upgrade" assurance):
 *   - composition_assurance is passed through EXACTLY as the core reported it
 *     (COMPOSITION_CALL_POLICY_COMPLETE may still be false; inescapable_runtime may be false).
 *   - The adapter converts tool SHAPE for the model API; it does not claim product-level
 *     inescapability the core does not claim.
 *
 * Only-protected-tools (6/D at the adapter surface):
 *   - `tools` is derived ONLY from the frozen registry's ProtectedTool list.
 *   - Raw tools never appear in the returned Gemini table. The host may still hold a raw
 *     reference outside this table; that boundary stays the host's responsibility.
 *
 * Ergonomics (5–10 lines): pass raw tools + client + operation → Gemini-ready tools.
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
 * One Gemini function declaration (inside functionDeclarations[]).
 * @see https://ai.google.dev/gemini-api/docs/function-calling
 */
export type GeminiFunctionDeclaration = {
  name: string;
  description?: string;
  /**
   * OpenAPI-like JSON Schema for function parameters
   * (Gemini `parameters` — from ProtectedTool.inputSchema).
   */
  parameters: Record<string, unknown>;
};

/**
 * Gemini `tools[]` element: a single wrapper holding all functionDeclarations.
 * Unlike OpenAI (one {type:'function'} per tool), Gemini nests every declaration
 * under one functionDeclarations array.
 */
export type GeminiTool = {
  functionDeclarations: GeminiFunctionDeclaration[];
};

/**
 * Result of withCodeRiftsGemini — Gemini tool definitions + core assurance, unflattened.
 *
 * `tools` is typically a one-element array:
 *   [ { functionDeclarations: [ …all protected tools… ] } ]
 * `protected_tools` is the same guarded list (with execute) for host dispatch after functionCall.
 */
export type WithCodeRiftsGeminiResult = {
  /**
   * Gemini generateContent `tools` array — only protected/guarded tools, nested under
   * functionDeclarations (usually length 1 wrapper).
   */
  tools: GeminiTool[];
  /**
   * Guarded ProtectedTool list from withCodeRifts.
   * Host dispatches model functionCall through these only. Never raw tools.
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

/** Empty OpenAPI-like JSON Schema — used when a ProtectedTool has no inputSchema. */
const EMPTY_PARAMETERS: Record<string, unknown> = Object.freeze({
  type: 'object',
  properties: {},
});

/**
 * Map one ProtectedTool → Gemini functionDeclaration (shape only; no execute).
 * Prefer tool.inputSchema when it is a plain object; otherwise empty object schema.
 */
export function protectedToolToFunctionDeclaration(tool: ProtectedTool): GeminiFunctionDeclaration {
  const parameters =
    tool.inputSchema != null
    && typeof tool.inputSchema === 'object'
    && !Array.isArray(tool.inputSchema)
      ? (tool.inputSchema as Record<string, unknown>)
      : { ...EMPTY_PARAMETERS };

  const out: GeminiFunctionDeclaration = {
    name: tool.name,
    parameters,
  };
  if (tool.description != null && tool.description !== '') {
    out.description = tool.description;
  }
  return out;
}

/**
 * Convert ProtectedTool[] into Gemini `tools` array:
 *   [ { functionDeclarations: [ … ] } ]
 *
 * Empty protected list → empty tools array (no empty wrapper).
 * Does NOT call the guard — pure shape map over an already-protected list.
 */
export function toGeminiTools(protectedTools: readonly ProtectedTool[]): GeminiTool[] {
  if (protectedTools.length === 0) return [];
  return [{
    functionDeclarations: protectedTools.map(protectedToolToFunctionDeclaration),
  }];
}

/**
 * Build Gemini-ready guarded tools from raw tools + client + operation.
 *
 * Calls withCodeRifts internally (guard logic stays in the core). Returns:
 *   - `tools` — Gemini shape [ { functionDeclarations: […] } ]
 *   - `protected_tools` — same guarded tools for host execute dispatch
 *   - assurance objects from the core, passed through untouched
 *
 * @param input Same shape as withCodeRifts (WithCodeRiftsInput).
 */
export function withCodeRiftsGemini(input: WithCodeRiftsInput): WithCodeRiftsGeminiResult {
  const core: WithCodeRiftsResult = withCodeRifts(input);
  return geminiToolAdapter(core);
}

/**
 * Shape-only adapter over an existing WithCodeRiftsResult (composition style).
 * Prefer withCodeRiftsGemini when starting from raw tools.
 *
 * Does not re-run the guard; does not invent assurance.
 */
export function geminiToolAdapter(result: WithCodeRiftsResult): WithCodeRiftsGeminiResult {
  const protected_tools = result.tools;
  const tools = toGeminiTools(protected_tools);
  const out: WithCodeRiftsGeminiResult = {
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
