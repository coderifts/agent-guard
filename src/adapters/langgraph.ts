/**
 * LangChain / LangGraph tool adapter over withCodeRifts (ID632 slice 3 — same thin
 * pattern as OpenAI / Anthropic).
 *
 * Thin converter only. Guard logic stays in withCodeRifts; this module:
 *   1. calls withCodeRifts with the same input shape,
 *   2. maps each ProtectedTool → a framework-agnostic tool descriptor that
 *      LangChain's tool()/StructuredTool and LangGraph's ToolNode can accept,
 *   3. returns those descriptors PLUS the untouched assurance objects
 *      (registry_report, composition_assurance, receipt_thread).
 *
 * NO hard dependency on langchain / @langchain/* / langgraph packages. The host
 * owns the framework import and wires descriptors into tool() / ToolNode /
 * bind_tools / StateGraph themselves.
 *
 * Descriptor shape (dependency-free plain object):
 *   { name, description?, schema, func, invoke }
 *   - schema  = JSON Schema from ProtectedTool.inputSchema (or empty object schema)
 *   - func / invoke = the GUARDED execute (same function reference) — never the raw tool
 *
 * Honesty (do not "upgrade" assurance):
 *   - composition_assurance is passed through EXACTLY as the core reported it
 *     (COMPOSITION_CALL_POLICY_COMPLETE may still be false; inescapable_runtime may be false).
 *   - The adapter converts tool shape + binds guarded execute; it does not claim product-level
 *     inescapability the core does not claim.
 *
 * Only-protected-tools (6/D at the adapter surface):
 *   - `tools` is derived ONLY from the frozen registry's ProtectedTool list.
 *   - Raw tools never appear in the returned table. The host may still hold a raw
 *     reference outside this table; that boundary stays the host's responsibility.
 *
 * Ergonomics (5–10 lines): pass raw tools + client + operation → LangGraph-ready descriptors.
 * Mirrors src/adapters/openai.ts and anthropic.ts — only the target tool shape differs.
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
 * Framework-agnostic LangChain/LangGraph tool descriptor (no package import).
 *
 * Host wiring (illustrative — host supplies the framework packages, e.g.
 * @langchain/core tools + @langchain/langgraph ToolNode):
 *   const lcTools = tools.map((d) =>
 *     hostTool(d.func, { name: d.name, description: d.description, schema: d.schema }));
 *   // then hostToolNode(lcTools) / hostLlm.bindTools(lcTools)
 */
export type LangGraphToolDescriptor = {
  name: string;
  description?: string;
  /** JSON Schema for tool args (LangChain `schema` / StructuredTool args). */
  schema: Record<string, unknown>;
  /**
   * Guarded execute — same as ProtectedTool.execute.
   * Pass to LangChain `tool(func, …)` or StructuredTool-style runners.
   */
  func: (args: unknown) => Promise<unknown>;
  /**
   * Alias of `func` for invoke-style APIs (StructuredTool.invoke / ToolNode).
   * Same guarded execute reference as `func`.
   */
  invoke: (args: unknown) => Promise<unknown>;
};

/**
 * Result of withCodeRiftsLangGraph — descriptors + core assurance, unflattened.
 *
 * `tools` is the ONLY list intended for the model/runtime tool table. `protected_tools` is the
 * same guarded list for host inspection — never the raw tools.
 */
export type WithCodeRiftsLangGraphResult = {
  /** LangGraph/LangChain-compatible descriptors — only protected/guarded tools. */
  tools: LangGraphToolDescriptor[];
  /**
   * Guarded ProtectedTool list from withCodeRifts (same tools as `tools`).
   * Host may use these for dispatch; never raw tools.
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
const EMPTY_SCHEMA: Record<string, unknown> = Object.freeze({
  type: 'object',
  properties: {},
});

/**
 * Map one ProtectedTool → LangGraph/LangChain tool descriptor.
 * Binds guarded execute to both `func` and `invoke` (same reference).
 * Prefer tool.inputSchema when it is a plain object; otherwise empty object schema.
 */
export function protectedToolToLangGraph(tool: ProtectedTool): LangGraphToolDescriptor {
  const schema =
    tool.inputSchema != null
    && typeof tool.inputSchema === 'object'
    && !Array.isArray(tool.inputSchema)
      ? (tool.inputSchema as Record<string, unknown>)
      : { ...EMPTY_SCHEMA };

  // Guarded execute only — never a raw unwrapped executor.
  const guarded = (args: unknown) => Promise.resolve(tool.execute(args));

  const out: LangGraphToolDescriptor = {
    name: tool.name,
    schema,
    func: guarded,
    invoke: guarded,
  };
  if (tool.description != null && tool.description !== '') {
    out.description = tool.description;
  }
  return out;
}

/**
 * Convert a list of ProtectedTool into LangGraph/LangChain descriptors.
 * Does NOT call the guard — pure map over an already-protected list.
 */
export function toLangGraphTools(protectedTools: readonly ProtectedTool[]): LangGraphToolDescriptor[] {
  return protectedTools.map(protectedToolToLangGraph);
}

/**
 * Build LangGraph/LangChain-ready guarded tool descriptors from raw tools + client + operation.
 *
 * Calls withCodeRifts internally (guard logic stays in the core). Returns:
 *   - `tools` — plain descriptors { name, description?, schema, func, invoke }
 *   - `protected_tools` — same guarded tools
 *   - assurance objects from the core, passed through untouched
 *
 * @param input Same shape as withCodeRifts (WithCodeRiftsInput).
 */
export function withCodeRiftsLangGraph(input: WithCodeRiftsInput): WithCodeRiftsLangGraphResult {
  const core: WithCodeRiftsResult = withCodeRifts(input);
  return langGraphToolAdapter(core);
}

/**
 * Shape adapter over an existing WithCodeRiftsResult (composition style).
 * Prefer withCodeRiftsLangGraph when starting from raw tools.
 *
 * Does not re-run the guard; does not invent assurance.
 */
export function langGraphToolAdapter(result: WithCodeRiftsResult): WithCodeRiftsLangGraphResult {
  const protected_tools = result.tools;
  const tools = toLangGraphTools(protected_tools);
  const out: WithCodeRiftsLangGraphResult = {
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

// ── ID827 phase 2 — proof-binding helper (Option B; additive guard@6.1) ─────────────────────────

/**
 * Minimal LangChain ToolMessage-shaped plain object (no @langchain/* dependency).
 * Host may wrap into ToolMessage: new ToolMessage({ content, tool_call_id, name? }).
 * @see https://js.langchain.com/docs/concepts/messages
 */
export type LangGraphToolMessage = {
  content: string;
  tool_call_id: string;
  name?: string;
};

declare const __proofBoundLangGraphBrand: unique symbol;
export type ProofBoundLangGraphToolMessage = LangGraphToolMessage & {
  readonly __proofBound: typeof __proofBoundLangGraphBrand;
};

export type BindLangGraphGuardOutcomeArgs<T> = {
  /** LangChain/LangGraph tool_call_id this ToolMessage answers. */
  tool_call_id: string;
  /** Optional tool name (ToolMessage.name). */
  name?: string;
  serialize?: (result: T) => string;
};

export function defaultSerializeLangGraphToolResult<T>(result: T): string {
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
 * Map a full GuardOutcome into a LangGraph/LangChain ToolMessage shape with proof embedded.
 * Same arm mapping as bindOpenAIGuardOutcome; id field is tool_call_id.
 */
export function bindLangGraphGuardOutcome<T>(
  outcome: GuardOutcome<T>,
  args: BindLangGraphGuardOutcomeArgs<T>,
): ProofBoundLangGraphToolMessage {
  const tool_call_id = args.tool_call_id;
  const serialize = args.serialize ?? defaultSerializeLangGraphToolResult;

  let body: string;
  if (outcome.executed === true) {
    body = serialize(outcome.result);
  } else if (outcome.executionAttempted === false) {
    const kind = verdictKind(outcome);
    body =
      `CodeRifts gate did not permit execution (verdict: ${kind}). `
      + 'No tool result was produced.';
  } else {
    const err = 'error' in outcome ? outcome.error : undefined;
    const kind = verdictKind(outcome);
    body =
      `Tool execution failed after gate decision (verdict: ${kind}): ${formatGuardError(err)}`;
  }

  const content = attachProofToAgentResponse(body, outcome.proof) as string;
  const msg: LangGraphToolMessage = {
    content,
    tool_call_id,
  };
  if (args.name != null && args.name !== '') {
    msg.name = args.name;
  }
  return msg as ProofBoundLangGraphToolMessage;
}

function verdictKind(outcome: GuardOutcome<unknown>): string {
  return outcome.verdict && typeof outcome.verdict === 'object' && 'kind' in outcome.verdict
    ? String((outcome.verdict as { kind: string }).kind)
    : 'UNKNOWN';
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
