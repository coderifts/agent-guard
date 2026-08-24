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
 * Descriptor shape (dependency-free, StructuredTool-compatible for createReactAgent):
 *   { name, description, schema, func, invoke, lc_runnable: true }
 *   Measured against @langchain/langgraph createReactAgent tools:
 *     ToolNode | (StructuredToolInterface | DynamicTool | RunnableToolLike)[]
 *     (@langchain/langgraph@0.2.74 d.ts; current npm 1.4.12). Runtime isRunnable
 *     requires lc_runnable === true; ToolNode drops non-matching tools and the
 *     model sees "Tool not found" — NEVER return that silent shape.
 *   - schema  = JSON Schema from ProtectedTool.inputSchema (or empty object schema)
 *   - func / invoke = the GUARDED execute (same function reference) — never the raw tool
 *   - description always set (fallback to name) — StructuredToolInterface requires it
 * NO hard @langchain/* dependency: duck-type the measured surface. If a tool would
 * still fail that check, throw LangGraphToolsNotStructuredError (named, with the fix).
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
import type { CoverageObservedHandle } from '../coverage-observed.js';
import type { ProtectedTool, RegistryCoverageReport } from '../tool-registry.js';
import type { GuardOutcome } from '../types.js';
import { attachProofToAgentResponse } from '../final-answer-proof.js';
import {
  formatGateRefusalBody,
  formatGuardError,
  verdictKind,
} from '../gate-refusal.js';

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
  /** Always set (fallback to name). StructuredToolInterface requires description. */
  description: string;
  /** JSON Schema for tool args (LangChain `schema` / StructuredTool args). */
  schema: Record<string, unknown>;
  /**
   * Guarded execute — same as ProtectedTool.execute.
   * Pass to LangChain `tool(func, …)` or StructuredTool-style runners.
   */
  func: (args: unknown) => Promise<unknown>;
  /**
   * Alias of `func` for invoke-style APIs (StructuredTool.invoke / ToolNode).
   * Same guarded execute reference as `func`. Runnable.invoke also accepts a config arg.
   */
  invoke: (args: unknown, _config?: unknown) => Promise<unknown>;
  /**
   * Measured isRunnable / isStructuredTool check (@langchain/core).
   * Without this, createReactAgent's ToolNode drops the tool → model-visible "Tool not found".
   */
  lc_runnable: true;
};

/**
 * Named error — thrown instead of returning tools createReactAgent would silently drop.
 * Never a model-visible "Tool not found".
 */
export class LangGraphToolsNotStructuredError extends Error {
  constructor(message?: string) {
    super(
      message
      ?? 'withCodeRiftsLangGraph() tools are not StructuredTool-compatible for createReactAgent. '
        + 'createReactAgent (@langchain/langgraph) requires StructuredToolInterface | DynamicTool | '
        + 'RunnableToolLike (name, description, schema, invoke, lc_runnable). '
        + 'Fix: wrap with tool() from @langchain/core/tools — see README (LangChain / LangGraph).',
    );
    this.name = 'LangGraphToolsNotStructuredError';
  }
}

/**
 * True iff `t` matches the measured createReactAgent tool surface
 * (StructuredToolInterface | DynamicTool | RunnableToolLike).
 */
export function isLangGraphReactAgentTool(t: unknown): t is LangGraphToolDescriptor {
  if (!t || typeof t !== 'object') return false;
  const o = t as Record<string, unknown>;
  return typeof o.name === 'string' && o.name.length > 0
    && typeof o.description === 'string'
    && o.schema != null && typeof o.schema === 'object' && !Array.isArray(o.schema)
    && typeof o.invoke === 'function'
    && typeof o.func === 'function'
    && o.lc_runnable === true;
}

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
  /** Observed coverage for this withCodeRifts run. Half A always; Half B via reportToolDispatch. */
  coverage_observed: CoverageObservedHandle;
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
  const guarded = (args: unknown, _config?: unknown) =>
    Promise.resolve().then(() => tool.execute(args));

  const description = tool.description != null && tool.description !== ''
    ? tool.description
    : tool.name;

  const out: LangGraphToolDescriptor = {
    name: tool.name,
    description,
    schema,
    func: guarded,
    invoke: guarded,
    lc_runnable: true,
  };
  if (!isLangGraphReactAgentTool(out)) {
    throw new LangGraphToolsNotStructuredError(
      `protectedToolToLangGraph(${JSON.stringify(tool.name)}): tool is not createReactAgent-consumable. `
      + 'Fix: wrap with tool() from @langchain/core/tools — see README (LangChain / LangGraph).',
    );
  }
  return out;
}

/**
 * Convert a list of ProtectedTool into LangGraph/LangChain descriptors.
 * Does NOT call the guard — pure map over an already-protected list.
 */
export function toLangGraphTools(protectedTools: readonly ProtectedTool[]): LangGraphToolDescriptor[] {
  return bindLangGraphTools(protectedTools.map(protectedToolToLangGraph));
}

/**
 * Assert (and return) tools that createReactAgent can consume.
 * Throws LangGraphToolsNotStructuredError — never a silent "Tool not found".
 */
export function bindLangGraphTools(
  tools: readonly unknown[],
): LangGraphToolDescriptor[] {
  const out: LangGraphToolDescriptor[] = [];
  for (const t of tools) {
    if (!isLangGraphReactAgentTool(t)) {
      const n = t && typeof t === 'object' && 'name' in t ? String((t as { name?: unknown }).name) : '?';
      throw new LangGraphToolsNotStructuredError(
        `bindLangGraphTools: ${JSON.stringify(n)} is not StructuredTool-compatible for createReactAgent. `
        + 'Fix: wrap with tool() from @langchain/core/tools — see README (LangChain / LangGraph).',
      );
    }
    out.push(t);
  }
  return out;
}

/**
 * Build LangGraph/LangChain-ready guarded tool descriptors from raw tools + client + operation.
 *
 * Calls withCodeRifts internally (guard logic stays in the core). Returns:
 *   - `tools` — StructuredTool-compatible descriptors { name, description, schema, func, invoke, lc_runnable }
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
    coverage_observed: result.coverage_observed,
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
  /**
   * Attach the rendered GuardExecutionProof (S4). Default ON.
   * Pass `false` to opt out.
   */
  attachProof?: boolean;
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
    body = formatGateRefusalBody(outcome);
  } else {
    const err = 'error' in outcome ? outcome.error : undefined;
    const kind = verdictKind(outcome);
    body =
      `Tool execution failed after gate decision (verdict: ${kind}): ${formatGuardError(err)}`;
  }

  const content = args.attachProof === false
    ? body
    : attachProofToAgentResponse(body, outcome.proof) as string;
  const msg: LangGraphToolMessage = {
    content,
    tool_call_id,
  };
  if (args.name != null && args.name !== '') {
    msg.name = args.name;
  }
  return msg as ProofBoundLangGraphToolMessage;
}


