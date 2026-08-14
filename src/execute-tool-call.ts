/**
 * Option A safe dispatcher — per-framework execute wrappers that run a tool call
 * through the protected table AND always return a proof-bound framework message.
 *
 * Closes the manual-binder gap (audit D): hosts that use these faces cannot
 * forget bind*GuardOutcome — the return type is ONLY the ProofBound* brand.
 *
 * MECHANISM (measured, tool-registry.ts wrapWithGuard):
 *   ProtectedTool.execute for mutators returns guardToolCall(...) → GuardOutcome.
 *   No parallel guard path: the dispatcher only calls tool.execute on the table.
 *
 * REACHABILITY (do not overclaim):
 *   Same residual as GuardExecutionProof.limits.calls_outside_guarded_path_invisible
 *   and withCodeRifts composition honesty — calls outside the returned table remain
 *   invisible. This dispatcher only covers calls it is given against the table.
 *
 * BLOCK branch: binder no-result path (never fabricates a tool result) + measured
 * DecisionResultEnvelope fields surfaced when present (decision_id, decision,
 * execution_action, required_action, next_actions, breaking_changes). No invented
 * remediation (ID850 lives in the app, not here).
 */

import type { GuardOutcome, GuardVerdict, DecisionResultEnvelope } from './types.js';
import type { ProtectedTool } from './tool-registry.js';
import { buildExecutionProof } from './execution-proof.js';
import {
  bindOpenAIGuardOutcome,
  type BindOpenAIGuardOutcomeArgs,
  type ProofBoundOpenAIToolMessage,
} from './adapters/openai.js';
import {
  bindAnthropicGuardOutcome,
  type BindAnthropicGuardOutcomeArgs,
  type ProofBoundAnthropicToolResult,
} from './adapters/anthropic.js';
import {
  bindGeminiGuardOutcome,
  type BindGeminiGuardOutcomeArgs,
  type ProofBoundGeminiFunctionResponse,
} from './adapters/gemini.js';
import {
  bindLangGraphGuardOutcome,
  type BindLangGraphGuardOutcomeArgs,
  type ProofBoundLangGraphToolMessage,
} from './adapters/langgraph.js';

// ── Table input ──────────────────────────────────────────────────────────────

/**
 * Accepts a bare ProtectedTool[] or a withCodeRifts / withCodeRifts* result that
 * carries `tools` and/or `protected_tools`.
 */
export type ProtectedToolTableInput =
  | readonly ProtectedTool[]
  | { tools?: readonly ProtectedTool[]; protected_tools?: readonly ProtectedTool[] };

function resolveProtectedTools(table: ProtectedToolTableInput): readonly ProtectedTool[] {
  if (Array.isArray(table)) return table;
  if (table && typeof table === 'object') {
    const bag = table as {
      protected_tools?: readonly ProtectedTool[];
      tools?: readonly ProtectedTool[];
    };
    if (Array.isArray(bag.protected_tools) && bag.protected_tools.length > 0) {
      return bag.protected_tools;
    }
    if (Array.isArray(bag.tools)) {
      // withCodeRifts returns tools as ProtectedTool[]; OpenAI face also has tools as shape defs —
      // prefer protected_tools when both exist (OpenAI). When only tools, use if they have execute.
      const withExecute = bag.tools.filter(
        (t) => t && typeof t === 'object' && typeof t.execute === 'function',
      );
      if (withExecute.length > 0) return withExecute;
    }
  }
  return [];
}

function findTool(table: ProtectedToolTableInput, name: string): ProtectedTool | undefined {
  const tools = resolveProtectedTools(table);
  return tools.find((t) => t && t.name === name);
}

// ── GuardOutcome detection ───────────────────────────────────────────────────

/** Measured shape: every arm has executed + executionAttempted + proof + verdict. */
export function isGuardOutcome(x: unknown): x is GuardOutcome<unknown> {
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

// ── Synthetic outcomes (unknown tool / non-outcome execute returns) ──────────

const FRESHNESS_NOT_CONFIGURED = Object.freeze({
  wiring: 'NOT_CONFIGURED' as const,
  write_style: false,
  require_freshness: false,
});

const CW_NOT_REPORTED = Object.freeze({
  conditional_write: 'not_reported' as const,
  require_conditional_write: false,
  write_style: false,
});

/**
 * Unknown tool name — typed refusal via binder no-result path.
 * Uses CONFIG_ERROR integrity UNAVAILABLE (not a fabricated ALLOW).
 * Never throws so the host cannot catch-and-fall-back to raw.
 */
function unknownToolOutcome(toolName: string): GuardOutcome<unknown> {
  const verdict: GuardVerdict = {
    kind: 'UNAVAILABLE',
    cause: 'CONFIG_ERROR',
    failPolicy: 'closed',
    resolution: 'CLOSED',
    action: 'STOP',
    decisionMissing: true,
    unavailableCount: 1,
  };
  const proof = buildExecutionProof({
    preflighted: false,
    executionAttempted: false,
    executed: false,
    enforced: false,
    verdict,
  });
  // Annotate verdict for body text; proof already has verdict_kind.
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
  };
}

/**
 * Readonly / passthrough tools return raw values (not GuardOutcome).
 * Wrap as unenforced executed SKIPPED so binders still produce ProofBound*.
 */
function wrapRawAsOutcome(result: unknown): GuardOutcome<unknown> {
  const verdict: GuardVerdict = {
    kind: 'SKIPPED',
    reason: 'NOT_A_CONTRACT_CALL',
    signals: ['dispatcher_passthrough'],
    detectorVersion: 'execute-tool-call',
  };
  const proof = buildExecutionProof({
    preflighted: false,
    executionAttempted: true,
    executed: true,
    enforced: false,
    verdict,
    result,
  });
  return {
    executionAttempted: true,
    executed: true,
    enforced: false,
    result,
    verdict,
    preflighted: false,
    proof,
    freshness: FRESHNESS_NOT_CONFIGURED,
    conditional_write: CW_NOT_REPORTED,
  };
}

function wrapThrownAsOutcome(error: unknown): GuardOutcome<unknown> {
  const verdict: GuardVerdict = {
    kind: 'SKIPPED',
    reason: 'NOT_A_CONTRACT_CALL',
    signals: ['dispatcher_passthrough_throw'],
    detectorVersion: 'execute-tool-call',
  };
  const proof = buildExecutionProof({
    preflighted: false,
    executionAttempted: true,
    executed: false,
    enforced: false,
    verdict,
    error,
  });
  return {
    executionAttempted: true,
    executed: false,
    enforced: false,
    error,
    verdict,
    preflighted: false,
    proof,
    freshness: FRESHNESS_NOT_CONFIGURED,
    conditional_write: CW_NOT_REPORTED,
  };
}

// ── Core: execute through table → GuardOutcome ───────────────────────────────

/**
 * Locate tool by name on the protected table and invoke its execute.
 * Mutators return GuardOutcome (guardToolCall); unknown → typed refusal outcome.
 *
 * Does NOT claim reachability outside the table
 * (limits.calls_outside_guarded_path_invisible).
 */
export async function executeProtectedTool(
  table: ProtectedToolTableInput,
  toolName: string,
  args: unknown,
): Promise<GuardOutcome<unknown>> {
  const tool = findTool(table, toolName);
  if (!tool) {
    return unknownToolOutcome(toolName);
  }
  try {
    const raw = await tool.execute(args);
    if (isGuardOutcome(raw)) return raw;
    // Readonly passthrough: raw factory return, not a GuardOutcome.
    return wrapRawAsOutcome(raw);
  } catch (err) {
    // Guarded mutators absorb factory throws into GuardOutcome; passthrough may throw.
    return wrapThrownAsOutcome(err);
  }
}

// ── Measured envelope surface (BLOCK / no-execution path) ────────────────────

/**
 * Fields lifted only when present on DecisionResultEnvelope (producer schema).
 * required_action is DISPLAY ONLY per schema — never a control source / remediation enginge.
 * No invented remediation structures (ID850 is app-side).
 */
export type SurfacedEnvelopeFields = {
  decision_id?: string;
  decision?: string;
  execution_action?: string;
  required_action?: string | null;
  next_actions?: unknown;
  breaking_changes?: number | null;
};

export function surfaceEnvelopeFields(
  envelope: DecisionResultEnvelope | null | undefined,
): SurfacedEnvelopeFields | null {
  if (!envelope || typeof envelope !== 'object') return null;
  const e = envelope as unknown as Record<string, unknown>;
  const out: SurfacedEnvelopeFields = {};
  if (typeof e.decision_id === 'string') out.decision_id = e.decision_id;
  if (typeof e.decision === 'string') out.decision = e.decision;
  if (typeof e.execution_action === 'string') out.execution_action = e.execution_action;
  if ('required_action' in e) {
    out.required_action = e.required_action == null ? null : String(e.required_action);
  }
  if ('next_actions' in e) out.next_actions = e.next_actions;
  if ('breaking_changes' in e) {
    out.breaking_changes =
      typeof e.breaking_changes === 'number' ? e.breaking_changes : e.breaking_changes === null ? null : undefined;
    if (out.breaking_changes === undefined) delete out.breaking_changes;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function envelopeFromOutcome(outcome: GuardOutcome<unknown>): DecisionResultEnvelope | null {
  const v = outcome.verdict;
  if (v && typeof v === 'object' && 'envelope' in v && v.envelope && typeof v.envelope === 'object') {
    return v.envelope as DecisionResultEnvelope;
  }
  return null;
}

/** Append measured envelope surface to a string body (OpenAI/Anthropic/LangGraph). */
function appendEnvelopeSurface(body: string, outcome: GuardOutcome<unknown>): string {
  if (outcome.executionAttempted !== false) return body;
  const fields = surfaceEnvelopeFields(envelopeFromOutcome(outcome));
  if (!fields) return body;
  return (
    body
    + '\n\n[CodeRifts decision envelope — measured fields only; not a remediation engine]\n'
    + JSON.stringify(fields, null, 2)
  );
}

/** Merge measured envelope into Gemini response object (no fabricated result key). */
function mergeEnvelopeIntoGeminiResponse(
  response: Record<string, unknown>,
  outcome: GuardOutcome<unknown>,
): Record<string, unknown> {
  if (outcome.executionAttempted !== false) return response;
  const fields = surfaceEnvelopeFields(envelopeFromOutcome(outcome));
  if (!fields) return response;
  return { ...response, decision_envelope: fields };
}

// ── Framework faces (withCodeRiftsOpenAI naming: execute*ToolCall) ───────────

export type ExecuteOpenAIToolCallArgs = {
  /** Protected table or withCodeRifts / withCodeRiftsOpenAI result. */
  tools: ProtectedToolTableInput;
  /** Model tool_call_id this message answers. */
  tool_call_id: string;
  /** Function/tool name as returned by the model. */
  name: string;
  /** Tool arguments (object or JSON string). */
  arguments?: unknown;
  serialize?: BindOpenAIGuardOutcomeArgs<unknown>['serialize'];
};

/**
 * OpenAI face: protected table + one tool_call → ProofBoundOpenAIToolMessage only.
 * Return type is branded — host cannot type-check a forgotten-proof path.
 */
export async function executeOpenAIToolCall(
  args: ExecuteOpenAIToolCallArgs,
): Promise<ProofBoundOpenAIToolMessage> {
  const callArgs = parseMaybeJsonArgs(args.arguments);
  const outcome = await executeProtectedTool(args.tools, args.name, callArgs);
  const bound = bindOpenAIGuardOutcome(outcome, {
    tool_call_id: args.tool_call_id,
    serialize: args.serialize,
  });
  if (outcome.executionAttempted === false) {
    const content = appendEnvelopeSurface(bound.content, outcome);
    return { role: 'tool', tool_call_id: args.tool_call_id, content } as ProofBoundOpenAIToolMessage;
  }
  return bound;
}

export type ExecuteAnthropicToolCallArgs = {
  tools: ProtectedToolTableInput;
  tool_use_id: string;
  name: string;
  arguments?: unknown;
  serialize?: BindAnthropicGuardOutcomeArgs<unknown>['serialize'];
};

export async function executeAnthropicToolCall(
  args: ExecuteAnthropicToolCallArgs,
): Promise<ProofBoundAnthropicToolResult> {
  const callArgs = parseMaybeJsonArgs(args.arguments);
  const outcome = await executeProtectedTool(args.tools, args.name, callArgs);
  const bound = bindAnthropicGuardOutcome(outcome, {
    tool_use_id: args.tool_use_id,
    serialize: args.serialize,
  });
  if (outcome.executionAttempted === false) {
    const content = appendEnvelopeSurface(bound.content, outcome);
    return {
      type: 'tool_result',
      tool_use_id: args.tool_use_id,
      content,
    } as ProofBoundAnthropicToolResult;
  }
  return bound;
}

export type ExecuteGeminiToolCallArgs = {
  tools: ProtectedToolTableInput;
  /** Gemini function name (also used as BindGemini name). */
  name: string;
  arguments?: unknown;
  serialize?: BindGeminiGuardOutcomeArgs<unknown>['serialize'];
};

export async function executeGeminiToolCall(
  args: ExecuteGeminiToolCallArgs,
): Promise<ProofBoundGeminiFunctionResponse> {
  const callArgs = parseMaybeJsonArgs(args.arguments);
  const outcome = await executeProtectedTool(args.tools, args.name, callArgs);
  const bound = bindGeminiGuardOutcome(outcome, {
    name: args.name,
    serialize: args.serialize,
  });
  if (outcome.executionAttempted === false) {
    const response = mergeEnvelopeIntoGeminiResponse(
      { ...bound.functionResponse.response },
      outcome,
    );
    return {
      functionResponse: { name: args.name, response },
    } as ProofBoundGeminiFunctionResponse;
  }
  return bound;
}

export type ExecuteLangGraphToolCallArgs = {
  tools: ProtectedToolTableInput;
  tool_call_id: string;
  name: string;
  arguments?: unknown;
  serialize?: BindLangGraphGuardOutcomeArgs<unknown>['serialize'];
};

export async function executeLangGraphToolCall(
  args: ExecuteLangGraphToolCallArgs,
): Promise<ProofBoundLangGraphToolMessage> {
  const callArgs = parseMaybeJsonArgs(args.arguments);
  const outcome = await executeProtectedTool(args.tools, args.name, callArgs);
  const bound = bindLangGraphGuardOutcome(outcome, {
    tool_call_id: args.tool_call_id,
    name: args.name,
    serialize: args.serialize,
  });
  if (outcome.executionAttempted === false) {
    const content = appendEnvelopeSurface(bound.content, outcome);
    const msg: { content: string; tool_call_id: string; name?: string } = {
      content,
      tool_call_id: args.tool_call_id,
      name: args.name,
    };
    return msg as ProofBoundLangGraphToolMessage;
  }
  return bound;
}

// ── helpers ──────────────────────────────────────────────────────────────────

function parseMaybeJsonArgs(args: unknown): unknown {
  if (typeof args === 'string') {
    const s = args.trim();
    if (s.length === 0) return {};
    try {
      return JSON.parse(s);
    } catch {
      return { _raw: args };
    }
  }
  return args === undefined ? {} : args;
}
