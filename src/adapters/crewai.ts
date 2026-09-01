/**
 * CrewAI tool-result proof binder (I-1272).
 *
 * MEASURED SHAPE. CrewAI tools are Python (`crewai_tools.BaseTool`), and a tool's
 * `_run` return value is placed into the agent's context as the tool's observation.
 * The one structural control CrewAI gives a tool over that observation is
 * `result_as_answer`:
 *
 *   class MyTool(BaseTool):
 *       name: str = "..."
 *       result_as_answer: bool = True   # this tool's output IS the agent's final answer
 *
 * With `result_as_answer=True` the agent does not keep reasoning around the output —
 * it is returned as the answer.
 *
 * SOURCES (docs, no package imported — this repo is TypeScript and CrewAI is Python;
 * the host serialises this object into its tool's return, exactly as with every other
 * adapter here, which never import their framework either):
 *   - CrewAI "Create your own tools" / `BaseTool` — `_run` return, `result_as_answer`.
 *     https://docs.crewai.com/concepts/tools
 *   - CrewAI "Agents" — tool output handling and final-answer forcing.
 *     https://docs.crewai.com/concepts/agents
 *
 * WHY THAT FLAG IS THE MAPPING THAT MATTERS. A gate refusal is not an observation to
 * reason around; it is the end of that path. Setting `result_as_answer: true` on the
 * blocked arm is the CrewAI-native way of saying so, and it is the same statement the
 * other binders make by refusing to fabricate a result. An executed result is an
 * ordinary observation, so the flag is false there — the agent goes on working.
 *
 * INVARIANTS, identical to the four shipped binders:
 *   - PURE and non-mutating; no CrewAI dependency (a plain JSON-serialisable object).
 *   - Type-level ProofBound brand.
 *   - The blocked arm carries NO fabricated tool result — only the gate's own message.
 *   - `result` is byte-identical to what attachProofToAgentResponse produces for the
 *     same outcome, so this binder cannot drift from the others (asserted in tests).
 */

import type { GuardOutcome } from '../types.js';
import type { GuardExecutionProof } from '../execution-proof.js';
import { attachProofToAgentResponse } from '../final-answer-proof.js';
import {
  formatGateRefusalBody,
  formatGuardError,
  verdictKind,
} from '../gate-refusal.js';

/**
 * Minimal CrewAI tool result (no crewai dependency).
 *
 * Host wiring (Python side receives this as JSON):
 *   bound = bindCrewAIToolOutcome(outcome, { tool_name: 'apply_openapi' });
 *   # tool._run returns bound["result"]; the tool declares
 *   # result_as_answer = bound["result_as_answer"]
 */
export type CrewAIToolResult = {
  /** The observation string CrewAI places in the agent's context. */
  result: string;
  /**
   * True when this output IS the agent's final answer and must not be reasoned
   * around — every arm where the guard did not permit execution.
   */
  result_as_answer: boolean;
  /** The tool this result answers for. */
  tool_name: string;
  /**
   * Structured proof, alongside the string. CrewAI itself only reads `result`;
   * this rides for the host's audit path and is never required by the framework.
   */
  final_answer_proof: GuardExecutionProof;
};

declare const __proofBoundCrewAIBrand: unique symbol;
export type ProofBoundCrewAIToolResult = CrewAIToolResult & {
  readonly __proofBound: typeof __proofBoundCrewAIBrand;
};

export type BindCrewAIToolOutcomeArgs<T> = {
  /** CrewAI tool name this result answers for. */
  tool_name: string;
  serialize?: (result: T) => string;
  /**
   * Append the rendered GuardExecutionProof to `result` (S4). Default ON.
   * The structured `final_answer_proof` field is present either way.
   */
  attachProof?: boolean;
};

export function defaultSerializeCrewAIToolResult<T>(result: T): string {
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
 * Map a full GuardOutcome into a CrewAI tool result.
 *
 * Arm mapping is the shipped one (same as bindOpenAIGuardOutcome):
 *   executed          → serialized result, result_as_answer: false
 *   gate refusal      → formatGateRefusalBody, result_as_answer: TRUE, no fabricated result
 *   factory error     → the failure named with its verdict, result_as_answer: TRUE
 */
export function bindCrewAIToolOutcome<T>(
  outcome: GuardOutcome<T>,
  args: BindCrewAIToolOutcomeArgs<T>,
): ProofBoundCrewAIToolResult {
  const serialize = args.serialize ?? defaultSerializeCrewAIToolResult;

  let body: string;
  let resultAsAnswer: boolean;
  if (outcome.executed === true) {
    body = serialize(outcome.result);
    resultAsAnswer = false;
  } else if (outcome.executionAttempted === false) {
    body = formatGateRefusalBody(outcome);
    // The gate said no. There is nothing for the agent to reason around.
    resultAsAnswer = true;
  } else {
    const err = 'error' in outcome ? outcome.error : undefined;
    const kind = verdictKind(outcome);
    body = `Tool execution failed after gate decision (verdict: ${kind}): ${formatGuardError(err)}`;
    // The factory ran and threw: the agent must not invent a success from a failure.
    resultAsAnswer = true;
  }

  const result = args.attachProof === false
    ? body
    : attachProofToAgentResponse(body, outcome.proof) as string;

  const out: CrewAIToolResult = {
    result,
    result_as_answer: resultAsAnswer,
    tool_name: args.tool_name,
    final_answer_proof: outcome.proof,
  };
  return out as ProofBoundCrewAIToolResult;
}
