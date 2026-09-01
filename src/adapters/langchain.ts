/**
 * LangChain `content_and_artifact` proof binder (I-1272).
 *
 * WHY THIS IS NOT bindLangGraphGuardOutcome. That binder answers a ToolMessage:
 * everything it carries — refusal body AND rendered proof — is a string that lands
 * in the model's context. LangChain has a second, documented return contract for
 * exactly the case where part of a tool's output should NOT reach the model:
 *
 *   const t = tool(fn, { name, schema, responseFormat: 'content_and_artifact' });
 *   // fn returns the tuple [content, artifact]
 *   // → ToolMessage { content, artifact }: `content` goes to the model,
 *   //   `artifact` is preserved on the message and stays out of the prompt.
 *
 * MEASURED SOURCES (docs + types, no package imported):
 *   - LangChain JS "How to return artifacts from a tool" — `responseFormat:
 *     "content_and_artifact"`, tool returns `[content, artifact]`.
 *     https://js.langchain.com/docs/how_to/tool_artifacts/
 *   - `ToolMessage` fields `content` / `artifact` / `tool_call_id` / `name`
 *     (@langchain/core `messages/tool`).
 *     https://js.langchain.com/docs/concepts/messages/
 *
 * A GuardExecutionProof is precisely an artifact: a downstream auditor wants every
 * field of it, and a model wants none of them. Putting the structured proof in
 * `artifact` keeps it verifiable without spending context on it.
 *
 * INVARIANTS, identical to the four shipped binders:
 *   - PURE and non-mutating; no @langchain/* dependency (minimal local types only).
 *   - Type-level ProofBound brand, so the compiler can tell a bound result from a raw one.
 *   - The blocked arm carries NO fabricated tool result — only the gate's own message.
 *   - `content` is byte-identical to what attachProofToAgentResponse produces for the
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
 * Minimal LangChain content-and-artifact tool output (no @langchain/* dependency).
 *
 * Host wiring:
 *   const bound = bindLangChainToolOutcome(outcome, { tool_call_id });
 *   return [bound.content, bound.artifact];        // inside a content_and_artifact tool
 *   // or: new ToolMessage({ ...bound })
 */
export type LangChainToolOutput = {
  /** Goes to the model. */
  content: string;
  /** Preserved on the ToolMessage, kept OUT of the model's context. */
  artifact: LangChainToolArtifact;
  tool_call_id: string;
  name?: string;
};

/** What rides in `artifact`. Structured on purpose — an auditor reads this, not a model. */
export type LangChainToolArtifact = {
  /** Guard-defined provenance marker, same idiom as proof_spec / view_spec. */
  artifact_spec: 'coderifts-guard-artifact.v1';
  /** The full proof object, untouched. */
  final_answer_proof: GuardExecutionProof;
  /** Whether the guarded factory ran. Mirrors outcome.executed; never re-derived. */
  executed: boolean;
  /** Whether this run was enforcing. Mirrors outcome.enforced. */
  enforced: boolean;
  /** Verdict kind (ALLOW / MONITOR / BLOCK / APPROVAL / SKIPPED / UNAVAILABLE). */
  verdict: string;
};

declare const __proofBoundLangChainBrand: unique symbol;
export type ProofBoundLangChainToolOutput = LangChainToolOutput & {
  readonly __proofBound: typeof __proofBoundLangChainBrand;
};

export type BindLangChainToolOutcomeArgs<T> = {
  /** The tool_call_id this output answers. */
  tool_call_id: string;
  /** Optional tool name (ToolMessage.name). */
  name?: string;
  serialize?: (result: T) => string;
  /**
   * Append the RENDERED proof text to `content` (S4). Default ON, matching every
   * other binder. `false` leaves `content` as the bare body — the artifact still
   * carries the structured proof, which is the reason to opt out.
   */
  attachProof?: boolean;
};

export function defaultSerializeLangChainToolResult<T>(result: T): string {
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

export const LANGCHAIN_ARTIFACT_SPEC = 'coderifts-guard-artifact.v1' as const;

/**
 * Map a full GuardOutcome into a LangChain content_and_artifact tool output.
 *
 * Arm mapping is the shipped one (same as bindOpenAIGuardOutcome):
 *   executed          → serialized result
 *   gate refusal      → formatGateRefusalBody, NO fabricated result
 *   factory error     → the failure, named, with the verdict that preceded it
 */
export function bindLangChainToolOutcome<T>(
  outcome: GuardOutcome<T>,
  args: BindLangChainToolOutcomeArgs<T>,
): ProofBoundLangChainToolOutput {
  const serialize = args.serialize ?? defaultSerializeLangChainToolResult;

  let body: string;
  if (outcome.executed === true) {
    body = serialize(outcome.result);
  } else if (outcome.executionAttempted === false) {
    body = formatGateRefusalBody(outcome);
  } else {
    const err = 'error' in outcome ? outcome.error : undefined;
    const kind = verdictKind(outcome);
    body = `Tool execution failed after gate decision (verdict: ${kind}): ${formatGuardError(err)}`;
  }

  const content = args.attachProof === false
    ? body
    : attachProofToAgentResponse(body, outcome.proof) as string;

  const out: LangChainToolOutput = {
    content,
    artifact: {
      artifact_spec: LANGCHAIN_ARTIFACT_SPEC,
      final_answer_proof: outcome.proof,
      executed: outcome.executed === true,
      enforced: outcome.enforced === true,
      verdict: verdictKind(outcome),
    },
    tool_call_id: args.tool_call_id,
  };
  if (args.name != null && args.name !== '') {
    out.name = args.name;
  }
  return out as ProofBoundLangChainToolOutput;
}
