/**
 * CodeRifts agent-host policy text.
 *
 * Vendored from coderifts-app `src/agent-host-rule.js` `getCanonicalRuleText()`.
 * Drift-gated by `test/policy-vendored-sync.test.js` (byte-equal to the app
 * canonical text; missing app checkout fails loud — never skip).
 *
 * This proves the TEXT is present when injected/detected, not that the model
 * read or obeyed it.
 */

/** Phrase present in ALL six generated host formats (AGENTS.md, CLAUDE.md, cursor rules, Copilot instructions, LangGraph policy, OpenAI agent instructions). */
export const POLICY_MARKER =
  "A receipt authorizes ONE operation: a merge receipt does not authorize a deploy.";

/** Canonical policy body (paragraphs joined by blank lines). */
export const CODERIFTS_POLICY: string = "Call `preflight_change_set` before merge, deploy, publish, or tool registration when a contract artifact changed (OpenAPI/Swagger, GraphQL, gRPC/protobuf, AsyncAPI, MCP manifest, or agent tool schemas).\n\nSend the complete base-to-head change set: every changed contract artifact with full before and after content. Do not send a single-file subset when other contract files also change.\n\nBranch on `execution_action` only. Do not branch on `decision` and do not branch on `safe_for_agent` (not_for_control_flow_use_execution_action). Canonical `execution_action` values: CONTINUE, CONTINUE_WITH_MONITORING, REQUEST_APPROVAL, STOP.\n\nAn unrecognised `execution_action` is not permission: fail closed (halt or re-preflight). Well-known code: `not_permission_fail_closed`.\n\n`CONTINUE_WITH_MONITORING` requires a wired monitoring sink (`monitoringSinkWired`). It is not \"proceed with caution\" without monitoring.\n\nDo not call CodeRifts tools for a documentation-only change (README, guides, comments) with no contract artifact content change.\n\nIf you already hold a chain receipt and only need authenticity/lifecycle: `verify_receipt`. If you need a past decision by id: `get_decision_details`. Neither replaces preflight for a new change set.\n\nA receipt authorizes ONE operation: a merge receipt does not authorize a deploy. Before a different operation (deploy, publish), call `preflight_change_set` with `context.operation` set to that operation \u2014 reusing a differently-scoped receipt is not permitted and will fail at the gate.\n\nA stale or superseded receipt on a changed head requires a NEW preflight \u2014 `verify_receipt` cannot re-diff.\n\nFor mutating tools, put only the guarded version in the agent's tool table; keep the raw handler host-only and unreachable from that table. How you name tools is yours \u2014 this is a reachability property, not a product rename of host tools. CodeRifts cannot see or stop a raw call the host makes outside the table it returns; adopt this as a host convention, not as a guarantee from the package.\n\nCodeRifts reports a governance decision and `execution_action`; it does not by itself block merges. Blocking requires separate repository configuration (required status checks, enforcement) that this rule file does not set.\n\nTo act (mutate a contract, merge, deploy, or publish): call `preflight_change_set` with `preflight_mode` authorize. Analyze is informational (`may_execute` is always false) and is not permission. Read `execution_action` on the `decision_result` envelope.\n\nBefore acting under a held receipt: call `verify_receipt` with the intended `context` (operation, environment, repository, branch, pull_request) for THIS attempt. Do not act on a receipt whose scope does not match.\n\nAct only when `currently_authorized` is true (`control_envelope.receipt_view.currently_authorized`). A valid-looking token is not permission if `currently_authorized` is false or omitted.\n\nCommit / CAS evidence is a separate measurement (`commit_observation` on GuardOutcome). It is not a substitute for authorize + `currently_authorized`. Production hosts that want the fail-closed conjunction lock it with `profile: ENFORCING_STRICT` on withCodeRifts.\n\nIf the host requests an execution grant (opt-in `include_execution_grant`), the grant is bound to operation + target + after-payload (`scope_hash`) and is short-lived \u2014 never reuse it after the after-payload changes.\n\nAn ATOMIC-profile grant carries `state_nonce` and is single-use at the executor \u2014 if the executor has consumed the nonce, re-preflight; do not retry the same grant.\n\nWith a proven tenant\u2194repo binding you may request `derivation:\"server\"` instead of assembling `artifacts[]` yourself (`context.repository` + `context.base` + `context.head` required; caller-supplied artifacts are rejected on that path).\n\nA commit is only proven when an executor attestation verifies (customer-held executor key, `cas_evidence: executor_attested`); otherwise say \"authorized, commit not proven\".";

/** Once-per-process warning when the host supplied a prompt that lacks the marker. */
export const POLICY_ABSENT_WARN =
  "CodeRifts policy text not detected in the system prompt. The agent will still see the tools, but measured evidence shows operation-scope misuse is markedly more likely without it. See https://github.com/coderifts/agent-guard#policy-delivery.";

export type PolicyPresence = 'detected' | 'absent' | 'unknown';

export type WithPolicyOptions = {
  /**
   * Default true. `false` returns a non-mutated copy and does not append.
   * Opt-out for hosts that call `withPolicy` from a shared wrapper.
   */
  injectPolicy?: boolean;
};

/** Minimal chat message shape (OpenAI/Anthropic-compatible). Extra fields are preserved. */
export type PolicyMessage = {
  role: string;
  content?: unknown;
  [key: string]: unknown;
};

function textHasMarker(text: string): boolean {
  return text.includes(POLICY_MARKER);
}

function contentHasMarker(content: unknown): boolean {
  if (typeof content === 'string') return textHasMarker(content);
  if (Array.isArray(content)) return content.some(contentHasMarker);
  if (content && typeof content === 'object') {
    const o = content as Record<string, unknown>;
    if (typeof o.text === 'string' && textHasMarker(o.text)) return true;
    if (typeof o.content === 'string' && textHasMarker(o.content)) return true;
  }
  return false;
}

/**
 * Observation-only classification of host-supplied instruction text.
 * `null`/`undefined` -> `unknown` (host did not tell us). Anything else is
 * `detected` or `absent` based on POLICY_MARKER.
 */
export function policyPresenceOf(text: string | null | undefined): PolicyPresence {
  if (text == null) return 'unknown';
  return textHasMarker(String(text)) ? 'detected' : 'absent';
}

/** Alias used by hosts that call the check at startup without the guard. */
export function detectPolicyPresence(text: string | null | undefined): PolicyPresence {
  return policyPresenceOf(text);
}

function appendPolicyToString(existing: string): string {
  if (textHasMarker(existing)) return existing;
  if (existing.trim() === '') return CODERIFTS_POLICY;
  return existing + '\n\n' + CODERIFTS_POLICY;
}

/**
 * Append the canonical policy text if the marker is not already present.
 * Never mutates the caller's string/array/objects — always returns a new value
 * for arrays; strings are new only when appending.
 */
export function withPolicy(input: string, opts?: WithPolicyOptions): string;
export function withPolicy<T extends PolicyMessage>(input: readonly T[], opts?: WithPolicyOptions): T[];
export function withPolicy(
  input: string | readonly PolicyMessage[],
  opts?: WithPolicyOptions,
): string | PolicyMessage[] {
  const inject = opts?.injectPolicy !== false;
  if (typeof input === 'string') {
    if (!inject) return input;
    return appendPolicyToString(input);
  }
  const copy: PolicyMessage[] = input.map((m) => ({ ...m }));
  if (!inject) return copy;
  if (copy.some((m) => contentHasMarker(m.content))) return copy;
  const sysIdx = copy.findIndex((m) => String(m.role).toLowerCase() === 'system');
  if (sysIdx >= 0) {
    const sys = copy[sysIdx];
    if (typeof sys.content === 'string') {
      copy[sysIdx] = { ...sys, content: appendPolicyToString(sys.content) };
      return copy;
    }
    // Non-string system content: prepend a dedicated system message rather than guess parts.
    return [{ role: 'system', content: CODERIFTS_POLICY }, ...copy];
  }
  return [{ role: 'system', content: CODERIFTS_POLICY }, ...copy];
}

let warnedThisProcess = false;

function defaultWarn(msg: string): void {
  console.warn(msg);
}

/** Once-per-process warn. Subsequent absent detections stay silent. */
export function warnPolicyAbsentOnce(): void {
  if (warnedThisProcess) return;
  warnedThisProcess = true;
  defaultWarn(POLICY_ABSENT_WARN);
}

/**
 * Classify + maybe warn. `unknown` never warns. `detected` is silent.
 * `absent` warns once per process.
 */
export function observePolicyPresence(text: string | null | undefined): PolicyPresence {
  const presence = policyPresenceOf(text);
  if (presence === 'absent') warnPolicyAbsentOnce();
  return presence;
}

/** Test-only: allow the once-warn to fire again. */
export function resetPolicyWarnForTests(): void {
  warnedThisProcess = false;
}
