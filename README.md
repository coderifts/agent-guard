# @coderifts/agent-guard

Fail-closed guard for AI agent tool calls — preflight contract changes before they execute.

Security core **FROZEN** (agent-guard-api v1.0). Built on [`@coderifts/sdk`](https://www.npmjs.com/package/@coderifts/sdk) `^1.1.1`.

```bash
npm install @coderifts/agent-guard @coderifts/sdk
```

### Host git wiring (example in-repo, not in the tarball)

The package is pure: `resolveArtifacts` reads a host-supplied `blobs` map keyed by
`blobMapKey(ref, path)` (`${ref}:${path}`). Git I/O is the host’s job.

A **worked example** (injectable fake git, offline-runnable) lives in the git tree at
[`examples/host-git-resolve.mjs`](./examples/host-git-resolve.mjs) — it is **not**
published in the npm package (`files` is only `dist` + `README.md`), so the tarball
stays free of git/fs. Production PR artifact derivation:
[`coderifts/contract-gate`](https://github.com/coderifts/contract-gate) `src/artifacts.js`
(do not copy it here).

**TOCTOU is unclosed.** Resolving content proves what was true *at measurement time*;
a host that then writes unconditionally still races. Neither the example nor this
package supplies a version token or conditional write.

```typescript
import { guardToolCall } from '@coderifts/agent-guard';
import { CodeRifts } from '@coderifts/sdk';

const client = new CodeRifts({ apiKey: 'cr_live_...' });

const outcome = await guardToolCall(
  {
    toolName: 'Edit',
    arguments: { path: 'openapi.yaml' },
    // Supply the contract change as artifacts[] with before/after content — this is what the
    // server preflights. `id`/`type`/`before`/`after` are all required for each artifact.
    artifacts: [{ id: 'public-api', type: 'openapi', before: baseSpec, after: proposedSpec }],
  },
  // The mutating work is created ONLY here, after the verdict — never eagerly. That closes the
  // EAGER-EXECUTION ORDERING hazard (work is built after the verdict, not before). It does NOT
  // close the measurement-to-commit race: see "TOCTOU is unclosed" above.
  async (envelope, redactedCall) => applyEdit(redactedCall),
  { client, operation: 'merge', environment: 'production' },
);

if (!outcome.executed) console.error('blocked:', outcome.verdict);
// Retry ONLY when outcome.executionAttempted === false (the safe-to-retry signal).
```

> **Supply `artifacts[]` with content.** If the guard detects a contract change (e.g. from
> `filesTouched`/`diff`) but you did **not** supply `artifacts[]` with `before`/`after`, it fails
> closed **locally** with `outcome.verdict.cause === 'MISSING_ARTIFACT_CONTENT'` — the tool does not
> execute and the error is *actionable* (pass the change as artifacts), not a package failure. The
> guard never sends an empty change set to the server.
>
> **The default binder now forwards `args.artifacts`.** If your tool call carries the change as an
> `artifacts` array in its arguments, `guardToolRegistry` picks it up automatically (no explicit
> binder needed). A custom binder is still required only when the content lives under a different
> argument name or must be resolved from `filesTouched`/`diff`.

### Guarding the whole tool surface (inescapability)

`guardToolCall` guards one call. To make CodeRifts the **only** path a mutating tool can take, wrap
your entire tool list with [`guardToolRegistry`](#) — it returns the sole tool table the agent may
see (every mutator wrapped, fail-closed at construction if any would remain raw):

```typescript
import { guardToolRegistry } from '@coderifts/agent-guard';

const { tools, coverage } = guardToolRegistry(rawTools, { guard: { client } });
// register ONLY `tools` with your agent SDK; coverage === 'COMPLETE' ⇒ no mutator is reachable raw.
```

### One-call orchestration with `withCodeRifts` (S1 + S2)

`withCodeRifts` wraps `guardToolRegistry` behind a single call that takes a **mandatory** `operation`
and returns the protected tools plus **two separate coverage statements**: the registry's own report and
a narrower, product-level composition assurance. Register **only** the returned `tools`:

```typescript
import { withCodeRifts } from '@coderifts/agent-guard';

const { tools, registry_report, composition_assurance } = withCodeRifts({
  tools: rawTools,      // your raw tool list
  client,               // the CodeRifts client (same one guardToolRegistry expects)
  operation: 'merge',   // REQUIRED — no default (see below)
});
// register ONLY `tools` with your agent SDK. Anything the host registers directly is OUTSIDE
// the guard — the composition can only protect the table it returns.
```

### Final-answer proof block (ID645)

When a call produces a machine `GuardExecutionProof` (`outcome.proof`), you can embed a
**human-readable** block in the agent’s final answer. The renderer is faithful: `currently_authorized: null`
is **SKIPPED (not a pass)**; limits (e.g. host can still bypass; calls outside the guarded path are
invisible) always appear. It does not change the proof shape.

```typescript
import { renderFinalAnswerProof, attachProofToAgentResponse } from '@coderifts/agent-guard';

// After guardToolCall / withCodeRifts …
const block = renderFinalAnswerProof(outcome.proof); // markdown string
const answer = attachProofToAgentResponse('I applied the authorized edit.', outcome.proof);
// string → appends block; object → adds final_answer_proof + final_answer_proof_text
```

See `examples/final-answer-proof.mjs` for verified vs skipped side by side.

### Framework proof-binders (ID827, guard@6.1)

After `guardToolCall` returns a `GuardOutcome`, the binders map that **whole outcome** into the
framework’s **tool-result** shape so the execution proof travels back to the model in the tool
message — not only in a human final answer.

| Function | Id arg | Target field |
|---|---|---|
| `bindOpenAIGuardOutcome(outcome, { tool_call_id })` | `tool_call_id` | OpenAI tool message `content` (string) |
| `bindAnthropicGuardOutcome(outcome, { tool_use_id })` | `tool_use_id` | Anthropic `tool_result` `content` (string) |
| `bindGeminiGuardOutcome(outcome, { name })` | function `name` | Gemini `functionResponse.response` — a **structured object** `{ result, final_answer_proof, … }` (not a text field) |
| `bindLangGraphGuardOutcome(outcome, { tool_call_id, name? })` | `tool_call_id` (+ optional `name`) | LangGraph/LangChain ToolMessage `content` (string) |

**Behaviour (all four):** take the full `GuardOutcome` (ALLOW / BLOCK / APPROVAL / SKIPPED / error
arms); always embed `outcome.proof` (present on every arm); on a blocked arm state that the gate
did not permit execution with **no fabricated tool result**; on factory-error arms report the
failure + proof. Pure and non-mutating. No framework SDK dependency — minimal local types only.
Return types are type-level branded (`ProofBoundOpenAIToolMessage`, etc.) so the compiler can
distinguish a proof-bound tool result from a raw one (proof-forgotten *detection*, not
prevention). Proof formatting reuses `attachProofToAgentResponse` / `renderFinalAnswerProof`.

OpenAI-compatible providers (Grok, Kimi, Qwen, DeepSeek, …) use **`bindOpenAIGuardOutcome`** for
their tool-results — same ChatCompletions tool-message shape.

```typescript
import { guardToolCall, bindOpenAIGuardOutcome } from '@coderifts/agent-guard';

const outcome = await guardToolCall(
  { toolName: 'edit_file', arguments: args, filesTouched: [path] },
  async (_envelope, redacted) => doEdit(redacted),
  { client },
);

// Send this tool message back to the model (chat.completions messages[]).
const toolMessage = bindOpenAIGuardOutcome(outcome, { tool_call_id: toolCall.id });
// { role: 'tool', tool_call_id, content: '<result or gate message> + rendered proof' }
```

**OpenAI tool-calling (ID632 reference adapter).** Same input; OpenAI-shaped `tools` for
`chat.completions`, plus the same unflattened assurance objects. Shape conversion only — does
**not** claim product-level inescapability the core does not:

```typescript
import { withCodeRiftsOpenAI } from '@coderifts/agent-guard';

const {
  tools,                 // OpenAI: [{ type:'function', function:{ name, description?, parameters } }]
  protected_tools,       // guarded execute — dispatch tool_calls here, never re-register rawTools
  registry_report,
  composition_assurance, // still may be incomplete (inescapable_runtime:false) — do not drop
  receipt_thread,
} = withCodeRiftsOpenAI({ tools: rawTools, client, operation: 'merge' });

// openai.chat.completions.create({ model, messages, tools })
// Host boundary: only `tools` / `protected_tools` enter the model loop — raw tools stay out.
```

See also `examples/openai-adapter.mjs` (not published in the npm tarball).

**OpenAI-compatible models (no extra adapter).** DeepSeek and Kimi (Moonshot) use the same
ChatCompletions tool-calling format as OpenAI (`{ type: 'function', function: { name,
description, parameters } }`). Use **`withCodeRiftsOpenAI`** and point your client `baseURL`
(and API key) at their endpoint — zero new adapters, same guarded tools + unflattened assurance.
Tool-results use **`bindOpenAIGuardOutcome`** the same way as OpenAI.

**Qwen (Alibaba DashScope).** OpenAI-compatible via Model Studio compatible-mode — use
**`withCodeRiftsOpenAI`**, point `baseURL` at the DashScope compatible endpoint. Zero new adapters.

**Grok (xAI).** Also OpenAI-compatible tool calling — use **`withCodeRiftsOpenAI`** with the xAI `baseURL`.

**Perplexity (Sonar).** OpenAI-compatible chat completions, but tool calling is model-dependent: `sonar-pro` supports it (with a stricter JSON-object parameter schema), while plain `sonar` rejects tool definitions. Use **`withCodeRiftsOpenAI`** with tool-capable Perplexity models only.

**Anthropic tool_use (ID632 slice 2).** Same thin pattern; Anthropic Messages `tools` shape
(`{ name, description?, input_schema }`) instead of OpenAI function tools. Assurance still
unflattened — composition may remain incomplete:

```typescript
import { withCodeRiftsAnthropic } from '@coderifts/agent-guard';

const {
  tools,                 // Anthropic: [{ name, description?, input_schema }]
  protected_tools,       // guarded execute — dispatch tool_use here, never re-register rawTools
  registry_report,
  composition_assurance, // still may be incomplete (inescapable_runtime:false) — do not drop
  receipt_thread,
} = withCodeRiftsAnthropic({ tools: rawTools, client, operation: 'merge' });

// anthropic.messages.create({ model, messages, tools, max_tokens })
// Host boundary: only `tools` / `protected_tools` enter the model loop — raw tools stay out.
```

See also `examples/anthropic-adapter.mjs` (not published in the npm tarball).

**LangChain / LangGraph (ID632 slice 3).** Same thin pattern; emits **dependency-free** plain
descriptors the host can hand to LangChain `tool()` / LangGraph `ToolNode` / `bind_tools`. This
package does **not** depend on langchain or langgraph — the host owns those imports. Assurance
still unflattened:

```typescript
import { withCodeRiftsLangGraph } from '@coderifts/agent-guard';
// host-owned (not a dependency of this package):
// import { tool } from '@langchain/core/tools';
// import { ToolNode } from '@langchain/langgraph/prebuilt';

const {
  tools,                 // [{ name, description?, schema, func, invoke }] — guarded execute bound
  protected_tools,
  registry_report,
  composition_assurance, // still may be incomplete (inescapable_runtime:false) — do not drop
  receipt_thread,
} = withCodeRiftsLangGraph({ tools: rawTools, client, operation: 'merge' });

// const lcTools = tools.map((d) =>
//   tool(d.func, { name: d.name, description: d.description, schema: d.schema }),
// );
// const toolNode = new ToolNode(lcTools); // StateGraph … .addNode('tools', toolNode)
// Host boundary: only `tools` / `protected_tools` enter the graph — raw tools stay out.
```

See also `examples/langgraph-adapter.mjs` (not published in the npm tarball).

**Google Gemini (ID632 slice 4).** Same thin pattern; Gemini nests **all** tools under one
`functionDeclarations` array (not one OpenAI-style `{ type: 'function' }` per tool). Assurance
still unflattened:

```typescript
import { withCodeRiftsGemini } from '@coderifts/agent-guard';

const {
  tools,                 // Gemini: [{ functionDeclarations: [{ name, description?, parameters }, …] }]
  protected_tools,       // guarded execute — dispatch functionCall here, never re-register rawTools
  registry_report,
  composition_assurance, // still may be incomplete (inescapable_runtime:false) — do not drop
  receipt_thread,
} = withCodeRiftsGemini({ tools: rawTools, client, operation: 'merge' });

// model.generateContent({ contents, tools })
// Host boundary: only `tools` / `protected_tools` enter the model loop — raw tools stay out.
```

See also `examples/gemini-adapter.mjs` (not published in the npm tarball).

**Why `operation` is mandatory (no default).** Receipts bind to an operation and `merge` is not
`deploy`, so a silent default would evaluate a deployment under merge semantics. `operation` is the
session-level default for **generic** mutating tools only; a tool with a specialised mutation class
(`mutating_deploy`, `mutating_publish`, `mutating_vcs`, …) still derives its own operation from that
class — `operation` does not override it.

**The two scopes — the point of this call.** The return carries two coverage statements answering two
different questions. Captured output from a real call against the current build (a clean list of two
mutating tools):

```jsonc
// composition_assurance — shown WHOLE:
{
  "coverage": "PARTIAL",
  "inescapable_runtime": false,
  "residuals": ["composition_call_policy_incomplete"]
}

// registry_report — abbreviated (… marks fields elided here, NOT trimmed to read cleaner):
{
  "coverage": "COMPLETE",
  "guarded_mutators": ["edit_file", "write_config"],
  "unguarded_mutators": [],
  "claim": { "inescapable_runtime": true, "inescapable_merge": false, "inescapable_deploy": false },
  "warnings": []
  // … version, protected_tools, readonly_passthrough, unknown_treated_as, siblings
}
```

- **`registry_report`** is the truth about the tool table that was wrapped. It may legitimately say
  `COMPLETE` with `inescapable_runtime: true` — every mutator wrapped, none reachable raw.
  `withCodeRifts` passes it through **untouched**.
- **`composition_assurance`** is the narrower, product-level statement — what `withCodeRifts` itself
  claims. Today it reports `PARTIAL` with `inescapable_runtime: false` and the residual
  `composition_call_policy_incomplete`, because **composition-call-policy completeness**
  (`COMPOSITION_CALL_POLICY_COMPLETE`) is still false — not because tool wrapping or receipt
  carry-forward are missing. Receipt carry-forward **ships** (per-composition cursor, `threadReceipts`
  default on). Call-time STOP on BLOCK/RA and both-sides edit binders are already on the frozen path.
  What still blocks the product-level claim includes a **freshness-safe prior for write-style calls**
  (path + new content only) wired into enforce, among other policy gates — carry-forward alone does
  not flip this residual off.
- **This is deliberate, not a defect.** The composition will not claim runtime inescapability it cannot
  yet deliver.

Reconciling with the `guardToolRegistry` note above (`coverage === 'COMPLETE' ⇒ no mutator is reachable
raw`): that claim is exactly what `registry_report` states, and it **remains true** — `withCodeRifts`
does not weaken it. `composition_assurance` answers a *different* question: not "is every mutator
wrapped" (true today) but "is the whole execution path through this composition inescapable yet" (not
yet). The composition says so rather than borrowing the registry's answer.

**What you get today:** one entry point, every mutator in the returned table wrapped fail-closed,
automatic receipt carry-forward on by default, and an honest composition statement. **What you do not
get yet:** any product-level claim of runtime inescapability —
`composition_assurance.inescapable_runtime` stays `false` while **composition-call-policy** remains
incomplete (`COMPOSITION_CALL_POLICY_COMPLETE` is false). That is **not** because carry-forward is
missing (it ships). A green construction is still **not** a product-level runtime-inescapability
guarantee.

**`requireCoverage?` (optional).** Aborts construction when the **registry** coverage is weaker than
required, by the ordering `COMPLETE > PARTIAL > BYPASSED > UNKNOWN`. It constrains the **registry surface
only** — it **cannot** demand product-level inescapability (still gated on composition-call-policy
completeness, not on registry wrapping or on whether carry-forward is enabled), and a green
construction under it is not a product-level enforcement guarantee.

**`unknownToolPolicy` defaults to `'mutating'`.** An unclassified tool (no `mutationClass`, no
name-heuristic match) is treated as a mutator and wrapped — never silently downgraded to readonly, which
would hide a raw mutating capability behind a green result. Pass `'readonly'` / `'reject'` explicitly to
change it.

> **Known limitation — `forceReadonly` vs. an explicit `mutationClass`.** `forceReadonly` has **no
> effect** on a tool the caller declared with an explicit `mutationClass`: class resolution returns on
> `mutationClass` **before** `forceReadonly` is consulted, so the tool stays a wrapped mutator and **no
> warning or residual is produced**. A caller who both sets `mutationClass: 'mutating'` and lists that
> tool in `forceReadonly` gets **no signal that their `forceReadonly` was ignored**. `forceReadonly` only
> downgrades a tool whose mutating status came from the name heuristic.

**Shipped binder (both-sides only):** defaultBinder lifts `old_string`/`new_string` and `edits[]` into
artifacts when a contract path is present — it does **not** invent a `before` for write-style
path+new-content-only calls (no IO; empty before is forbidden).

**Not in this yet** (do not infer these from the one-call ergonomics): freshness-safe prior content
for write-style calls wired into enforce (path + new content only — pure core may exist; product
path is incomplete), platform-native bypass exclusion, a concurrent receipt manager (overlap
refuses to advance the package cursor — host owns serialisation if a linear chain is required), and
framework adapters. **Receipt carry-forward is shipped** (see below); do not list it as missing.

#### `composition_assurance` is the runtime placement input

`coverageReport` aggregates four placements — `runtime`, `merge`, `deploy`, and `content` — plus an
`applicability` map saying which apply. It does not gather those placements; the host supplies them.
`withCodeRifts` already returns one of them in full: **`composition_assurance` is field-for-field the
same shape as `RuntimePlacementInput`** (`coverage`, `inescapable_runtime`, `residuals`). Pass it
straight through as the runtime input:

```typescript
import { withCodeRifts, coverageReport } from '@coderifts/agent-guard';

const { tools, composition_assurance } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
});

const report = coverageReport({
  applicability: { /* host-known — see warning below */ runtime: true, merge: true, deploy: true, content: true },
  // Required for FULLY_ENFORCED: absence is not attestation (RT-P-16).
  applicability_attested: true,
  runtime: composition_assurance, // complete RuntimePlacementInput — no remapping
  // merge / deploy / content: host still supplies (see next)
});
```

The package cannot fill the other three. It sees the agent’s tool table, not branch protection, not the
deployment target, not content resolution. Hosts produce those with the exports that already own them:
**`gateDecision`** (merge), **`deployGate`** (deploy), **`resolveArtifacts`** (content).

**Change-set re-bind is optional; its absence is residual-only.** A green `gateDecision` /
`deployGate` without `requiredContext.expected_fingerprint` means the receipt matched the **head**
(or deploy artifact/env bind), **not** that it was re-bound to the host’s current change set. The
optional fingerprint step still fails hard with `fingerprint_mismatch` when an expected value is
supplied and disagrees; when it is omitted, the gate stays green and names residual
`change_set_not_rebound` (claim flags `inescapable_merge` / `inescapable_deploy` are not flipped).
That distinction bites when the base moves, or when a different artifact subset was analysed at the
same tip: same head, different change set, receipt still greens without a re-bind.
The residual field is a **single slot**: when another honesty residual is already named
(e.g. app-binding or enforcement), `change_set_not_rebound` is not written — so **absence of a
residual is not evidence that the corresponding gap is closed**; it may only have been outranked.

**Applicability is not a placeholder for “unknown.”** The `applicability` map is four booleans. Setting
a placement to `false` asserts that placement **does not apply** — not that you have not measured it
yet. A host that passes only the runtime placement and marks `merge`, `deploy`, and `content` false is
claiming three enforcement boundaries are irrelevant to them; the aggregate report will treat those
placements as `EXCLUDED` and will not residual or cap them. Do not set three falses just to typecheck.
That overstates coverage.

**`applicability_attested` (RT-P-16).** The map alone is not enough for a full-tetrad claim. Pass
`applicability_attested: true` only when the host has deliberately decided which placements apply.
If the field is absent or false, `coverageReport` names residual `applicability_unattested` and will
not return `FULLY_ENFORCED` even when every applicable placement is ENFORCING (downgrade to
`PARTIALLY_ENFORCED`). Absence is not attestation.

`withCodeRifts` does not call `coverageReport` itself: it can only speak for the runtime placement, and
a report it produced alone would either guess the other three or assert they do not apply — neither is
honest, so the composition hands the caller the piece it owns and stops.

#### `deployGate` and deploy-time `bindDeploy`

`deployGate` is the pure decision. **`bindDeploy`** is the pure **caller** at the moment of
deploying: the host supplies `{ environment, artifact_id, receipt, pipeline_enforcement }`; the
package composes `deployGate` and returns a decision. No I/O, no receipt re-verify, no CD call.

Same shape as the merge gate (`gateDecision` is pure; GitHub enforces outside us). Deploy differs:
there is no PR status check to hang on, and **the environment name is a host assertion** — the
receipt’s `bound_environment` is signed evidence; the target environment string is not. A host can
claim `staging` while deploying to production; the package cannot tell. The result always reports
`environment.provenance: 'host_asserted'` (never `verified`).

```typescript
import { bindDeploy } from '@coderifts/agent-guard';

const r = bindDeploy({
  environment: { name: 'production', provenance: 'host_asserted' },
  artifact_id: digest,
  receipt: receiptView, // finished view — not re-verified here
  pipeline_enforcement: { enforcement: 'ENFORCING', bypass_possible: false },
});
// r.decision_allows_deploy  — pure decision only
// r.pipeline_action         — always 'not_observed' (we did not block or run the pipeline)
// r.environment.provenance  — always 'host_asserted'
// r.inescapable_deploy      — only true under ENFORCING ∧ ¬bypass (from the gate, not a host flag)
if (!r.decision_allows_deploy) process.exit(1); // host pipeline chooses to honour
```

#### `deployGate` is also the publish / register gate

`deployGate` gates any **artifact-bound application** operation — not only CD deploys. The target is
`{ environment, artifact_id }`; the operation label is `requiredContext.operation` (default
`'deploy'`). The receipt must have been issued for **that same** operation: merge is not deploy is not
publish. Binding checks are the same regardless of the label (environment + artifact match, allow-class
verdict, enforcement residual). Prefer **`bindDeploy`** at the live step; raw `deployGate` remains
for hosts that already build the full input.

```typescript
import { deployGate } from '@coderifts/agent-guard';

// npm publish — same gate, operation label 'publish'
const g = deployGate({
  deployTarget: {
    environment: 'npm',
    artifact_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
  // Receipt view: server receipt must have been issued for operation 'publish' (T7 match).
  // bound_environment / bound_artifact_id are NOT server-emitted signed fields — the caller
  // supplies them on this view alongside the token (deploy-gate's "view of the finished receipt").
  receipt,
  requiredContext: {
    operation: 'publish',
    enforcement: { enforcement: 'ENFORCING', bypass_possible: false },
  },
});
// g.deploy_allowed — decision flag (name is historical; see caveat)
```

MCP **register** is the same shape: set `operation: 'register'` and put the **manifest digest** in
`artifact_id` (caller supplies the matching `bound_artifact_id` on the receipt view).

**Naming caveat:** the result field is always `deploy_allowed`, even when the operation was `publish`
or `register`. It is accurate about the boolean decision and wrong about the noun. Type names
(`DeployTarget`, `DeployGateInput`, `inescapable_deploy`) are the same historical deploy vocabulary —
not a second gate.

There is no separate `publishGate` export: the function is already generic over `operation`, and
aliases would grow a frozen public surface for a parameter that already does the job. That is a
deliberate choice, not an omission.

### Observation hooks (`onEvent` + `onSettledCall`)

Optional hooks on `withCodeRifts` for seeing what calls through the **returned** tool table do.
Neither changes `composition_assurance` (still `PARTIAL` / `inescapable_runtime: false` until the
gaps above land). `onSettledCall` is pure observation; `onEvent` is the lifecycle emitter and, only
together with host `monitoringSinkWired: true`, satisfies the MONITOR gate (next section).

```typescript
import {
  withCodeRifts,
  foldTableSettledCalls,
  guardedFractionAmongRoutes,
  type SettledCallObservation,
} from '@coderifts/agent-guard';

const settled: SettledCallObservation[] = [];
const { tools } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
  onEvent: (e) => { /* frozen-core lifecycle event; partial — see gaps */ },
  onSettledCall: (o) => {
    settled.push(o);
    // Discriminated: o.kind === 'settled_call', o.route, o.terminal are EXPLICIT tags.
    // GUARDED + RETURNED → o.outcome is a non-optional GuardOutcome
    //   e.g. o.outcome.executed === false && o.outcome.verdict.kind === 'BLOCK'
    // PASSTHROUGH / BYPASSED + RETURNED → o.result (raw tool return)
    // any route + THREW → o.error (then the rejection still propagates to the host)
  },
});

// Host-owned fold only. The package holds no counters and never computes a ratio at runtime.
const counts = foldTableSettledCalls(settled);
const share = guardedFractionAmongRoutes(counts);
// share.kind === 'absent' when zero calls or only one route was observed — never a misleading 0 or 1.
// These numbers describe only settled calls through the returned table — not "total operations"
// and not "100% enforcement coverage".
```

**Why two hooks (not redundant):**

| Hook | What it is |
|------|------------|
| **`onEvent`** | The frozen core’s lifecycle emitter (`GuardConfig.onEvent`), forwarded **unchanged** into the guard config. Partial telemetry. Alone does **not** unlock MONITOR — pair with `monitoringSinkWired: true`. |
| **`onSettledCall`** | Composition post-call observation: fires **exactly once** for every **settled** call through the **returned** table. Discriminated union `SettledCallObservation` with explicit `route` (`GUARDED` \| `PASSTHROUGH` \| `BYPASSED`) and `terminal` (`RETURNED` \| `THREW`). Replaces the former guarded-only `onOutcome` / `ObservedOutcome`. |

Neither replaces the other. Lifecycle crumbs ≠ full settle record; settle record ≠ every lifecycle event.

**Gaps (same weight as the features — do not build an “every mutation was checked” claim on these hooks alone):**

- **`onEvent` has no dedicated BLOCK / REQUIRE_APPROVAL event.** After `preflight_result`, those paths return blocked with no further emit. Those outcomes are visible via **`onSettledCall`** on the GUARDED arm (`outcome.executed === false`, `outcome.verdict.kind === 'BLOCK' | 'APPROVAL'`), not via `onEvent`.
- **Event payload carries no envelope, receipt, or fingerprint** — only optional `decisionId` (and action/cause/signals/…). **GUARDED+RETURNED** carries the full outcome, including `outcome.verdict.envelope` where the frozen path attached one (BLOCK / APPROVAL / ALLOW / MONITOR).
- **`onSettledCall` sees only the returned table.** Host-registered raw tools outside that table are invisible. Passthrough and forced-bypass (break-glass readonly) routes **do** fire; that is deliberate so hosts can count table traffic without inventing “total operations.”
- **`onEvent` is partial on other branches too** (e.g. some closed-availability stops may emit only `preflight_start`). The declared type **`execution_skipped` is never emitted** by the frozen core.
- Neither hook alone is receipt carry-forward: `onEvent` lacks envelope/receipt; `onSettledCall` exposes them when present on GUARDED+RETURNED but does not retain or re-inject them across calls.
- **No package-held ratio.** Pure helpers `foldTableSettledCalls` / `guardedFractionAmongRoutes` run on a host list; the latter returns **absent** (not zero) when observation is one-sided.

**Safety guarantees (observation must not change execution):**

- The host receives the **same return value** the unwrapped tool produced; observation does not alter it.
- A throwing `onSettledCall` does not break the call; a **returned rejected promise** is handled (not left unhandled).
- If the tool/`guardToolCall` path **rejects**, the rejection **propagates** after the THREW observation fires — no fake GuardOutcome is invented on that arm.

### Receipt chaining (package cursor default-on; host may override)

The signed receipt body has always carried a **previous-receipt** field (`prev`): the issuer stores
the literal `null` when no prior token was supplied, or `sha256:`+hex of the prior token when the
preflight request included `previous_receipt`. That makes **hash-linked sequences** possible.

**Package-level composition cursor (shipped, default on):** `withCodeRifts` keeps a **per-composition-
instance** receipt cursor. With `threadReceipts` defaulting to **true** (`threadReceipts !== false`),
each enforced+receipt-verified guarded call can advance that cursor and supply it as
`previous_receipt` on the next preflight for the same composition. Opt out with
`threadReceipts: false` (every call is then a root unless the host threads manually). This is **not**
process/session global; it is one cursor per `withCodeRifts` result. The package does **not** verify
signatures or self-attest chain authenticity — re-run `verifyReceiptChainLinkage` (and signature
verify) on tokens you export if you need product truth.

**Host override (always wins):** `previousReceipt` on the composition (string or getter) overrides the
package cursor at resolve time when set — use it to inject a prior the composition does not hold.

```typescript
// Default: automatic carry-forward for this composition (threadReceipts defaults true).
const { tools, receipt_thread } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
});
// receipt_thread.enabled === true; receipt_thread.lastToken() after settled guarded calls.

// Opt out of the package cursor:
const { tools: t2 } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
  threadReceipts: false,
});

// Host-owned prior (overrides the package cursor when both exist):
let lastToken: string | undefined;
const { tools: t3 } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
  previousReceipt: () => lastToken,
  onSettledCall: (o) => {
    if (o.kind !== 'settled_call' || o.route !== 'GUARDED' || o.terminal !== 'RETURNED') return;
    const v = o.outcome.verdict;
    if (v && 'envelope' in v && v.envelope?.receipt?.token) {
      lastToken = v.envelope.receipt.token;
    }
  },
});
```

The same `previousReceipt` field exists on `GuardConfig` for direct `guardToolCall` /
`guardToolRegistry` use (`previousReceipt?: string | (() => string | undefined | null)`).

**Concurrency (serial only for a linear chain):** Automatic advance is correct when guarded contract
calls run **one after another**. Overlapping tool calls can race; the package **refuses to advance**
the composition cursor under overlap rather than inventing a concurrent receipt manager. If you need
a linear chain under concurrency, **the host owns the ordering rule** (no package mutex or queue).
Symptom of treating a fork as a line: `verifyReceiptChainLinkage` reports `broken_link` on a
sequence you believed was linear, with no other explanation in the tokens themselves.

**Offline linkage check (not signature verification):**

```typescript
import { verifyReceiptChainLinkage } from '@coderifts/agent-guard';

const result = verifyReceiptChainLinkage([token0, token1, token2]);
// result.ok === true  → each token's body.prev matches null / sha256(prevToken)
// result.ok === false → failedAt + reason (broken_link | unexpected_predecessor | malformed_token)
```

This checks **only** predecessor commitments inside the token bodies. It does **not** verify
Ed25519 signatures, expiry, keys, or authorization — use the existing verify-receipt path for that.
**The package does not call this over a self-held chain and announce integrity**; you export tokens
and re-check them yourself (or with this pure helper).

**`chain_status` is not linkage.** A preflight response may set `chain_status: "absent"` on a
receipt that **is** hash-linked to a prior token — and `verifyReceiptChainLinkage` will still report
`ok: true`. That field is the server’s **channel-chain attestation gate** (prior signature intact /
broken / not evaluated), not predecessor linkage. On the preflight path that gate does not run, so
`absent` is expected; linkage is what `verifyReceiptChainLinkage` answers. Neither proves the
predecessor was ever a real signed receipt — see the signature/auth path above. `previous_receipt`
also does not change the decision or fingerprint (audit trail only, by design).

**When a chainable receipt exists — and when it does not**

A receipt token appears on the outcome when the frozen path attached an envelope with
`envelope.receipt.token` (typically BLOCK / APPROVAL / ALLOW / MONITOR after a successful
preflight). An intact chain of those tokens means: **the guarded contract calls that produced
receipts, in the order you present, with none removed or reordered** (linkage is tamper-evident).
It does **not** mean a complete session record.

Receipts are **absent** on at least:

- **Detector-skipped** calls (`SKIPPED` / not a contract call) — no preflight, no envelope.
- Calls that **failed closed before the oracle** (e.g. missing artifact content) — no issuance.
- **Open-passthrough** availability paths that execute with a null envelope — no this-call receipt.
- **Readonly passthrough** tools — never enter `guardToolCall`; they still settle via `onSettledCall`
  as `PASSTHROUGH` (no GuardOutcome / no receipt).

A receipt **can exist when the tool then threw** after approval (`executed: false`, `error` set).
The chain records an issued decision for a mutation that may never have landed — do not read
“chain link” as “edit applied on disk.”

Do **not** claim an intact chain proves session completeness, that edits landed, or that downstream
CI may skip re-analysis. Prefer tamper-evident language over “tamper-proof.”

### WARN / `CONTINUE_WITH_MONITORING` needs a host assertion + `onEvent`

Without both **`monitoringSinkWired: true`** and an **`onEvent`** handler, a **WARN** verdict does
**not** proceed. The outcome is fail-closed with cause **`MONITORING_UNWIRED`**, and the tool **does
not run**. That is intentional, not a transport bug.

The host **asserts** that a monitoring sink is intentionally wired (`monitoringSinkWired: true`). The
package records that claim and checks only that it **agrees** with a present `onEvent` callback. It
does **not** and **cannot** confirm that any event reaches a destination — a no-op `() => {}` is
indistinguishable from a real logger, and we do not try to detect empty functions. A declaration is
a claim we record, not a fact we verify.

**Agreement (fail closed on contradiction):**

| `monitoringSinkWired` | `onEvent` | MONITOR gate |
|-----------------------|-----------|--------------|
| `true` | function present | wired — proceeds (when receipt verified) |
| `true` | absent | contradiction → `MONITORING_UNWIRED` |
| absent / `false` | function present | **unwired** — declaration required; `onEvent` alone is not enough |
| absent / `false` | absent | unwired (same as today with no sink) |

**Absent declaration = unwired** (breaking for callers that only passed `onEvent`). That closes the
hole where `onEvent: () => {}` unlocked MONITOR while observing nothing. Cost: every host that wants
WARN to proceed must set `monitoringSinkWired: true` in addition to `onEvent`.

On a MONITOR/WARN path the guard emits `monitoring_required` when the gate is wired, or
`monitoring_unwired` when it is not (then `MONITORING_UNWIRED` if the call would otherwise be
enforceable).

**Three different jobs (not three sinks):** `onEvent` = lifecycle events; `monitoringSinkWired` =
host claim that monitoring is intentionally wired (opens MONITOR only when it agrees with
`onEvent`); `onSettledCall` = one settle record per returned-table call (GUARDED arm carries
`GuardOutcome`) and gates nothing.

Pass both on `withCodeRifts({ …, onEvent, monitoringSinkWired: true })`, or on `guardToolCall` /
`guardToolRegistry`’s `guard: { client, onEvent, monitoringSinkWired: true }` — same fields.

## Guarantees (tsc-verified)

- **Fail-closed by default** — any ambiguity, integrity failure, or unknown state resolves to `STOP`.
- **Eager-execution ordering closed (TOCTOU proper is NOT closed)** — the factory creates the
  mutating work *after* the verdict, so no mutation is built before authorization. The
  measurement-to-commit race remains: content resolved at measurement time can change before the
  host commits. Closing that needs a host-side conditional write (compare-and-swap on a version
  token) — this package never writes, and reports `conditional_write` as a host assertion it
  cannot verify.
- **Retry-safe** — `executionAttempted` is the only safe-to-retry signal; a post-authorization throw
  is `executionAttempted:true` (the remote side effect may have landed).
- **`enforced:true` only on a LIVE, receipt-verified `ALLOW`/`MONITOR`** — never on cached/LKG,
  SKIPPED, observeOnly, or fail-open paths (unrepresentable at compile time).
- **Integrity failures never fail open** — a bad signature, schema-invalid response, detector/config
  error, or request-attributable rejection (413/422) always resolves closed + trips the breaker.

## Trigger detection

`builtinDetector` (fail-safe, versioned) decides whether a tool call touches a contract artifact
(OpenAPI/GraphQL/gRPC/AsyncAPI/MCP manifest/migrations/CI gates). Precedence: explicit artifacts >
filesTouched patterns > diff/content markers > toolName > intent (add-only). Ambiguity triggers
(`confident=false ⇒ trigger=true`). It passes all 68 vectors of the Grok trigger corpus.

See `agent-guard-api.FROZEN-v1.0.md` for the full frozen contract.
