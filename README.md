# @coderifts/agent-guard

Fail-closed guard for AI agent tool calls — preflight contract changes before they execute.

Security core **FROZEN** (agent-guard-api v1.0). Built on [`@coderifts/sdk`](https://www.npmjs.com/package/@coderifts/sdk) `^1.1.1`.

```bash
npm install @coderifts/agent-guard @coderifts/sdk
```

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
  // The mutating work is created ONLY here, after the verdict — never eagerly (closes TOCTOU).
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
  `composition_call_policy_incomplete`, because composition-level completeness still needs more than
  tool wrapping: receipt carry-forward, and a freshness-safe prior for write-style calls (path + new
  content only). Call-time STOP on BLOCK/RA is already on the frozen path; both-sides edit binders
  (old_string/new_string, edits[]) are already shipped — neither alone flips this residual off.
- **This is deliberate, not a defect.** The composition will not claim runtime inescapability it cannot
  yet deliver.

Reconciling with the `guardToolRegistry` note above (`coverage === 'COMPLETE' ⇒ no mutator is reachable
raw`): that claim is exactly what `registry_report` states, and it **remains true** — `withCodeRifts`
does not weaken it. `composition_assurance` answers a *different* question: not "is every mutator
wrapped" (true today) but "is the whole execution path through this composition inescapable yet" (not
yet). The composition says so rather than borrowing the registry's answer.

**What you get today:** one entry point, every mutator in the returned table wrapped fail-closed, and an
honest composition statement. **What you do not get yet:** any product-level claim of runtime
inescapability — `composition_assurance.inescapable_runtime` stays `false` until receipt carry-forward
and a freshness-safe prior for write-style calls (path + new content only) land. Both-sides edit
binders already shipped; they do not complete that claim alone.

**`requireCoverage?` (optional).** Aborts construction when the **registry** coverage is weaker than
required, by the ordering `COMPLETE > PARTIAL > BYPASSED > UNKNOWN`. It constrains the **registry surface
only** — it **cannot** demand product-level inescapability (still blocked on receipt carry-forward and
write-style prior content, not on registry wrapping), and a green construction under it is not a
product-level enforcement guarantee.

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

**Not in this yet** (do not infer these from the one-call ergonomics): receipt carry-forward,
freshness-safe prior content for write-style calls, and framework adapters.

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
  runtime: composition_assurance, // complete RuntimePlacementInput — no remapping
  // merge / deploy / content: host still supplies (see next)
});
```

The package cannot fill the other three. It sees the agent’s tool table, not branch protection, not the
deployment target, not content resolution. Hosts produce those with the exports that already own them:
**`gateDecision`** (merge), **`deployGate`** (deploy), **`resolveArtifacts`** (content).

**Applicability is not a placeholder for “unknown.”** The `applicability` map is four booleans. Setting
a placement to `false` asserts that placement **does not apply** — not that you have not measured it
yet. A host that passes only the runtime placement and marks `merge`, `deploy`, and `content` false is
claiming three enforcement boundaries are irrelevant to them; the aggregate report will treat those
placements as `EXCLUDED` and will not residual or cap them. Do not set three falses just to typecheck.
That overstates coverage.

`withCodeRifts` does not call `coverageReport` itself: it can only speak for the runtime placement, and
a report it produced alone would either guess the other three or assert they do not apply — neither is
honest, so the composition hands the caller the piece it owns and stops.

#### `deployGate` is also the publish / register gate

`deployGate` gates any **artifact-bound application** operation — not only CD deploys. The target is
`{ environment, artifact_id }`; the operation label is `requiredContext.operation` (default
`'deploy'`). The receipt must have been issued for **that same** operation: merge is not deploy is not
publish. Binding checks are the same regardless of the label (environment + artifact match, allow-class
verdict, enforcement residual).

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

### Observation hooks (`onEvent` + `onOutcome`)

Optional hooks on `withCodeRifts` for seeing what guarded calls do. Neither changes
`composition_assurance` (still `PARTIAL` / `inescapable_runtime: false` until the gaps above land).
`onOutcome` is pure observation; `onEvent` is also the monitoring **presence** gate (next section).

```typescript
const { tools } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
  onEvent: (e) => { /* frozen-core lifecycle event; partial — see gaps */ },
  onOutcome: ({ toolName, outcome }) => {
    // composition post-call: full GuardOutcome for this guarded tool
    // e.g. outcome.executed === false && outcome.verdict.kind === 'BLOCK'
  },
});
```

**Why two hooks (not redundant):**

| Hook | What it is |
|------|------------|
| **`onEvent`** | The frozen core’s lifecycle emitter (`GuardConfig.onEvent`), forwarded **unchanged** into the guard config. Partial telemetry. |
| **`onOutcome`** | Composition post-call observation: fires after each **guarded** tool’s `execute` returns, with `{ toolName, outcome }` where `outcome` is the full **`GuardOutcome`**. |

Neither replaces the other. Lifecycle crumbs ≠ full outcome; full outcome ≠ every lifecycle event.

**Gaps (same weight as the features — do not build an “every mutation was checked” claim on these hooks alone):**

- **`onEvent` has no dedicated BLOCK / REQUIRE_APPROVAL event.** After `preflight_result`, those paths return blocked with no further emit. Those outcomes are visible via **`onOutcome`** (`outcome.executed === false`, `outcome.verdict.kind === 'BLOCK' | 'APPROVAL'`), not via `onEvent`.
- **Event payload carries no envelope, receipt, or fingerprint** — only optional `decisionId` (and action/cause/signals/…). **`onOutcome`** carries the full outcome, including `outcome.verdict.envelope` where the frozen path attached one (BLOCK / APPROVAL / ALLOW / MONITOR).
- **`onOutcome` fires only for guarded tools** (`_coderifts.guarded === true`). Readonly passthrough tools never enter `guardToolCall` and produce no `GuardOutcome` — they are not wrapped and never fire `onOutcome`.
- **`onEvent` is partial on other branches too** (e.g. some closed-availability stops may emit only `preflight_start`). The declared type **`execution_skipped` is never emitted** by the frozen core.
- Neither hook alone is receipt carry-forward: `onEvent` lacks envelope/receipt; `onOutcome` exposes them when present but does not retain or re-inject them across calls.

**Safety guarantees (observation must not change execution):**

- The host receives the **same outcome object** the hook saw; observation does not alter the return value.
- A throwing `onOutcome` does not break the call; a **returned rejected promise** is handled (not left unhandled).
- If the tool/`guardToolCall` path **rejects**, the rejection **propagates** and **no** outcome is invented — `onOutcome` is not called with a fake object.

### Receipt chaining (optional, host-threaded — no package cursor)

The signed receipt body has always carried a **previous-receipt** field (`prev`): the issuer stores
the literal `null` when no prior token was supplied, or `sha256:`+hex of the prior token when the
preflight request included `previous_receipt`. That makes **hash-linked sequences** possible.
Historically the guard sent `previous_receipt: undefined` on every call, so every receipt was a
root. Chaining is now **possible**, not automatic.

**How to thread a prior (host-owned):**

```typescript
let lastToken: string | undefined;
const { tools } = withCodeRifts({
  tools: rawTools,
  client,
  operation: 'merge',
  // Read on each preflight; the package does not store or advance this value.
  previousReceipt: () => lastToken,
  onOutcome: ({ outcome }) => {
    const v = outcome.verdict;
    if (v && 'envelope' in v && v.envelope?.receipt?.token) {
      lastToken = v.envelope.receipt.token; // host advances the cursor
    }
  },
});
```

The same field exists on `GuardConfig` for direct `guardToolCall` / `guardToolRegistry` use
(`previousReceipt?: string | (() => string | undefined | null)`). A plain string works if the host
mutates it between calls; a getter is preferred so the package never looks like it owns the value.

**Concurrency (serial only for a linear chain):** The getter/onOutcome pattern above is correct when
guarded contract calls run **one after another**. Modern agents often issue **overlapping** tool
calls. `onOutcome` runs **after** a call finishes, so two preflights in flight can both read the
same `lastToken` before either advances it. The issuer then produces two children of one parent —
a **forest**, not a single linear chain. The package holds nothing, so it cannot serialise that
advance; **the host owns the ordering rule**. If you need a linear chain under concurrency, you
must serialise your own advance (no package mutex or queue is provided). Symptom of treating a
fork as a line: `verifyReceiptChainLinkage` reports `broken_link` on a sequence you believed was
linear, with no other explanation in the tokens themselves.

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
- **Readonly passthrough** tools — never enter `guardToolCall`; no `onOutcome` either.

A receipt **can exist when the tool then threw** after approval (`executed: false`, `error` set).
The chain records an issued decision for a mutation that may never have landed — do not read
“chain link” as “edit applied on disk.”

Do **not** claim an intact chain proves session completeness, that edits landed, or that downstream
CI may skip re-analysis. Prefer tamper-evident language over “tamper-proof.”

### WARN / `CONTINUE_WITH_MONITORING` needs `onEvent`

Without an `onEvent` handler, a **WARN** verdict does **not** proceed. The outcome is fail-closed with
cause **`MONITORING_UNWIRED`**, and the tool **does not run**. That is intentional, not a transport bug.

The check is **presence only**: `sinkWired = !!config.onEvent`. Any truthy handler counts. The guard does
**not** require the handler to persist, forward, or acknowledge events — a no-op `() => {}` satisfies
the gate the same as a real logger.

**Sharp edge:** wiring `onEvent` only to debug lifecycle events **also** enables WARN to proceed as
`CONTINUE_WITH_MONITORING` (when the receipt is verified). Presence is the whole precondition.

On a MONITOR/WARN path the guard emits `monitoring_required` when the handler is present, or
`monitoring_unwired` when it is not (then `MONITORING_UNWIRED` if the call would otherwise be
enforceable).

**Three different jobs (not three sinks):** `onEvent` = lifecycle events **and** the monitoring
presence gate; `onOutcome` = full `GuardOutcome` per guarded call and gates nothing.

Pass `onEvent` on `withCodeRifts({ …, onEvent })`, or on `guardToolCall` / `guardToolRegistry`’s
`guard: { client, onEvent }` — same field.

## Guarantees (tsc-verified)

- **Fail-closed by default** — any ambiguity, integrity failure, or unknown state resolves to `STOP`.
- **No TOCTOU** — the factory creates the mutating work *after* the verdict.
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
