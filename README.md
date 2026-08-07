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
  onSettledCall: (o) => {
    // Advance the chain only on a GUARDED return that carries a receipt token.
    if (o.kind !== 'settled_call' || o.route !== 'GUARDED' || o.terminal !== 'RETURNED') return;
    const v = o.outcome.verdict;
    if (v && 'envelope' in v && v.envelope?.receipt?.token) {
      lastToken = v.envelope.receipt.token; // host advances the cursor
    }
  },
});
```

The same field exists on `GuardConfig` for direct `guardToolCall` / `guardToolRegistry` use
(`previousReceipt?: string | (() => string | undefined | null)`). A plain string works if the host
mutates it between calls; a getter is preferred so the package never looks like it owns the value.

**Concurrency (serial only for a linear chain):** The getter/`onSettledCall` pattern above is correct
when guarded contract calls run **one after another**. Modern agents often issue **overlapping** tool
calls. `onSettledCall` runs **after** a call settles, so two preflights in flight can both read the
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
