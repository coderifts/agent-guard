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
  `composition_call_policy_incomplete`, because call-time policy and receipt carry-forward are not yet
  delivered.
- **This is deliberate, not a defect.** The composition will not claim runtime inescapability it cannot
  yet deliver.

Reconciling with the `guardToolRegistry` note above (`coverage === 'COMPLETE' ⇒ no mutator is reachable
raw`): that claim is exactly what `registry_report` states, and it **remains true** — `withCodeRifts`
does not weaken it. `composition_assurance` answers a *different* question: not "is every mutator
wrapped" (true today) but "is the whole execution path through this composition inescapable yet" (not
yet). The composition says so rather than borrowing the registry's answer.

**What you get today:** one entry point, every mutator in the returned table wrapped fail-closed, and an
honest composition statement. **What you do not get yet:** any product-level claim of runtime
inescapability — `composition_assurance.inescapable_runtime` stays `false` until the later slices land.

**`requireCoverage?` (optional).** Aborts construction when the **registry** coverage is weaker than
required, by the ordering `COMPLETE > PARTIAL > BYPASSED > UNKNOWN`. It constrains the **registry surface
only** — it **cannot** demand product-level inescapability (unreachable until later slices), and a green
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

**Not in this yet** (do not infer these from the one-call ergonomics): call-time policy, automatic
binders, receipt carry-forward, WARN monitoring, and framework adapters.

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
