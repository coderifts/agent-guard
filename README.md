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
  { toolName: 'Edit', arguments: { path: 'openapi.yaml' }, filesTouched: ['openapi.yaml'], diff: '...' },
  // The mutating work is created ONLY here, after the verdict — never eagerly (closes TOCTOU).
  async (envelope, redactedCall) => applyEdit(redactedCall),
  { client },
);

if (!outcome.executed) console.error('blocked:', outcome.verdict);
// Retry ONLY when outcome.executionAttempted === false (the safe-to-retry signal).
```

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
