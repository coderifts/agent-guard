# Host examples (not published)

This directory is **not** part of the `@coderifts/agent-guard` npm tarball
(`package.json` → `"files": ["dist", "README.md"]` only). The shipped package
stays free of git and filesystem I/O.

These files exist so a host can **read a worked wiring** without cloning a second
repo. They are **not** a claim that the freshness / TOCTOU story is closed.

| File | What it shows |
|------|----------------|
| [`host-git-resolve.mjs`](./host-git-resolve.mjs) | How a host builds `blobs` keys, feeds `resolveArtifacts`, and wires `resolvePriorContent` with an **injectable** git seam. Runnable offline with a fake. |
| [`openai-adapter.mjs`](./openai-adapter.mjs) | **ID632** thin OpenAI tool-calling adapter: raw tools + client + `operation` → OpenAI `tools[]` + untouched `composition_assurance` / `registry_report` / `receipt_thread`. Shape only — does not upgrade assurance. |
| [`anthropic-adapter.mjs`](./anthropic-adapter.mjs) | **ID632** thin Anthropic tool_use adapter: same pattern as OpenAI; target shape is `{ name, description?, input_schema }`. Assurance unflattened. |
| [`langgraph-adapter.mjs`](./langgraph-adapter.mjs) | **ID632** thin LangChain/LangGraph adapter: plain descriptors `{ name, description?, schema, func, invoke }` (no hard framework dep). Host wires into `tool()` / `ToolNode`. Assurance unflattened. |
| [`gemini-adapter.mjs`](./gemini-adapter.mjs) | **ID632** thin Google Gemini adapter: `tools: [{ functionDeclarations: [{ name, description?, parameters }] }]`. Assurance unflattened. |
| [`vercel-adapter.mjs`](./vercel-adapter.mjs) | **roadmap 129** thin Vercel AI SDK adapter: `tools` record `{ [name]: { description?, parameters, execute } }` matching v4 `tool()`. No `ai` dep. Assurance unflattened. |
| [`final-answer-proof.mjs`](./final-answer-proof.mjs) | **ID645** human-readable final-answer proof block: verified/enforced vs skipped (`currently_authorized: null`) side by side; limits always surfaced. |
| [`langgraph-guard-python/`](./langgraph-guard-python/) | **Python** reference for the same control-flow contract this package enforces in TS: branch on `execution_action`, closed set of four, present-but-unknown halts. Framework nodes for LangGraph / LangChain / AutoGen plus a `@coderifts_guard` decorator. Offline test suite, stdlib only. |

### About `langgraph-guard-python/`

Consolidated in from `coderifts/example-langgraph-guard` (git subtree, history
preserved). It is here because it is an **example of the same contract**, not a
second implementation of this package: it is Python, it targets the zero-auth
`POST /api/v1/demo` endpoint, and it never imports `@coderifts/agent-guard`.

It is the language-mirror of the rule this package enforces, taken verbatim from
`/.well-known/coderifts.json` → `recommended_usage`:

    branch_on                      = execution_action
    execution_action               = [CONTINUE, CONTINUE_WITH_MONITORING,
                                      REQUEST_APPROVAL, STOP]
    unrecognised_execution_action  = not_permission_fail_closed
    safe_for_agent                 = not_for_control_flow_use_execution_action

Verified at consolidation time: `python3 langgraph-guard-python/test_execution_action.py`
→ **10 passed**, offline, standard library only. The `langgraph`/`langchain`
node files need their frameworks installed to run; the decorator, the evaluator
and the whole test suite do not.

Like everything else in this directory it is **not** shipped: `package.json` →
`"files": ["dist", "README.md"]`.

## Production-grade sibling

Do **not** copy a second implementation into agent-guard. The production host that
derives contract artifacts from a PR’s real head diff lives in
**[coderifts/contract-gate](https://github.com/coderifts/contract-gate)** →
`src/artifacts.js` (`deriveArtifactsFromDiff`, injectable `gitImpl`,
`git diff --name-only base...head` + `git show ref:path`).

This package’s `resolveArtifacts` is the **pure** consumer of a pre-built
snapshot. contract-gate is the **git-facing producer**. Wire them; do not fork them.

## What this does not close

Resolving content proves what was true **at measurement time**. A host that then
writes unconditionally still races the tree. Conditional execution needs a
version token from the resolve and an expectation on the write — neither this
example nor the package provides that. See the TOCTOU section in
`host-git-resolve.mjs`.
