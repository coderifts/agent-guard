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
| [`final-answer-proof.mjs`](./final-answer-proof.mjs) | **ID645** human-readable final-answer proof block: verified/enforced vs skipped (`currently_authorized: null`) side by side; limits always surfaced. |

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
