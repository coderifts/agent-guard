# Changelog

## 17.1.0

Fix the audience binding, and make the public test suite hermetic (RECORDED fallback).

AUDIENCE (wire change): the Guard sent context.audience and audience_hash — the server reads
NEITHER (it reads top-level `audience`, strict /^v:[0-9a-f]{12}$/, and derives audience_hash
itself). Both channels were inert: a host that configured an audience was getting a grant bound
under sha256('') and could not see it. The Guard now sends top-level `audience` (what the server
consumes) on EVERY authorize, and drops audience_hash from the wire; a free-text audience emits an
audience_not_bindable event rather than a binding that looks real but isn't. IF YOU CONFIGURED
audienceHash: you were binding NOTHING before this release — now a v:-form audience actually binds.

CLEAN-ROOM: the public suite was red (parity/policy/bundle-sync tests needed a private app
checkout). It now runs LIVE against the checkout when present and RECORDED against a sha256-pinned
vendored snapshot when absent, never silent-skip. The snapshot vendors EXTRACTED INVARIANTS of the
two app engines (change-set.js, github-enforcement.js), not their full source — 134 kB of engine
became 1.9 kB of golden fingerprints, so the public repo carries no governance engine and no
permission list. A verified-snapshot check gates every read (missing pin/file or sha mismatch →
throw, never fallback).


## 17.0.0

Raw shell carrying a mutation is now blocked (breaking default change).

A host-declared mutating capability (mutationClass: 'mutating_shell') now reaches the
UNGUARDED_MUTATION decision — previously the class was computed by the registry but had no field
on ToolCallDescriptor, so it died at the boundary and raw Bash mutations (kubectl apply, terraform
apply, helm upgrade, rm -rf, gh pr merge, curl to a deploy webhook) SLIPPED THROUGH with
verdict=SKIPPED, executed=true, even when the host explicitly declared mutating_shell. Now they are
BLOCKED, executionAttempted=false.

REMOVE RAW SHELL FROM THE GUARDED HOST, OR NAME THE OPT-OUT. A raw shell is undecidable by
construction — the guard does NOT read the command string (sh -c, alias, wrapper, base64 would win
that race while looking like it lost). So any host-declared mutating shell blocks, including ls -la
under a mutating_shell descriptor: that is correct, not collateral. The safe architecture is
capability-narrowing — take raw shell off the guarded host. A host that keeps it gets a block on
every shell call after upgrading; the escape is explicit and loud: CODERIFTS_ADVISORY=1 proceeds
with a warning. This is a breaking change to the DEFAULT: a caller on ^16 that relied on raw shell
running through will now be blocked unless it sets CODERIFTS_ADVISORY=1 or declares the class.


## 16.0.0

Default fail-closed on unguarded mutations (breaking default change — major bump).

A mutating tool call the detector does not recognise as a contract artifact is now BLOCKED by
default with UNGUARDED_MUTATION unless a valid CONTINUE receipt is present. Previously such calls
ran unguarded. The opt-out is explicit and loud: CODERIFTS_ADVISORY=1 proceeds with a logged
warning, never silently. Reads and non-mutating tools are unaffected; the offline verify path is
unchanged. This is a breaking change to the DEFAULT behaviour: a caller on ^15 that relied on
unrecognised mutations running through will now be blocked unless it sets CODERIFTS_ADVISORY=1 or
supplies a receipt. The ^15 range does not pull 16, so the change is opt-in by version.


## 15.1.0

Additive on both counts — no field removed, no meaning changed, no signature widened —
so the expected release is a **MINOR** bump (15.1.0). `DeployGateReason` and every other
closed set are untouched; the two new outcome fields are optional and the two new binders
are new exports.

### Added

- **A pointer on the unversioned profile spelling.** `withCodeRifts({ profile: 'ENFORCING_STRICT' })`
  now emits, once per process:

  > ENFORCING_STRICT is the unversioned spelling of ENFORCING_STRICT_V1; prefer the versioned name.

  It is **not** a deprecation. The unsuffixed alias resolves to `_V1` and is designed to do so
  permanently — re-pointing it at a future `_V2` would silently move every existing caller, which
  is the migration the versioned names exist to refuse. So the notice names no removal version and
  makes no promise; it points at the name that carries the version, for a caller who wants that
  guarantee by name. Emitted through `console.warn`, matching this package's existing advisory
  channel, and deliberately not as a `DeprecationWarning`. The wire value is unchanged: the four
  modules that compare `opts.profile === 'ENFORCING_STRICT'` see exactly what they saw before.

- **`next_step` on refusals that hold a SIGNED envelope (I-1288f).** The app moved
  `next_agent_step` inside `decision_result`, where `decision_body_hash` covers it and the
  receipt signs it. A consumer holding only the envelope can therefore render the decision's
  own remediation without a second call to the issuer.
  - `deployGate` exposes it top-level, **TOKEN mode only** — a `verified_view` or bare
    receipt is a host claim about someone else's check, and a step read from one would be
    guidance with no issuer behind it.
  - `guardToolCall` exposes it top-level on refusals, **only when `verdict.receiptVerified`
    is true**. With `verifyReceipts: false` the BLOCK still stands and the step is not shown.
  - `readNextAgentStep`, `NEXT_AGENT_ACTIONS` and `NEXT_STEP_NOTE` are exported. The note is
    byte-identical to contract-gate 0.8.0: *"This is the decision's remediation suggestion,
    not permission; branch on execution_action."*
  - Not a verdict input and not a preimage field: every branchable field is deep-equal to the
    same run with no step in the envelope.

- **`bindLangChainToolOutcome` (I-1272)** — LangChain's `content_and_artifact` return
  contract (`responseFormat: "content_and_artifact"`; the tool returns `[content, artifact]`
  and the artifact is preserved on the `ToolMessage` without entering the model's context).
  `content` carries the same string the other binders emit; `artifact` carries the structured
  `GuardExecutionProof`, so the proof stays verifiable without spending model context.

- **`bindCrewAIToolOutcome` (I-1272)** — CrewAI's `result` plus `result_as_answer`. The flag
  is `true` on exactly the arms the guard did not permit: a gate refusal is the end of that
  path, not an observation for the agent to reason around. No CrewAI dependency — a plain
  JSON-serialisable object the host returns from its Python tool.

  Both binders keep the shipped invariants: pure, non-mutating, no framework SDK dependency,
  type-level `ProofBound` brand, no fabricated result on the blocked branch, and a rendering
  byte-identical to `attachProofToAgentResponse` (asserted against `bindLangGraphGuardOutcome`
  on all five outcome arms).

### Changed

- `@coderifts/sdk` dependency range `^3.4.0` → `^3.10.0`. It stays a **dependency**; moving it to a
  peer dependency is a consumer-visible install change and waits for the next natural major.

## 15.0.0

### Security

- **deployGate no longer allows a deploy on a revoked key.** `deploy-receipt-token` resolved every registry status other than `retired` to `active` and never read `revoked_at` / `compromised_at`, so a deploy receipt signed by a key the registry marked revoked (or carrying `revoked_at`, or an unknown status) verified as `VERIFIED_CURRENT` and `deployGate` allowed the deploy under ENFORCING. The key-withdrawal rule is now the canonical receipt-verifier rule, judged before any authorization path; `test/vendor-core.test.js` pins the reference core by digest and asserts parity on the full vector set. The `guardToolCall` receipt path (server-side verify) and the posture-receipt verifier were not affected.

### Breaking

- `DeployGateReason` gains `revoked_key` and `unknown_key_status`; both are non-repairable (re-requesting a receipt would use the same key). Exhaustive switches must handle them.
- Conflicting V2 configuration now throws instead of being silently reconciled (one canonical source).

### Added

- A machine-readable remedy (`deny-remedy.v1`) on refused `guardToolCall` outcomes: which tool to call, in which mode, with what argument shape, and what a grant does not promise. The blocked branch still returns no invented result.
- The V2 wire fields the guard actually has are sent; the rest are bound in posture as named-absent.
- The vendored `CODERIFTS_POLICY` text is re-synced from the canonical source.

## 14.1.0

### Security

- **ENFORCING_ATOMIC_V2 posture verifier no longer fails open.** The posture-receipt verifier now rejects a revoked signing key (active-only resolution; a revoked key in the registry no longer resolves via fallback), a future or unparseable `measured_at` (a non-finite or negative age is refused, not silently passed), and — found in security review — a non-finite clock: `NaN < -tolerance` and `NaN > maxAgeMs` are both false, so a non-finite `now()` previously skipped both freshness predicates and a future receipt could still pass under a set `maxAgeMs`; the verifier now requires `Number.isFinite(now)` and `Number.isFinite(ageMs)` when `maxAgeMs` is set. When `maxAgeMs` is unset the direct verifier stays permissive; ENFORCING_ATOMIC_V2 is what makes a bounded `maxAgeMs` and an `expectedDeploymentId` mandatory, at the call site. V1 is byte-frozen and unchanged.

### Fixed

- **ENFORCING_ATOMIC_V2 is now reachable from the public API.** `withCodeRifts({ profile: 'ENFORCING_ATOMIC_V2' })` was defined in the profile module but excluded from the public entry's accepted-profile list, so the V2 profile could not be selected from the product API. It is now accepted (type + `ACCEPTED_PROFILES` + re-export), and the profile is forwarded to the construction helper so a V2 profile runs the V2 credential-boundary check rather than silently falling back to V1 — a bare `credentialBoundary: true` no longer passes under a V2 profile.

### Added

- **Vercel AI SDK tool adapter.** `withCodeRiftsVercel` / `protectedToolToVercel` / `toVercelTools` emit a dependency-free `generateText` tools record matching v4 `tool({ description, parameters, execute })`. `bindVercelGuardOutcome` maps GuardOutcome arms onto `{ type: 'tool-result', toolCallId, result }` (id field is `toolCallId`). `executeVercelToolCall` is the Option A dispatcher face, same wiring as the other four. No `ai` or `zod` dependency; `parameters` is JSON Schema from `inputSchema`. BLOCK never fabricates a result; a guarded non-outcome fails closed to an UNAVAILABLE bind rather than forwarding raw GuardOutcome JSON to the model.

## 14.0.0

### Breaking

- **ENFORCING_ATOMIC_V1 profile.** A new frozen assurance profile that conjoins eleven invariants (verified receipt, verified v2 grant, exact executor, exact target, after-payload hash, fresh nonce, nonce consumed once, target CAS, read-back, executor attestation, credential boundary). A missing invariant at construction throws `ATOMIC_PROFILE_UNSATISFIED` — the guard does not start. The outcome union is `AUTHORIZED_COMMITTED` / `REFUSED` / `INDETERMINATE`. `registerMutator` replaces `isWriteStyleCall` for ATOMIC only; non-ATOMIC profiles keep the previous predicate.
- **Commit label on the live outcome.** On the ATOMIC host-claimed path the live `GuardOutcome.commit_label` is now `authorized_and_host_reported_committed`; `authorized_and_committed` is emitted only with a verified executor attestation. The label is carried on the live outcome and the execution proof, not only the CAS record. Non-ATOMIC behaviour is unchanged (v1 compatible).

### Added

- v2 execution grant minting (`cr.exec.v2`) when the profile is ATOMIC or `grantVersion: 'v2'` is requested; the v1 default is unchanged.
- LICENSE shipped in the package `files[]`.

## 13.0.0

### Fixed — BREAKING (1093): the CAS conditioned on a token it fetched itself

- **`wrapWriteWithFsCas` measured its expected token INSIDE `executeFactory`** — after preflight
  (T1) and after the T2 execution-time recheck — then conditioned the write on that value. It asked
  whether the state had changed since a read a microsecond earlier: a real check of a vacuous
  window. Measured on 12.0.0 with a writer landing between T2 and that read, the CAS adopted the
  interfering state as its legitimate starting point and returned `status: 'committed'` with
  `enforced: true`, clobbering the other writer.

  The token now comes from **T1**, measured by the runner beside `collectFreshnessCallContext`,
  before preflight. Timing proof, same interleaving both ways: before → `committed`, interfering
  state overwritten; after → `refused` / `stale_version_token`, and the write does not land.

  **The adapter contract did not change.** All four CAS adapters (fs, api, db, registry) already
  took `expected_token` as a required argument; none fetched it. The defect was confined to the
  default-wire convenience layer, so this is plumbing rather than a contract break.

- **Absent an authorization-time token, no CAS claim is made at all.** The write runs unwrapped and
  no `ExecuteIfUnchangedOutcome` is fabricated. Self-fetching a substitute is precisely the vacuous
  claim; a weaker true guarantee is reportable, a false one is not.

### Added — (1098) filesystem defences, none of which existed

Measured absent on 12.0.0: `lstat`, `realpath`, `O_NOFOLLOW`, fd-based reads and `ino`/`dev` were
all missing from `src/cas-adapters/`.

- **Traversal refused.** A literal `..` segment is rejected, judged on the caller's own string
  *before* resolution — resolution is exactly what makes `sub/../escaped` look innocent.
- **Symlinked final component refused.** This was the other half of the TOCTOU and it was worse
  than a following bug: `stat`/`readFile` measured the link's TARGET while `rename` replaced the
  LINK, so the check and the write named **different objects**.
- **A symlinked ANCESTOR is canonicalised, not refused.** Requiring `realpath(dir) === dir` was
  written first and measured wrong within the hour — on macOS `/var` is itself a symlink, so every
  path under a normal temp directory was refused. The danger is an ancestor that *changes* between
  check and write, which identity closes.
- **The token is read through a file descriptor.** One `open`, then `stat` and `read` from the same
  handle, instead of `stat(path)` followed by `readFile(path)` — two interpretations a swap could
  slip between.
- **`dev`+`ino` recorded in the write evidence**, and an optional `expected_identity` from T1 is
  compared. This is strictly stronger than the token: an inode swapped in carrying identical bytes
  and mtime yields an **identical token**, and content equality cannot see it. Opt-in — omitted
  means no identity claim is made rather than one inferred.

### Added — (1099) the outcome can say how strong the guarantee was, and can say it does not know

- **`ConditionalWriteGuarantee`** on the basis, worded as claim language — each class states what it
  asserts and what it does not. `SAME_TRANSACTION` (check and mutation in one transaction of one
  system) · `CONDITIONAL_EXTERNAL` (a single conditional claim against a provider CAS, plus a
  read-back — a Redis `SETNX` followed by a separate HTTP call is **not** this class and is not a
  transaction) · `NON_ATOMIC` (applied, nothing guarded it). Carried only when the host reports it;
  never inferred from `conditional_write: true`, and an unrecognised value is dropped.
- **`status: 'indeterminate'`** as a first-class `ExecuteIfUnchangedOutcome`, with reasons
  `response_lost` / `ambiguous_provider_reply` / `observation_failed`. The rule is strict: never
  blindly retry, reconciliation is required, and downstream must block until resolved. On the
  attestation `cas.write_ran` is the string `'unknown'` — a third value, never collapsed to a
  boolean, because `false` would claim it did not run and `true` would claim it did.

### Measured and NOT built — (1098) `git update-ref` is a CAS over a different object

`git update-ref <ref> <new> <expected_old>` is a genuine atomic CAS (verified: refuses a stale
expected sha with exit 128 naming both values, succeeds with the correct one). It does **not**
subsume 1093 for git targets, and the measurement that settles it is one line: writing the
working-tree file moved **no ref**. A ref-level CAS guards commit history; our mutation target is
the bytes at a path, and a file inside a repository can be written entirely outside git's index.
Routing a file write through `update-ref` would mean creating a blob, a tree and a commit — turning
"write this file" into "commit this change", which is a different operation, not a hardening. It is
the right CAS only where the mutation *is* a ref move. So 1093 remains real for every file target,
git-tracked or not.

### Version

**MAJOR.** A composition that executed yesterday now refuses: a write whose target moved between
authorization and commit returns `refused` where it returned `committed`, and a symlinked target is
rejected outright. Same rule that made 10.0.0 and 12.0.0 major.

## 12.0.0

### Fixed — BREAKING for `requireConditionalWrite` / `ENFORCING_STRICT` callers

- **The conditional-write policy now gates on MUTATION, not on write-style.** An ordinary
  mutation that carried `artifacts[]` with a non-empty `before` AND `after` was classified
  not-write-style, so `requireConditionalWrite: true` never fired: the call executed with
  `enforced: true` and the outcome read `conditional_write: "not_reported"`.

  Reproduced against the published `@coderifts/agent-guard@11.0.1` tarball from npm, not the
  working tree — end to end through `guardToolCall` (the side effect ran) and through
  `withCodeRifts` + the default binder, which is the surface where it actually bites.

  **Why it was wrong.** `isWriteStyleCall` answers "did the caller supply a both-sides snapshot
  we can compare against?" That is the right question for FRESHNESS, and it was written for
  freshness (f14e5a3: *"a caller-supplied before is a claim, and a claim is not a measurement"*).
  The conditional-write policy was built to mirror `requireFreshness` (322c334) and mirrored its
  gating predicate along with its shape. But passing both sides of a change does not make the
  commit atomic — those are different facts, and evidence about content was suppressing the
  demand for atomicity.

  New `isMutatingCall` (exported) answers the separate question, independent of `artifacts[]`:
  a non-empty artifact `after`, content-bearing arguments (`contents`/`content`/`new_string`/
  `old_string`/`patch`), or a non-empty `edits[]`. A path alone is not evidence — a read names a
  path too. `isWriteStyleCall` is unchanged and still drives freshness.

- `ConditionalWriteBasis` gains `mutating: boolean` (additive). `write_style` is retained and
  still reported. `buildConditionalWriteBasis`, `conditionalWriteResidual`, and
  `assertEnforcedReceiptInvariant` accept an optional `mutating` that **defaults to `writeStyle`**,
  so a direct caller of those pure exports keeps its previous behaviour; `guardToolCall` always
  supplies it.

### Who this breaks

Callers with `requireConditionalWrite: true` (or `profile: 'ENFORCING_STRICT'`, which sets it at
`src/with-coderifts.ts`) whose agents emit `old_string`/`new_string` or `edits[]` edits on
contract-artifact paths. `defaultBinder` (`src/tool-registry.ts`) lifts both sides into
`artifacts[]`, which is exactly the shape that used to escape the gate. Every such call now fails
closed with `CONDITIONAL_WRITE_REQUIRED` unless the host reports `conditional_write: true`.

This is an adoption cliff, and it is named rather than smoothed: the default FS CAS wire
(`wrapWriteWithFsCas`) deliberately handles only full-file `path` + `contents` writes and declines
edit fragments, so an edit under this policy has no built-in way to report a conditional write —
the host must wire a CAS adapter. A policy that says "no unconditional writes" refusing a write it
cannot condition is the policy working, not a regression.

No test in this repo relied on the old behaviour (893 → 910, 0 fail).

### Known-open — measured, NOT fixed here

- **The CAS expected token is self-fetched, not authorization-bound (TOCTOU).**
  `wrapWriteWithFsCas` calls `createFsVersionToken` *inside* `executeFactory` — after preflight
  (T1) and after the T2 execution-time recheck — then conditions the write on that token. So it
  asks "did this change since I read it a microsecond ago", which is a real check of a vacuous
  window. Measured on 11.0.1: with a writer landing between T2 and the token read, the guard
  returned `executed: true`, `enforced: true`, the CAS returned `status: 'committed'`, and the
  `expected_token` did not equal the token of the state the authorization examined.

  This is a timing defect, not a classification defect, and it needs its own proof, so it is
  deliberately not bundled into the fix above. The residual is now documented at the site that
  causes it (`src/cas-adapters/fs-default-wire.ts`); `guard.ts` already named it as
  "no `observed_token_at_commit` CAS". Closing it means threading a token measured at
  authorization into the write rather than reading one at write time.

## 11.0.1

Identifier rename only. **No preimage byte changed, and no digest moved.**

### Changed

- **The 0x1F separator constant is now named `US` (Unit Separator) instead of `NUL`.**
  It was never NUL — NUL is 0x00 — and that misnomer was load-bearing: three constants
  across the server and its mirrors were all called `NUL` while only one of them was,
  which is how a published document (`RECEIPT_FORMAT.md` §2.0) came to give `\x1f` as the
  separator for the single-spec preimage, which actually uses `\x00`. Anyone who followed
  that revision computed a wrong digest. The name is now the measurement.

  Affects `src/execution-time-fingerprint.ts` and `src/enforcement-gate.ts`, following the
  server rename in `coderifts-app` 90c39cc. These files are kept faithful to the server BY
  EYE, so a mirror left on the old name would read as drift where there was none.

### Not changed — and this is why it is a patch

- **Every preimage is byte-identical.** Proved per function rather than assumed, by
  recomputing real vectors before and after: `computeCanonicalBundleFingerprint` and the
  exported `computeBundleFingerprint` both still return
  `sha256:049650f2…0443df` for the published `crbundle.v1` vector, and
  `computeArtifactDigest` still returns `sha256:6ddd4c07…010817`.
- **Nothing in the public surface names the constant.** Re-verified against this package
  specifically: none of the 199 exports is a separator, the built `dist` contains the old
  identifier zero times, and no `.d.ts` declares it. (`RECEIPT_PREV_NULL` is an unrelated
  receipt-chain constant, not a separator.) A consumer cannot have pinned the old name, so
  the rename cannot break one.


## 11.0.0

`computeBundleFingerprint` returned a WRONG digest and shipped that way in 10.0.0.

### Fixed

- **`computeBundleFingerprint(artifacts, context?)` now matches the server byte for byte.**
  The 10.0.0 form took only `artifacts` and built its own preimage, omitting two elements the
  server includes: the artifact **count**, and the entire trailing **context** block
  (`operation`, `environment`, `repository`, `branch`, `pull_request`, `policy_profile`). On
  identical inputs it returned `sha256:1a0e7470…` where the server returned `sha256:049650f2…`.

  The effect was worse than an absent verifier: a third party checking a receipt's `fp` against
  their own change set saw a mismatch and had no way to tell that the verifier, not the receipt,
  was at fault.

  Root cause was a **second preimage** inside this package. `execution-time-fingerprint.ts`
  already carried a faithful mirror under the comment *"Do NOT invent a second preimage"*;
  the exported function was that second preimage. It is now a thin delegation, so the package
  carries exactly one crbundle.v1 implementation.

### Compatibility — a behaviour break, made deliberately

- The signature gains an optional second parameter, so **existing source keeps compiling**. What
  changes is the **returned value**: any call that previously produced a digest now produces a
  different — and correct — one.
- **Measured, not assumed:** no caller anywhere in our repositories passes one argument. The only
  references to a one-argument form are the old definition itself and a docstring. There is no
  correct caller to protect, because the previous return value did not match the server for any
  request that carried a context.
- If you pinned a digest produced by 10.0.0's `computeBundleFingerprint`, it was not the server's
  fingerprint. Recompute it; do not migrate it.
- `computeCanonicalBundleFingerprint` is unchanged and remains exported. The two now return
  identical values by construction, and a test asserts that for every fixture case.

### Added

- **`test/exported-bundle-fingerprint-parity.test.js`** — cross-repo parity for the EXPORTED name,
  against the app's real `change-set.js` producer rather than a frozen hash, and unskippable: a
  missing app checkout fails the suite instead of passing quietly.

  The existing `crbundle-v1-parity-cross-repo.test.js` opens by saying it keeps
  *"computeBundleFingerprint / computeCanonicalBundleFingerprint"* from drifting, but only ever
  imported the canonical one — the exported name was never executed by a parity test. That gap is
  how the fork survived in plain sight, so the new file tests the export specifically.


## 9.6.0

Native execution grant on `withCodeRifts` / `guardToolCall`. The 9.5.0
host-wrap (`withExecutionGrantClient` / `takeGrant()`) is no longer needed
once a host is on 9.6.0: that wrap was last-authorize (racy under overlapping
tool calls). The grant is now scoped to the invocation that authorized it.

### Added

- **`executionGrant: { enabled: true, resolveStateNonce? }`** on
  `withCodeRifts` / `GuardConfig`. Default **OFF** (absent → byte-identical
  to 9.5.0). When enabled, THIS call's authorize carries
  `include_execution_grant: true` and, if `resolveStateNonce` is supplied,
  the `state_nonce` it returns for that call (ATOMIC profile).
- The factory's optional 3rd argument is `{ execution_grant }` for THIS
  call. `RawTool.execute` may take the same object as a 2nd argument
  (existing 1-arg execute functions ignore it).
- Outcome observation `{ requested, arrived }` on `outcome.execution_grant`
  when the path was on. The token is not recorded on the outcome.
- Fail-closed named causes: `EXECUTION_GRANT_NONCE_UNRESOLVABLE` (resolver
  throw), `EXECUTION_GRANT_MISSING` (allow-class 200 with no grant),
  `SIGNER_UNAVAILABLE` (503 / `code: SIGNER_UNAVAILABLE`, including a
  naked 503 on a grant-requesting authorize). After a grant was requested
  for THIS call, `failPolicy: 'open'` / LKG cannot execute grant-less —
  the call fails closed with the server's reason. Grant-OFF `open` is
  unchanged (9.5.0).

### Unchanged

- Grant flags are not a verdict input and are not in any fingerprint
  preimage.
- BLOCK / REQUIRE_APPROVAL still do not require a grant (the server does
  not mint one on deny-class).
- App-side `withExecutionGrantClient` remains valid for hosts still on
  9.5.0; it is unnecessary on 9.6.0.

## 9.5.0

Source: 7-AI panel — the largest real gain from a pre-execution attachment is
**measured coverage**, not blocking, and it does not depend on the hook being
deny-capable. Demonstrated in code on three frameworks (LangGraph, OpenAI
Agents, Anthropic SDK): the guard could emit registry `COMPLETE` and
`inescapable_runtime: true` **while an ungoverned tool rewrote the spec**.
That flag is true of our own table; it was being read as a claim about the
agent. This release reports what the guard **measured** about tool traffic.

### Changed

- **Claim narrowing (deliberate).** `composition_assurance.coverage` stays
  `PARTIAL` and `inescapable_runtime` stays `false` (byte-identical to 9.4.0).
  Registry `coverage: COMPLETE` / `claim.inescapable_runtime: true` remains
  **table-truth** for `requireCoverage` consumers — every mutator in the
  returned table is wrapped — and is **not** a claim that the agent cannot
  invoke a tool outside that table. The new live field is
  `composition_assurance.observed_class`. Direct `guardToolCall` without a
  composition observer is byte-identical to 9.4.0 (no `coverage_observed` on
  the outcome/proof). Observation only; nothing in any preimage.

### Added

- **Half A (always).** `coverage_observed: { governed_calls, tools }` counts
  every `execute()` through the returned table. Run scope = one
  `withCodeRifts` instance (same lifetime as `receipt_thread`; there is no
  process-wide session — this is the smallest honest run).
- **Half B (optional host report).** `reportToolDispatch({ name, at? })` and
  `reportToolDispatchBatch`. `at` is accepted for host convenience and **not
  retained** (the snapshot is counts, not a trail). A valid `{ name }` or an
  actual array (including `[]`) marks Half B supplied; a rejected argument
  (string, null, non-array) does **not**. When supplied: snapshot gains
  `total_calls`, `ungoverned_calls`, `ungoverned_tools[]`. When **not**
  supplied: those fields are **omitted, never zero** (absence ≠ zero).
- **Classes.** `UNKNOWN_OUTSIDE_SCOPE` (Half B absent — not COMPLETE);
  `INCOMPLETE_OBSERVED` (Half B present, ungoverned_calls > 0, names listed);
  `COMPLETE_OBSERVED` (Half B present, ungoverned_calls === 0).
- **Proof / T3 line.** `Coverage (observed)` prints e.g.
  `governed 9/12 dispatched calls; 3 outside the guarded table: patch_file, raw_write, shell`
  or
  `governed 9 calls; traffic outside the guarded table not observable from here`.
- **Signed coverage statement (`cr.coverage.attest.v1`).** Follow-up, not in
  this release — issuing a quotable token needs kid + host signer + envelope
  like `cr.monitor.attest.v1`, which is not a small addition.

## 9.4.0

Source: N-6 host series — three adoption blockers, all in the guard.

### Fixed

- **LangGraph tools shape (N-6 host #4, silent).** `withCodeRiftsLangGraph().tools`
  returned plain `{ name, schema, func, invoke }` callables. `createReactAgent`
  (`@langchain/langgraph`, measured 0.2.74 d.ts / current npm 1.4.12) requires
  `StructuredToolInterface | DynamicTool | RunnableToolLike` — ToolNode drops
  non-matching tools and the model sees **"Tool not found"** instead of a crash.
  Descriptors now duck-type that surface (`description` always set, `lc_runnable:
  true`, `invoke`) **without a hard `@langchain/*` dependency** (optional wrap
  would have been a peer import; duck-type is enough for the measured
  `isRunnable`/`isStructuredTool` check and keeps hosts who still call
  `tool(d.func, …)` working). If a tool would still fail that check,
  `LangGraphToolsNotStructuredError` is thrown with the fix (`wrap with tool()`
  from `@langchain/core/tools`). `bindLangGraphTools` is the duck-type assert,
  not a langchain wrap. Never silent.

- **First-run freshness teaching (N-6).** Fail-closed is unchanged
  (`FRESHNESS_REQUIRED` / `FRESHNESS_FAILED` still halt before a governance
  verdict). The binder-visible error now names the cause and the one-line fix
  using existing vocabulary: `resolvePriorContent` / `createFsPriorContentResolver()`
  on `withCodeRifts` / `GuardConfig`. BLOCK/APPROVAL refusal prefix is
  byte-identical to 9.3.0.

### Added

- **FS CAS default-wire (S1 remainder).** When tool args carry an unambiguous
  fs `path` **and** a full-file body (`contents` / Write-style `content`),
  mutators run `writeFileIfUnchanged` (the FS adapter) instead of an
  unconditional host write. Edit fragments (`old_string`/`new_string`) and
  path-only mutators stay 9.3.0 (host execute, no invented `committed`
  envelope). If the host already returns an `ExecuteIfUnchangedOutcome`, it
  is passed through. API, DB, and registry adapters stay opt-in. No preimage
  change.

## 9.3.0

### Added

- **Policy delivery (three layers).** File-based hosts load the agent-host
  rule automatically; a developer assembling their own system prompt got
  nothing. This wave ships the text where we can, exports it, and detects
  its absence as a last net.

  1. **`withPolicy(prompt)` / `withPolicy(messages)`** — the four provider
     adapters (`bind*GuardOutcome`) are **result-shapers**; they never see
     the outbound request. Layer 1 is therefore a one-line helper the host
     calls, not a request interceptor we do not have. Idempotent (marker
     detected → no second append). `injectPolicy: false` opt-out. Never
     mutates the caller's object/array in place.
  2. **`CODERIFTS_POLICY`** — canonical policy body vendored from the app
     `getCanonicalRuleText()`. Drift-gated byte-equal to the app (missing
     checkout fails loud). Marker
     `A receipt authorizes ONE operation: a merge receipt does not authorize a deploy.`
     (present in all six generated host formats).
  3. **`policy_presence`** on the outcome (`detected` | `absent`; omitted
     when the host did not supply `systemPrompt` — semantically `unknown`,
     byte-identical to 9.2.0). Observation only; never a verdict input;
     nothing in any preimage. Absent marker → once-per-process warn.

Honesty: this proves the TEXT is present, not that the model read or
obeyed it.

## 9.2.0

### Added

- **B2/1 `cr.monitor.attest.v1`.** Opt-in `monitoringAttestation: { kid, signer }`.
  `signer(bytes)` is a host-provided Ed25519 sign callback — **never a raw key in
  config**. When configured and a CWM arm ran, the outcome/proof carry
  `monitoring_attestation` (the token). The token states the measured
  `delivery_status` (`delivered_acked` | `sent_unacked` | `not_delivered`).
  Proof line upgrades to `monitoring: delivered (attested kid …)`.
  Honesty: proves a holder of the monitoring key observed this delivery
  status; does **not** prove a human read the alert; does **not** prove the
  sink is configured for the right audience. Observation-side; no preimage
  change. Absent config → CWM outcome byte-identical to 9.1.0.

## 9.1.0

### Added

- **P0-3 (audit): `ENFORCING_STRICT` success name requires executor attestation.**
  `enforced` is a pre-write fact and is unchanged. Under `profile: 'ENFORCING_STRICT'`
  only, an allow-class outcome is labelled `authorized_and_committed` (the existing
  `CasAttestation.derived` name) **only when** `cas_evidence.class ===
  "executor_attested"` **and** the attestation cross-checks the outcome's grant/receipt
  (`jti` + `scope_hash` + `receipt_digest`, kernel `verifyExecutionAttestation`).
  Otherwise the strict outcome is `authorized_not_committed` with visible reason
  `commit_evidence_missing`. Proof/T3: `authorized; commit not proven (no executor
  attestation)`. A lying/unbound attestation stays `host_claimed` (9.0.0 principle)
  and never upgrades the strict label. Observation-side; no preimage change.

### Unchanged

- **Non-strict profiles are byte-identical to 9.0.0** (no `commit_label`, banner
  stays `ENFORCED`, `derived.authorized_and_committed` stays receipt-verified +
  clean commit even on `host_claimed`).

## 9.0.0

**Breaking (major-worthy).** External audit 2026-08-24: `deployGate` treated a
caller-supplied `receipt.currently_authorized: true` as authentic authorization
(`deploy-gate.ts` previously `if (receipt.currently_authorized !== true)
deny('receipt_not_authorized')`). The CLI 4.4.0 round closed that for *its*
call path by verifying before calling the guard; **any other host** could still
hand the guard a forged view. Silently accepting forged views is not an
acceptable alternative.

### Breaking
- **A bare `currently_authorized: true` (no TOKEN, no provenance) is DENY**
  with reason **`unverified_receipt_view`**. That is not
  `receipt_not_authorized` — "you didn't prove it" ≠ "verification says no".
- **VERIFIED-VIEW** is accepted only when the object carries the
  guard-defined marker `view_spec: 'deploy-receipt-view.v1'` **and**
  `verified: true` (same idiom as `proof_spec` / `attestation_spec`). Use
  `asVerifiedDeployReceiptView(view, verify_status)`.
- **TOKEN mode (recommended):** pass `{ token, decision_result, registry |
  pinnedKeyPem }`. The guard verifies locally (Ed25519, kid window, body-hash,
  ID104 expiry leeway). No HTTP — SDK 3.4.0 `client.verifyReceipt` is
  I/O and cannot run inside this pure function.
- Outcome gains observation `verification: { mode, verify_status }`
  (`token` | `verified_view` | `unverified` | `none`). Not a preimage field.
- New deny reasons: `unverified_receipt_view`, `invalid_signature`, `expired`,
  `unknown_key`, `retired_key`.

### Callers that must update
- **coderifts CLI `deploy-gate` (4.4.0)** — passes a *computed* view **without**
  `view_spec`. Follow-up **4.4.1: TOKEN mode** (`token` + keys). Interim:
  stamp `asVerifiedDeployReceiptView` on the computed view. Do not ship
  guard 9.0.0 against CLI 4.4.0 without that.
- In-tree: `bindDeploy`, deploy-gate matrix, pentad deployGate fixtures,
  `inescapable-fail-closed` (clones the matrix). Merge-gate is unchanged.

### Not a preimage change
`verification` is observation-only.

## 8.5.0

### Added

- **S6 auto-recheck loop.** Opt-in `withCodeRifts({ autoRecheck: { maxAttempts, applyFix } })`
  (also on `GuardConfig`). Default **OFF**. After a BLOCK that carries
  `remediation_transaction`, the host's `applyFix` applies the fix (the guard
  never writes artifacts); artifacts are re-resolved FRESH (`resolve` /
  rebind) and the same `preflight_mode` runs again. `maxAttempts` bounds
  re-preflights (1–3, hard cap 3). Trail: `outcome.recheck_trail` /
  `proof.recheck_trail` `[{attempt, decision_id, fingerprint, execution_action}]`.
  Final outcome is the last decision (no special-casing of executed/enforced).
  Stops on allow-class, exhausted attempts, `applyFix` false/throw, or
  identical fingerprint twice (`recheck_stop_reason: 'no_progress'`).
  Events: `recheck_attempt {attempt, decision_id, from_fp, to_fp}`. Feeds the
  849 `fixed_after_block` metric when a recheck lands allow-class.
  Proof line: `re-preflighted N× after remediation; final decision <id>`.
  `recheck_scope` is envelope output only — preflight has no scope hint, so
  each attempt is a full re-preflight.
  Host orchestration only; nothing new enters a fingerprint preimage.

- **S1 auto-derive.** Opt-in `withCodeRifts({ autoDerive: true | { readers } })`
  (also on `GuardConfig`). Default **OFF** this round (flip-to-default is a
  later, evidence-gated decision). When the host does not supply
  `args.artifacts`, the wrap layer reads CURRENT state as `before` (fs/api/db/
  registry readers; default fs = utf8 file read) and the call's intended write
  as `after`. Missing target → `before: null` + `derivation_note:
  before_unavailable`; empty file → `before: ""`. Host `args.artifacts` always
  win. Reader throw/timeout → today's fragment path, event `derive_failed`.
  Observation: `outcome.derivation { mode, targets, notes? }` with
  `source: "guard_auto_derived"` on derived artifacts — not a preimage field.
  Frozen `guard.ts` untouched. Re-preflight (S6) re-derives FRESH.

- **S2-F2a R3 `executor_attested` evidence class.** Opt-in
  `withCodeRifts({ executorAttestation: { registry } })` (customer-pinned
  executor keys). When a CAS outcome carries an attestation token (from the
  executor's mutation response), the guard verifies it via
  `@coderifts/sdk` `verifyExecutionAttestation` (no re-implementation).
  Observation-side `cas_evidence: { class, attest_status, executor_kid, grant_jti }`
  with `class` ∈ `executor_attested` | `host_claimed` | `absent`.
  Invalid / unbound attestation stays `host_claimed` with `attest_status`
  visible (a lying token must not upgrade — N-4 lying-sink principle).
  No registry configured → `host_claimed`, no verification, no penalty.
  Proof/T3: `committed — executor-attested (ATTEST_VALID, kid …)` vs today's
  host-claim wording. Verdict/preimage untouched.

## 8.4.0

### Added

- **N-4 monitoring delivery attestation.** CWM outcomes gain observation-side
  `monitoring_delivery` with a closed tri-state: `delivered_acked` |
  `sent_unacked` | `not_delivered`. A dedicated `monitoringSink` (callback
  returning an ack, or HTTP POST `{ url }`) is invoked with a bounded timeout
  (default 5s, `monitoringSinkTimeoutMs`). Evidence records `{ at, ack_hash
  or status_code, sink_kind, ack_verified? }`. Optional HMAC (`ackHmacKey`;
  header `x-coderifts-ack-signature` / `x-hub-signature-256`) — valid →
  `ack_verified: true`; invalid → `not_delivered` (a lying sink is worse than
  no sink); no key → no verification, no penalty. No dedicated sink (host
  claim + `onEvent` only) → `sent_unacked`.
- **ENFORCING teeth:** `not_delivered` under default `failPolicy: 'closed'`
  (and `profile: 'ENFORCING_STRICT'`) treats CWM as the sink-not-wired case
  (`MONITORING_UNWIRED`, factory does not run). `observeOnly` / `failPolicy:
  'open'` degrade: proceed unenforced with the reason visible.
- **Proof:** `renderFinalAnswerProof` adds a Monitoring delivery section when
  the field is present (`monitoring: delivered (acked sha256:ab12…)` /
  `sent, not acked` / `NOT delivered`). Honesty: delivered_acked does **not**
  mean a human saw the event. ALLOW proofs are unchanged (field omitted).
  Observation-side only — never the verdict/preimage.

## 8.3.0

### Added

- **S4 binder auto-attach default ON.** `bindOpenAIGuardOutcome` /
  `bindAnthropicGuardOutcome` / `bindGeminiGuardOutcome` /
  `bindLangGraphGuardOutcome` attach the rendered `GuardExecutionProof` by
  default (this was already the measured behaviour; it is now an explicit
  default). Opt out with `{ attachProof: false }`. Proof wording is unchanged
  (`renderFinalAnswerProof` / `attachProofToAgentResponse`). Honesty: the
  block still states authorization + observed state only — no
  executed/enforced upgrade.

## 8.2.1

### Fixed

- **P0-2: missing `execution_action` on a v2 body never maps ALLOW→CONTINUE.**
  `readDecision` applies the legacy decision→action map **only** when
  `decision_spec_version === "1.0"` explicitly on a non-v2 body (no
  `decision_result`, no `preflight_mode`, spec does not start `"2."`).
  Otherwise missing action → `STOP` + reason `UNREADABLE_DECISION`.
  `guardToolCall` reuses the existing `closedIntegrity` halt arm with
  cause `UNREADABLE_DECISION` (`executed:false`, `enforced:false`).
- **P0-4: `ENFORCING_STRICT` locks `requireCommitObservation`.** Explicit
  `requireCommitObservation: false` aborts construction
  (`ENFORCING_STRICT cannot be weakened: requireCommitObservation conflicts`),
  same error style as `requireExecutionStateMatch: false`. The STRICT lock
  block now sets `requireCommitObservation: true` with freshness / CW / T2.

## 8.2.0

### Added

- **T3 post-commit observation** (`commit_observation` on every `GuardOutcome` / proof).
  After `executeFactory` returns, the guard re-reads the target and compares to the
  authorized `after` (FS content via `node:fs`) or the intended post token (API/DB/Registry
  reuse `current_token()` already required by `executeIfUnchanged`). Status is
  `observed_match` | `observed_token_match` | `observed_drift` | `not_observed`.
  Default ON; `requireCommitObservation: false` emits `commit_observation_check_disabled`
  and leaves `enforced` unchanged. Observed drift reports (`commit_observed_drift`) and
  re-runs preflight on the observed content for blast radius; it does **not** flip
  `enforced` (pre-write fact). Host `cas-attestation.v1` is a label on top of the
  measurement (`host_attested_committed` / `host_attested_refused` / `conflict`) — never
  a substitute. `executeIfUnchanged` now always re-reads after write and attaches
  additive `observed_token` (same reader; not a new host callback).

Honesty: observed at T3, not atomic: another writer may act between write and
observation; token-only adapters compare version token not content; host attestation
is a host claim layered on the measurement. Signed receipt / `bh` unchanged.

## 8.1.1

### Fixed

- **`requireExecutionStateMatch: false` no longer reports `enforced: true`.** The opt-down
  still proceeds on drift (behavior unchanged). The T2 recheck did not run, so the outcome
  now uses the same `runUnenforced` arm as `'warn'` mismatch (`enforced: false`) and emits
  `execution_state_check_disabled`. Claiming `enforced: true` when the check was off was a
  honesty bug (P0-6 / audit #16). `GuardOutcome.enforced` stays boolean — there is no
  `NOT_CHECKED` arm; `false` is the honest value.

## 8.1.0

### Added

- **`withCodeRifts({ profile: 'ENFORCING_STRICT' })`** — opt-in lock of the fail-closed
  conjunction: `requireCoverage: 'COMPLETE'`, `requireFreshness: true`,
  `requireExecutionStateMatch: true`, `requireConditionalWrite: true`,
  `failOnUnguardedMutator: true`, `unknownToolPolicy: 'mutating'`. Construction
  **aborts** on a conflicting opt-down (`ENFORCING_STRICT cannot be weakened: <flag> conflicts`)
  — no silent overwrite, no silent host-win. Missing `resolvePriorContent` under STRICT
  aborts at construction (detectable; not deferred to call-time `FRESHNESS_REQUIRED`).
  Composition residual `calls_outside_guarded_path_invisible` is always named under STRICT:
  host-invoked raw tools outside the returned table remain invisible (not total inescapability).
  Absent profile: **no default change** (freshness / conditional-write stay opt-in).

## 8.0.0

### Breaking

- **`requireExecutionStateMatch` defaults to `true`.** Immediately before `executeFactory`,
  the guard recomputes crbundle.v1 over the current `artifacts[]` and compares it to the
  fingerprint authorized on the receipt. Observed mismatch → integrity `EXECUTION_STATE_DRIFT`
  (factory does not run). Missing authorized fingerprint or missing artifacts →
  `EXECUTION_STATE_UNMEASURABLE` (cannot assert; STOP — not silent ALLOW).
- **Opt-down (not removed):** `'warn'` still emits (`execution_state_drift_observed` /
  `execution_state_unmeasurable`) then runs the factory **unenforced** (`enforced: false`
  on mismatch). `false` turns the recheck off entirely (v7 proceed-on-drift). Hosts that
  need v7 default behavior must set `requireExecutionStateMatch: false` explicitly.
  No timed auto-removal of the opt-down.

Honesty: this refuses on *observed* execution-state drift. It does **not** close TOCTOU
proper — recheck and execute are not atomic (no `observed_token_at_commit` CAS).

## 4.2.0

### Breaking (honest claims)

- **`coverageReport` honors `applicability_attested` (RT-P-16).**  
  Absence or any value other than strict `true` is **not** attestation (`not_reported`).  
  Unattested applicability can never support `FULLY_ENFORCED`: a previously green
  all-ENFORCING report without attestation is now `PARTIALLY_ENFORCED` with residual
  `applicability_unattested`, and `may_claim_full_tetrad` is false.  
  Hosts that already pass `applicability_attested: true` (e.g. the CodeRifts App
  `mergeCoverageInput`) keep `FULLY` under the same placement rules.

### Why not 4.1.x

This changes an existing **output value** on inputs that previously claimed FULLY
without attestation. That claim was never provable (applicability was unattested),
but the wire change is real for any consumer that branched on
`overall_coverage === 'FULLY_ENFORCED'` without sending the field — hence a minor
bump with changelog, not a silent patch.
