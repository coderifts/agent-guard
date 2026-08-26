# Changelog

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
