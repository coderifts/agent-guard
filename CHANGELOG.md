# Changelog

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
