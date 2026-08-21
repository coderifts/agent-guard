# Changelog

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
