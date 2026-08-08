# Changelog

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
